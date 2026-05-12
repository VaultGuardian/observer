package rec

import (
	"sync"
	"time"
)

// =============================================================================
// Ring Buffer — Multi-Constraint Bounded Response Storage
// =============================================================================
//
// Constraints (whichever hits first wins):
//   - MaxEntries:       10,000 (default, v1.0 — was 1,000)
//   - MaxTotalBytes:    128MB  (default, v1.0 — was 16MB)
//   - MaxAge:           30s    (default) — must exceed worst-case LLM latency for first-encounter evidence
//   - MaxBodyPreview:   2KB    (default) — per-entry body cap
//
// v1.0 bump rationale: 10,000 × ~3KB avg = ~30MB working set, 128MB cap = 4x
// headroom. Handles ~333 req/sec sustained for 30s without evidence loss.
// Previous 1,000-entry cap was defeated by any standard scanner (Nuclei, ffuf,
// gobuster) at default rates (~50 req/sec for 30s = 1,500 requests).
//
// All four parameters are overridable via REC_BUFFER_* env vars for operator
// tuning without rebuilds.
//
// Thread safety: sync.RWMutex
//   - Sniffer goroutine writes constantly (Lock)
//   - Analyzer reads occasionally on alert (RLock)
//
// The buffer is a circular array. When full, oldest entries are overwritten.
// Age-based eviction happens lazily on insert.
// Evicted/overwritten slots are zeroed so old BodyPreview slices don't pin
// memory for GC (code review's catch).

const (
	DefaultMaxEntries    = 10000
	DefaultMaxTotalBytes = 128 * 1024 * 1024 // 128MB
	DefaultMaxAge        = 30 * time.Second
	DefaultMaxBodyBytes  = 2 * 1024 // 2KB per entry body preview
)

// Approximate bookkeeping overhead per entry (strings, ints, timestamps).
// This is NOT exact — it's a conservative estimate for total byte tracking
// so the buffer stays within the memory cap. Do not treat as precise accounting.
const approxEntryOverheadBytes = 256

// BufferConfig holds the multi-constraint configuration.
type BufferConfig struct {
	MaxEntries    int
	MaxTotalBytes int64
	MaxAge        time.Duration
	MaxBodyBytes  int
}

// DefaultBufferConfig returns the design team-agreed defaults.
func DefaultBufferConfig() BufferConfig {
	return BufferConfig{
		MaxEntries:    DefaultMaxEntries,
		MaxTotalBytes: DefaultMaxTotalBytes,
		MaxAge:        DefaultMaxAge,
		MaxBodyBytes:  DefaultMaxBodyBytes,
	}
}

// CapturedResponse is a single entry in the ring buffer.
// Represents one observed HTTP response on the plaintext wire.
type CapturedResponse struct {
	// When the response was observed on the wire
	Timestamp time.Time

	// --- Request fields (for L7 heuristic correlation) ---

	// HTTP method (GET, POST, etc.)
	Method string

	// Full request path INCLUDING query string.
	// SACRED: never stripped, never normalized. This must match what
	// gopacket sees on the wire, not what the normalizer produces.
	// ('s raw-path reminder.)
	Path string

	// Host header value. Used as a HARD FILTER in correlation.
	// On CapRover with multiple virtual hosts behind the same nginx,
	// same path on different hosts is NOT the same transaction.
	// (code review's catch — captured but previously unused.)
	Host string

	// User-Agent header. Used as a TIE-BREAKER when multiple candidates
	// match on method+path+host+status+time. Not a hard filter.
	UserAgent string

	// --- Response fields ---

	// HTTP status code. Used as a HARD FILTER in correlation.
	// A 404 and a 200 for the same path are definitively different
	// transactions. ( + code review agreed: not a soft downgrade.)
	StatusCode      int
	ContentType     string
	ContentLength   int64
	BodyPreview     []byte // truncated to MaxBodyBytes
	BodyPreviewHash string // SHA-256 of captured body PREVIEW (not full body)

	// Source container/service that generated the response (if identifiable)
	SourceContainer string

	// Size of this entry in bytes (for total byte tracking).
	// Approximate — see approxEntryOverheadBytes constant.
	entryBytes int64
}

// emptyResponse is the zero value used to clear evicted slots for GC.
var emptyResponse CapturedResponse

// BufferStats is a snapshot of ring buffer utilization and eviction pressure.
// All fields are populated under RLock in Stats() — no atomics needed.
type BufferStats struct {
	Entries    int
	TotalBytes int64

	// Eviction counters — split by reason so operators can immediately
	// diagnose which constraint is binding under burst load.
	// Plain int64, NOT atomic.Int64 — incremented only inside Insert()
	// under the existing rb.mu.Lock(). Atomic ops would be redundant
	// memory-barrier overhead inside an already-locked critical section.
	EvictionsTotal    int64 // total evictions across all reasons
	EvictionsCapacity int64 // evicted because entry cap hit
	EvictionsAge      int64 // evicted because MaxAge expired
	EvictionsBytes    int64 // evicted because byte cap hit
}

// RingBuffer is a thread-safe, multi-constraint bounded circular buffer.
type RingBuffer struct {
	mu     sync.RWMutex
	config BufferConfig

	entries []CapturedResponse
	head    int   // next write position
	count   int   // current number of valid entries
	total   int64 // current total bytes across all entries

	// Eviction counters (v1.0 burst hardening). Plain int64 — only
	// touched inside Insert() under rb.mu.Lock(). See BufferStats.
	evictionsTotal    int64
	evictionsCapacity int64
	evictionsAge      int64
	evictionsBytes    int64
}

// NewRingBuffer creates a ring buffer with the given configuration.
func NewRingBuffer(cfg BufferConfig) *RingBuffer {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MaxTotalBytes <= 0 {
		cfg.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	return &RingBuffer{
		config:  cfg,
		entries: make([]CapturedResponse, cfg.MaxEntries),
	}
}

// Insert adds a captured response to the buffer.
// Body is truncated to MaxBodyBytes (BodyPreviewHash covers the truncated preview).
// Called by the sniffer goroutine — takes a write lock.
func (rb *RingBuffer) Insert(resp CapturedResponse) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Truncate body preview if needed
	if len(resp.BodyPreview) > rb.config.MaxBodyBytes {
		resp.BodyPreview = resp.BodyPreview[:rb.config.MaxBodyBytes]
	}

	// Calculate approximate entry size
	resp.entryBytes = int64(len(resp.BodyPreview)) + approxEntryOverheadBytes

	// Evict aged-out entries from the tail
	rb.evictExpired()

	// Evict oldest entries until we're under the total byte cap
	for rb.total+resp.entryBytes > rb.config.MaxTotalBytes && rb.count > 0 {
		rb.evictOldest()
		rb.evictionsBytes++
		rb.evictionsTotal++
	}

	// If buffer is at max count, the circular write overwrites the oldest.
	// Zero the slot first so old BodyPreview slices get GC'd (code review's fix).
	if rb.count == rb.config.MaxEntries {
		rb.total -= rb.entries[rb.head].entryBytes
		rb.entries[rb.head] = emptyResponse // zero for GC
		rb.evictionsCapacity++
		rb.evictionsTotal++
	} else {
		rb.count++
	}

	rb.entries[rb.head] = resp
	rb.total += resp.entryBytes
	rb.head = (rb.head + 1) % rb.config.MaxEntries
}

// LookupRequest contains the request attributes for L7 heuristic correlation.
// Used by the collector to query the buffer.
type LookupRequest struct {
	Method          string
	Path            string // MUST be raw un-normalized path including query string
	Host            string // Host header — hard filter if present on both sides
	UserAgent       string // tie-breaker for multiple matches
	SourceContainer string // container/service that logged the request
	StatusCode      int    // status code from log line — HARD FILTER (+code review)
	Timestamp       time.Time
	Window          time.Duration // correlation window (default 500ms)
	ExpectedBytes   int64         // response bytes from access log — ranking signal for orphan disambiguation
}

// Lookup performs L7 heuristic correlation.
//
// Hard filters (must match exactly):
//   - Method
//   - Path (raw, including query string)
//   - StatusCode (if > 0 in request — a 404 and 200 are NOT the same transaction)
//   - Host (if non-empty on both sides)
//
// Section 3 / Finding 10: SourceContainer is no longer filtered on. The
// AF_PACKET sniffer never populates entry.SourceContainer (it sees wire
// packets, not container attribution), so the filter was always a no-op.
// req.SourceContainer is still accepted by callers but currently unused.
//
// Returns all matching candidates — the caller decides confidence based on count
// and uses UserAgent as a tie-breaker if needed.
//
// Called by the analyzer goroutine after LLM classification — takes a read lock.
func (rb *RingBuffer) Lookup(req LookupRequest) []CapturedResponse {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	window := req.Window
	if window == 0 {
		window = DefaultCorrelationWindow
	}

	var candidates []CapturedResponse
	windowStart := req.Timestamp.Add(-window)
	windowEnd := req.Timestamp.Add(window)

	for i := 0; i < rb.count; i++ {
		idx := (rb.head - 1 - i + rb.config.MaxEntries) % rb.config.MaxEntries
		entry := rb.entries[idx]

		// --- Time window filter ---
		if entry.Timestamp.Before(windowStart) || entry.Timestamp.After(windowEnd) {
			continue
		}

		// --- Hard filters (all must match) ---

		// Method + Path are the core identity — BUT only when the stored
		// entry has request info. On namespace capture (single-node Swarm),
		// the sniffer sees incoming responses from the backend but NOT the
		// outgoing proxy request (TLS terminates at nginx, so the inbound
		// request is encrypted on port 443, and the outbound proxy request
		// is an outgoing packet that AF_PACKET doesn't capture).
		// These "orphan" responses have empty Method/Path but valid
		// StatusCode, ContentType, and Body. Matching on StatusCode +
		// timestamp is sufficient for low-traffic servers.
		if entry.Method != "" {
			// Entry has request info — match exactly
			if entry.Method != req.Method || entry.Path != req.Path {
				continue
			}
		} else {
			// Orphan response (pair miss) — Method/Path filter is unavailable,
			// so we rely on StatusCode + timestamp + Host below. BUT we also
			// need to gate on body size compatibility, otherwise a tiny
			// healthcheck UUID body (cl=36) can match a real attack response
			// (cl=2401) just because they share status=200 and a 5-second
			// timestamp window. That false correlation actually fired in
			// production — a captain-identifier-healthcheck body downgraded
			// an XDEBUG curl event because the LLM looked at the wrong body.
			//
			// Tolerance: response bytes from the access log (req.ExpectedBytes)
			// should be plausibly compatible with captured ContentLength.
			// Reject orphan if both are known and they disagree by more than
			// max(10%, 256 bytes). When either side is unknown (zero/unset),
			// don't filter — fall through and let other gates decide.
			if !orphanBytesCompatible(req.ExpectedBytes, entry.ContentLength) {
				continue
			}
		}

		// Status code is a HARD filter, not a soft downgrade.
		// If the log says 404 and the wire says 200, these are definitively
		// different transactions. ( + code review independently agreed.)
		if req.StatusCode > 0 && entry.StatusCode != req.StatusCode {
			continue
		}

		// Host is a hard filter — same path on different virtual hosts
		// is NOT the same transaction. Critical on CapRover where multiple
		// services share one nginx. (code review's catch.)
		if req.Host != "" && entry.Host != "" && entry.Host != req.Host {
			continue
		}

		// Section 3 / Finding 10: the SourceContainer filter that used to
		// live here was dead code — the AF_PACKET sniffer never populates
		// CapturedResponse.SourceContainer (it sees wire packets, not
		// container attribution), so the inner condition was always false.
		// Removed entirely. If we ever wire container attribution at the
		// packet layer, restore the filter and a real assignment together.

		candidates = append(candidates, entry)
	}

	return candidates
}

// Stats returns current buffer utilization and eviction pressure (for monitoring/debugging).
func (rb *RingBuffer) Stats() BufferStats {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return BufferStats{
		Entries:           rb.count,
		TotalBytes:        rb.total,
		EvictionsTotal:    rb.evictionsTotal,
		EvictionsCapacity: rb.evictionsCapacity,
		EvictionsAge:      rb.evictionsAge,
		EvictionsBytes:    rb.evictionsBytes,
	}
}

// evictExpired removes entries older than MaxAge. Must hold write lock.
func (rb *RingBuffer) evictExpired() {
	cutoff := time.Now().Add(-rb.config.MaxAge)
	for rb.count > 0 {
		oldestIdx := (rb.head - rb.count + rb.config.MaxEntries) % rb.config.MaxEntries
		if rb.entries[oldestIdx].Timestamp.Before(cutoff) {
			rb.total -= rb.entries[oldestIdx].entryBytes
			rb.entries[oldestIdx] = emptyResponse // zero for GC (code review's fix)
			rb.count--
			rb.evictionsAge++
			rb.evictionsTotal++
		} else {
			break
		}
	}
}

// evictOldest removes the single oldest entry. Must hold write lock.
func (rb *RingBuffer) evictOldest() {
	if rb.count == 0 {
		return
	}
	oldestIdx := (rb.head - rb.count + rb.config.MaxEntries) % rb.config.MaxEntries
	rb.total -= rb.entries[oldestIdx].entryBytes
	rb.entries[oldestIdx] = emptyResponse // zero for GC (code review's fix)
	rb.count--
}

// orphanBytesCompatible decides whether an orphan response (no Method/Path)
// could plausibly be the response to a request whose access log says
// expectedBytes. Used as a sanity gate to prevent tiny healthcheck bodies
// from matching large attack responses.
//
// When either side is unknown (<=0), returns true — we don't have enough
// information to reject, so fall through to other filters.
//
// When both are known, accepts a difference up to max(10%, 256 bytes).
// 256 bytes accommodates small responses where 10% is too tight (e.g.
// a 100-byte access log "bytes" vs a 95-byte captured response is fine).
// 10% accommodates larger responses where 256 bytes is too tight (e.g.
// a 50KB response with slight chunked-encoding overhead).
func orphanBytesCompatible(expectedBytes, contentLength int64) bool {
	if expectedBytes <= 0 || contentLength <= 0 {
		return true
	}
	diff := expectedBytes - contentLength
	if diff < 0 {
		diff = -diff
	}
	tolerance := expectedBytes / 10
	if tolerance < 256 {
		tolerance = 256
	}
	return diff <= tolerance
}