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
//   - MaxEntries:       1000 (default)
//   - MaxTotalBytes:    16MB (default)
//   - MaxAge:           10s  (default) — bridges LLM latency gap per 's timing trap
//   - MaxBodyPreview:   2KB  (default) — per-entry body cap
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
	DefaultMaxEntries    = 1000
	DefaultMaxTotalBytes = 16 * 1024 * 1024 // 16MB
	DefaultMaxAge        = 10 * time.Second
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
	StatusCode    int
	ContentType   string
	ContentLength int64
	BodyPreview   []byte // truncated to MaxBodyBytes
	BodyPreviewHash string // SHA-256 of captured body PREVIEW (not full body)

	// Source container/service that generated the response (if identifiable)
	SourceContainer string

	// Size of this entry in bytes (for total byte tracking).
	// Approximate — see approxEntryOverheadBytes constant.
	entryBytes int64
}

// emptyResponse is the zero value used to clear evicted slots for GC.
var emptyResponse CapturedResponse

// RingBuffer is a thread-safe, multi-constraint bounded circular buffer.
type RingBuffer struct {
	mu     sync.RWMutex
	config BufferConfig

	entries []CapturedResponse
	head    int   // next write position
	count   int   // current number of valid entries
	total   int64 // current total bytes across all entries
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
	}

	// If buffer is at max count, the circular write overwrites the oldest.
	// Zero the slot first so old BodyPreview slices get GC'd (code review's fix).
	if rb.count == rb.config.MaxEntries {
		rb.total -= rb.entries[rb.head].entryBytes
		rb.entries[rb.head] = emptyResponse // zero for GC
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
}

// Lookup performs L7 heuristic correlation.
//
// Hard filters (must match exactly):
//   - Method
//   - Path (raw, including query string)
//   - StatusCode (if > 0 in request — a 404 and 200 are NOT the same transaction)
//   - Host (if non-empty on both sides)
//   - SourceContainer (if non-empty on both sides)
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

		// Method + Path are the core identity
		if entry.Method != req.Method || entry.Path != req.Path {
			continue
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

		// Source container — hard filter if identifiable on both sides
		if req.SourceContainer != "" && entry.SourceContainer != "" &&
			entry.SourceContainer != req.SourceContainer {
			continue
		}

		candidates = append(candidates, entry)
	}

	return candidates
}

// Stats returns current buffer utilization (for monitoring/debugging).
func (rb *RingBuffer) Stats() (entries int, totalBytes int64) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count, rb.total
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