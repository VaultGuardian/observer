package rec

import (
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"
)

// =============================================================================
// Ring Buffer - Multi-Constraint Bounded Response Storage
// =============================================================================
//
// Constraints (whichever hits first wins):
//   - MaxEntries:       10,000 (default, v1.0 - was 1,000)
//   - MaxTotalBytes:    128MB  (default) - see memory-pressure note below
//   - MaxAge:           10m    (default) - relaxed safety backstop, was 30s
//   - MaxBodyPreview:   2KB    (default) - per-entry body cap
//
// Eviction model: memory pressure is the PRIMARY eviction trigger. When a new
// entry would push total bytes past MaxTotalBytes, Insert evicts oldest-first
// until it fits (counted as EvictionsBytes). MaxAge is a relaxed backstop, not
// the hot trigger - it only sweeps entries that have sat untouched for the full
// window.
//
// Age rationale (v1.0): the previous 30s cap evicted REC responses mid-pipeline.
// During scanner bursts the LLM inference pipeline queues 30–60s+ of work, so by
// the time the coordinator's evidence check called Lookup, the matching response
// was already gone and the finding resolved as evidence_unavailable. Raising the
// backstop to 10m (20× longer) keeps first-encounter evidence alive long enough
// for the delayed evidence check to find it.
//
// Memory rationale: the longer retention window is offset at the deploy layer by
// a tighter effective byte ceiling. main.go composes the cap as
// min(REC_BUFFER_MAX_BYTES, REC_BUFFER_MAX_MB*1MB); with defaults that is 64MB,
// down from the legacy 128MB. REC_BUFFER_MAX_MB (default 64) is the preferred
// operator dial for memory; REC_BUFFER_MAX_BYTES remains honored for back-compat.
//
// All four parameters are overridable via REC_BUFFER_* env vars for operator
// tuning without rebuilds.
//
// Thread safety: sync.RWMutex
//   - Sniffer goroutine writes constantly (Lock)
//   - Analyzer looks up occasionally on alert (Lock as of Part 2 - Lookup
//     stamps everSelected on matched entries; Stats still takes RLock)
//
// The buffer is a circular array. When full, oldest entries are overwritten.
// Age-based eviction happens lazily on insert.
// Evicted/overwritten slots are zeroed so old BodyPreview slices don't pin
// memory for GC.

const (
	// DefaultMaxEntries was 10,000; Part 3 raises it to 32,768 - body
	// interning moved the dominant per-entry cost (the preview bytes) into
	// the shared body store, so a flood of identical bodies is charged one
	// body plus small per-entry identity records. The Part 2 budget-derived
	// clamp in NewRingBuffer still governs.
	DefaultMaxEntries    = 32768
	DefaultMaxTotalBytes = 128 * 1024 * 1024 // 128MB
	DefaultMaxAge        = 10 * time.Minute  // relaxed backstop; memory pressure is the primary trigger
	DefaultMaxBodyBytes  = 2 * 1024          // 2KB per entry body preview
)

// Approximate bookkeeping overhead per entry (struct fields, timestamps, the
// fixed-length BodyPreviewHash string, short Method strings). This is NOT
// exact - it's a conservative estimate for total byte tracking so the buffer
// stays within the memory cap. Do not treat as precise accounting. The
// VARIABLE-length owned strings (Path, Host, UserAgent, ContentType) are
// charged separately in entryByteCharge - they are attacker-influenced and
// must scale the charge.
const approxEntryOverheadBytes = 256

// maxEntryArrayBudgetDivisor bounds the preallocated (empty) entry array to
// 1/4 (25%) of the byte budget - see the NewRingBuffer clamp.
const maxEntryArrayBudgetDivisor = 4

// entryStructSize reports the fixed in-memory size of one ring entry struct
// (excluding what its strings/slices reference). Feeds the NewRingBuffer
// budget clamp and is surfaced by tests so entry-size drift stays visible.
func entryStructSize() uintptr {
	return unsafe.Sizeof(CapturedResponse{})
}

// BufferConfig holds the multi-constraint configuration.
type BufferConfig struct {
	MaxEntries    int
	MaxTotalBytes int64
	MaxAge        time.Duration
	MaxBodyBytes  int
}

// DefaultBufferConfig returns the standard defaults.
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
	//
	Path string

	// Host header value. Used as a HARD FILTER in correlation.
	// On CapRover with multiple virtual hosts behind the same nginx,
	// same path on different hosts is NOT the same transaction.
	//
	Host string

	// User-Agent header. Used as a TIE-BREAKER when multiple candidates
	// match on method+path+host+status+time. Not a hard filter.
	UserAgent string

	// Wall-clock time the paired request's first segment was parsed on
	// the wire (pendingRequest.timestamp). Zero when the response was
	// never paired (orphan path) - orphans must NOT get a value.
	RequestTimestamp time.Time

	// --- Response fields ---

	// HTTP status code. Used as a HARD FILTER in correlation.
	// A 404 and a 200 for the same path are definitively different
	// transactions. (agreed: not a soft downgrade.)
	StatusCode    int
	ContentType   string
	ContentLength int64

	// BodyPreview carries the captured raw preview bytes INTO Insert().
	// Part 3: the STORED ring entry does not own this slice - Insert
	// interns the bytes into the shared body store, sets `body`, and clears
	// this field on the stored copy. Read previews through
	// BodyPreviewBytes(), which serves both shapes.
	BodyPreview []byte

	// body is the shared, refcounted storage for the preview bytes and the
	// intern-time disclosure analysis. Storage sharing is INVISIBLE to
	// correlation semantics (Invariant 6): identity and clone checks key
	// off BodyPreviewHash and per-entry fields, NEVER off this reference -
	// two entries sharing storage are not the same transaction.
	body *internedBody

	// BodyPreviewHash is the SHA-256 of the captured body PREVIEW (not the
	// full body). Unchanged computation and unchanged role in clone checks,
	// catch-all matching, and the byte fallback - it is per-entry identity,
	// independent of the internal storage fingerprint.
	BodyPreviewHash string

	// BodyComplete reports that BodyPreview covers the ENTIRE response body:
	// the read hit a clean end-of-body within the preview cap with no read
	// error. False means truncated or error-terminated. len(BodyPreview) and
	// ContentLength are NOT proof of completeness; only the capture layer
	// sets this. Consumed by the XML-RPC redactor, which requires a complete
	// document.
	BodyComplete bool

	// Source container/service that generated the response (if identifiable)
	SourceContainer string

	// CaptureID is a monotonically increasing identity assigned by Insert()
	// under the ring lock. All tracking keys off CaptureID, never off ring
	// slot index (slots are reused). Zero means "never accepted by Insert"
	// (e.g. an oversized rejection).
	CaptureID uint64

	// --- Read/demand tracking flags (Part 2) ---
	//
	// What these CAN prove: everSelected = the entry was returned in at
	// least one Lookup() candidate set; selectedBest = it was chosen as the
	// best candidate of a Lookup at least once; knownDemand = a PrePin/VIP
	// request matched it.
	//
	// What they CANNOT prove: "read" is NOT "safe to lose". A lookup
	// candidate is not selected evidence; selected is not analyzed; VIP
	// promotion is not consumption. No logic may free, evict preferentially,
	// or uncharge an entry because any of these flags is set - they exist
	// only so loss counters can report honestly what was lost.
	everSelected bool
	selectedBest bool
	knownDemand  bool

	// Size of this entry in bytes (for total byte tracking).
	// Approximate - see entryByteCharge.
	entryBytes int64
}

// entryByteCharge approximates the memory owned by one entry ITSELF: the
// variable-length owned strings plus the fixed bookkeeping overhead. The
// body preview is NOT charged here (Part 3) - it lives in the shared body
// store and is charged once per unique body via internedBody.byteCharge.
// Deliberately approximate but directionally honest - it must grow when the
// entry's attacker-influenced allocations grow. Do not treat as precise
// accounting.
func entryByteCharge(resp *CapturedResponse) int64 {
	return int64(len(resp.Path)) + int64(len(resp.Host)) +
		int64(len(resp.UserAgent)) + int64(len(resp.ContentType)) +
		approxEntryOverheadBytes
}

// BodyPreviewBytes returns the captured raw preview, whether the entry still
// owns it directly (before Insert, or a rejected insert) or holds it through
// the interned body store. Treat the returned slice as read-only.
func (c *CapturedResponse) BodyPreviewBytes() []byte {
	if c.body != nil {
		return c.body.rawPreview
	}
	return c.BodyPreview
}

// emptyResponse is the zero value used to clear evicted slots for GC.
var emptyResponse CapturedResponse

// BufferStats is a snapshot of ring buffer utilization and eviction pressure.
// All fields are populated under RLock in Stats() - no atomics needed.
type BufferStats struct {
	Entries    int
	TotalBytes int64

	// Eviction counters - split by reason so operators can immediately
	// diagnose which constraint is binding under burst load.
	// Plain int64, NOT atomic.Int64 - incremented only inside Insert()
	// under the existing rb.mu.Lock(). Atomic ops would be redundant
	// memory-barrier overhead inside an already-locked critical section.
	EvictionsTotal    int64 // total evictions across all reasons
	EvictionsCapacity int64 // evicted because entry cap hit
	EvictionsAge      int64 // evicted because MaxAge expired
	EvictionsBytes    int64 // evicted because byte cap hit

	// Part 2 loss counters.
	//
	// HONESTY NOTE (Invariant 5): the known-demand counter measures demand
	// that was OBSERVED - a PrePin/VIP request had matched the entry before
	// it was lost. It is NOT proof that no future event needed an evicted
	// entry, and its absence is not proof an eviction was harmless.
	//
	// Counter semantics (fix rounds v3/v4):
	//   RejectedOversized  - the insert's CONSERVATIVE worst-case estimate
	//                        (entry record + raw preview +
	//                        redactorMaxOutputBytes + store overhead)
	//                        exceeded the effective budget. NOT proof the
	//                        actual entry could never fit - the estimate
	//                        assumes the largest capped-redactor preview.
	//   RejectedBudget     - the estimate fit, but current owners (VIP-held
	//                        bodies included) occupy the space even after
	//                        full ring eviction.
	RejectedOversized int64
	RejectedBudget    int64

	// DemandedEvidenceEvicted: a known-demand RING entry was evicted; the
	// promoted VIP copy, if any, may still hold the evidence - this is NOT
	// proof the evidence was lost.
	DemandedEvidenceEvicted int64

	// VIPReacquireRejected counts VIP promotions refused because the body
	// was no longer store-resident and the effective budget had no room to
	// resurrect it. The existing VIP evidence (if any) was left in place.
	VIPReacquireRejected int64

	// Eviction split by whether the entry was ever returned in a Lookup
	// candidate set (FIX 5a). Telemetry only: "ever selected" is NOT
	// "consumed" and "never selected" is NOT "worthless" - see the flag
	// comments on CapturedResponse.
	EvictedEverSelected  int64
	EvictedNeverSelected int64
}

// RingBuffer is a thread-safe, multi-constraint bounded circular buffer.
type RingBuffer struct {
	mu     sync.RWMutex
	config BufferConfig

	entries []CapturedResponse
	head    int   // next write position
	count   int   // current number of valid entries
	total   int64 // current total bytes: entry records + shared body charges (incl. VIP-held bodies)

	// bodies is the shared refcounted body store (Part 3). Guarded by rb.mu
	// - the store itself has no lock. VIP copies that outlive their ring
	// slot hold their own references via reacquire/releaseBody.
	bodies *bodyStore

	// Eviction counters (v1.0 burst hardening). Plain int64 - only
	// touched inside Insert() under rb.mu.Lock(). See BufferStats.
	evictionsTotal    int64
	evictionsCapacity int64
	evictionsAge      int64
	evictionsBytes    int64

	// effectiveMaxTotalBytes is the byte budget actually available for
	// entry records and interned bodies: the configured MaxTotalBytes minus
	// the preallocated entry array's fixed cost (FIX 2b). Used in ALL
	// admission and eviction checks; the configured value in rb.config is
	// never mutated and stays what stats/logs report as configured.
	effectiveMaxTotalBytes int64

	// Part 2 counters - also only touched under rb.mu.Lock().
	rejectedOversized       int64
	rejectedBudget          int64
	demandedEvidenceEvicted int64
	vipReacquireRejected    int64
	evictedEverSelected     int64
	evictedNeverSelected    int64

	// nextCaptureID feeds CaptureID assignment in Insert() under the lock.
	nextCaptureID uint64
}

// worstCaseEntryBytes is the admission-estimate ceiling for a single entry:
// its bookkeeping record, a full-size raw preview, the largest preview any
// redactor can retain (an OUTPUT cap - see redactorMaxOutputBytes), and the
// body-store overhead. Variable request strings (Path/Host/UA/CT) are
// approximated by the record overhead; a pathological path is caught by the
// per-insert worst-case check, not this construction-time constant.
func worstCaseEntryBytes(maxBodyBytes int) int64 {
	return approxEntryOverheadBytes + int64(maxBodyBytes) +
		redactorMaxOutputBytes + bodyStoreOverheadBytes
}

// NewRingBuffer creates a ring buffer with the given configuration.
//
// FIX C (fix round v4): a configuration whose MaxTotalBytes cannot fit ONE
// worst-case entry after array charging even at MaxEntries == 1 is INVALID
// and returns an error - the buffer must never limp along on a floored
// 1-byte effective budget rejecting everything silently. The caller decides
// the failure mode (NewCollector logs loudly and runs REC as a no-op).
func NewRingBuffer(cfg BufferConfig) (*RingBuffer, error) {
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

	entrySize := int64(entryStructSize())
	worstCase := worstCaseEntryBytes(cfg.MaxBodyBytes)

	// FIX C: unusable-budget validation, before any clamping - the bound is
	// independent of MaxEntries because the check assumes the minimum
	// possible array (one slot).
	if cfg.MaxTotalBytes-entrySize < worstCase {
		return nil, fmt.Errorf(
			"rec: unusable buffer config: MaxTotalBytes=%d cannot fit one worst-case entry (%d bytes, at MaxBodyBytes=%d) plus the entry array (%d bytes/entry) even at MaxEntries=1; need at least %d",
			cfg.MaxTotalBytes, worstCase, cfg.MaxBodyBytes, entrySize, entrySize+worstCase)
	}

	// Budget-derived ceiling on MaxEntries (Part 2): the preallocated entry
	// array is a real fixed cost - MaxEntries × sizeof(CapturedResponse) -
	// charged against MaxTotalBytes. An enormous configured MaxEntries must
	// not allocate outside the budget before insertion begins, so the EMPTY
	// array may consume at most 1/maxEntryArrayBudgetDivisor (25%) of the
	// byte budget.
	ceiling := int(cfg.MaxTotalBytes / maxEntryArrayBudgetDivisor / entrySize)
	if ceiling < 1 {
		ceiling = 1
	}
	if cfg.MaxEntries > ceiling {
		log.Printf("[rec:buffer] MaxEntries=%d exceeds budget ceiling - clamped to %d "+
			"(empty entry array at %d bytes/entry may use at most 1/%d of the %d-byte budget)",
			cfg.MaxEntries, ceiling, entrySize, int64(maxEntryArrayBudgetDivisor), cfg.MaxTotalBytes)
		cfg.MaxEntries = ceiling
	}

	// --- FIX 2b: effective budget + tiny-budget guard ---
	// The preallocated entry array is a real fixed cost. Everything the
	// buffer admits (entry records + interned bodies) is checked against
	// what remains AFTER that cost, so the process footprint stays inside
	// the configured MaxTotalBytes. If the remainder is no bigger than one
	// worst-case entry, keep shrinking MaxEntries until at least four
	// worst-case entries fit or a single slot remains. The FIX C validation
	// above guarantees the single-slot fallback still fits one worst-case
	// entry, so the effective budget is always positive and usable.
	effective := cfg.MaxTotalBytes - int64(cfg.MaxEntries)*entrySize
	if effective <= worstCase && cfg.MaxEntries > 1 {
		shrunk := int((cfg.MaxTotalBytes - 4*worstCase) / entrySize)
		if shrunk < 1 {
			shrunk = 1
		}
		if shrunk < cfg.MaxEntries {
			cfg.MaxEntries = shrunk
		}
		effective = cfg.MaxTotalBytes - int64(cfg.MaxEntries)*entrySize
	}
	log.Printf("[rec:buffer] geometry: maxEntries=%d arrayBytes=%d (at %d bytes/entry) "+
		"configuredBudget=%d effectiveBudget=%d worstCaseEntry=%d",
		cfg.MaxEntries, int64(cfg.MaxEntries)*entrySize, entrySize,
		cfg.MaxTotalBytes, effective, worstCase)

	return &RingBuffer{
		config:                 cfg,
		entries:                make([]CapturedResponse, cfg.MaxEntries),
		bodies:                 newBodyStore(),
		effectiveMaxTotalBytes: effective,
	}, nil
}

// Insert adds a captured response to the buffer and returns the STORED form
// of the entry: CaptureID assigned, body interned into the shared store,
// BodyPreview cleared. Callers that hand the entry onward (the VIP onCapture
// callback) must use the returned value so downstream copies share the
// interned body. CaptureID 0 on the returned value means the insert was
// rejected (nothing stored, body not interned).
// Body is truncated to MaxBodyBytes (BodyPreviewHash covers the truncated preview).
// Called by the sniffer goroutine - takes a write lock.
func (rb *RingBuffer) Insert(resp CapturedResponse) CapturedResponse {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Truncate body preview if needed
	if len(resp.BodyPreview) > rb.config.MaxBodyBytes {
		resp.BodyPreview = resp.BodyPreview[:rb.config.MaxBodyBytes]
	}

	// Calculate approximate entry size (entry record only - the body is
	// charged via the store below, once per unique body).
	resp.entryBytes = entryByteCharge(&resp)

	// Part 2 (oversized): CONSERVATIVE worst-case admission estimate - the
	// entry record, the raw preview, the largest preview the CAPPED
	// redactors can retain (redactorMaxOutputBytes, an output cap -
	// MaxBodyBytes caps input, not output), and store overhead. An estimate
	// exceeding the effective budget is REJECTED without evicting anything
	// for it. This is not proof the actual entry could never fit (its real
	// preview may be smaller); the estimate errs toward refusing.
	worstCase := resp.entryBytes + int64(len(resp.BodyPreview)) +
		redactorMaxOutputBytes + bodyStoreOverheadBytes
	if worstCase > rb.effectiveMaxTotalBytes {
		rb.rejectedOversized++
		resp.CaptureID = 0
		return resp
	}

	// Stable capture identity: assigned under the lock, never reused.
	rb.nextCaptureID++
	resp.CaptureID = rb.nextCaptureID

	// Intern the body BEFORE any eviction: the incoming reference is held
	// first, so byte-pressure eviction below can never free the body this
	// insert is about to share. An intern hit charges nothing and skips
	// redaction entirely (floods of identical bodies redact once).
	var bodyAdded int64
	resp.body, bodyAdded = rb.bodies.intern(resp.BodyPreview, resp.ContentType, resp.BodyComplete)
	rb.total += bodyAdded

	// Evict aged-out entries from the tail
	rb.evictExpired()

	// Evict oldest entries until we're under the effective byte budget.
	// Evicting an entry whose body is shared frees only its record bytes
	// until the last owner releases; the loop stays bounded by rb.count.
	for rb.total+resp.entryBytes > rb.effectiveMaxTotalBytes && rb.count > 0 {
		rb.evictOldest()
		rb.evictionsBytes++
		rb.evictionsTotal++
	}

	// FIX 2a: post-eviction admission recheck. VIP-held body charges are
	// not freed by ring eviction, so the budget can still be over even with
	// the ring fully evicted. Rejection must remain rejection: release the
	// just-taken intern reference (uncharging on last owner) and refuse.
	if rb.total+resp.entryBytes > rb.effectiveMaxTotalBytes {
		rb.total -= rb.bodies.release(resp.body)
		resp.body = nil
		rb.rejectedBudget++
		resp.CaptureID = 0
		return resp
	}
	resp.BodyPreview = nil // stored entries never own preview bytes

	// If buffer is at max count, the circular write overwrites the oldest.
	// Zero the slot first so old references get GC'd.
	if rb.count == rb.config.MaxEntries {
		rb.noteEvictedLocked(rb.head)
		rb.releaseSlotBodyLocked(rb.head)
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
	return resp
}

// noteEvictedLocked records loss telemetry for the entry in slot idx that is
// about to be evicted: the known-demand counter (the promoted VIP copy, if
// any, may still hold the evidence - not proof it was lost) and the FIX 5a
// ever/never-selected split. Must hold rb.mu.
func (rb *RingBuffer) noteEvictedLocked(idx int) {
	if rb.entries[idx].knownDemand {
		rb.demandedEvidenceEvicted++
	}
	if rb.entries[idx].everSelected {
		rb.evictedEverSelected++
	} else {
		rb.evictedNeverSelected++
	}
}

// releaseSlotBodyLocked releases the slot's interned body reference (if any)
// and uncharges the body bytes when this was the last owner. Must hold
// rb.mu. Ring eviction never frees a body still held by VIP storage - the
// store's refcount guarantees that.
func (rb *RingBuffer) releaseSlotBodyLocked(idx int) {
	if b := rb.entries[idx].body; b != nil {
		rb.total -= rb.bodies.release(b)
	}
}

// reacquire re-establishes a store reference for a CapturedResponse copy
// that is about to outlive its ring slot (VIP promotion / VIP match) - FIX 1.
//
// The copy was made outside rb.mu (buffer.Lookup returns after unlocking;
// Insert's return travels to onCapture unlocked), so by the time VIP wants
// to hold it, eviction may already have released its body. Atomic under
// rb.mu:
//   - The store still holds a body under this fingerprint (the same object,
//     or a re-interned twin) → retain it, repoint the copy, ok.
//   - The body is gone → BUDGET ADMISSION FIRST: the resurrection charge is
//     the copy's retained byteCharge (raw preview + retained redacted
//     preview + store overhead). If it does not fit the effective budget,
//     refuse WITHOUT evicting ring entries for it (rejection must remain
//     rejection) and count vipReacquireRejected. If it fits, resurrect the
//     copy's body object into the store (reusing its immutable disclosure -
//     no re-redaction), charge, ok.
//
// Never panics on a released body - the release/retain panics remain for
// true double-release bugs.
//
// ACCEPTED LIMITATION: returned copies can keep raw slice allocations
// GC-reachable after their store charge is released - the byte accounting
// bounds STORE-owned memory, approximately, not every alias.
//
// Lock order: callers may hold vipMu; rb.mu is taken here (vipMu → rb.mu,
// the established order).
func (rb *RingBuffer) reacquire(c *CapturedResponse) bool {
	if c.body == nil {
		return true // nothing to hold (test-built or preview-less copies)
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if existing, ok := rb.bodies.byKey[c.body.key]; ok {
		// Live under this fingerprint - either the same object or a twin
		// re-interned after our copy's release. Either way retain THAT one.
		rb.bodies.retain(existing)
		c.body = existing
		return true
	}

	// Released and not re-interned. Budget admission before resurrection.
	if rb.total+c.body.byteCharge > rb.effectiveMaxTotalBytes {
		rb.vipReacquireRejected++
		return false
	}
	rb.total += rb.bodies.resurrect(c.body)
	return true
}

// releaseBody drops the reference held by a VIP copy (expiry, consumption,
// cap eviction, overwrite) and uncharges the body bytes on last release.
func (rb *RingBuffer) releaseBody(c *CapturedResponse) {
	if c.body == nil {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.total -= rb.bodies.release(c.body)
}

// LookupRequest contains the request attributes for L7 heuristic correlation.
// Used by the collector to query the buffer.
type LookupRequest struct {
	EventID         string // event identity for ownership-safe VIP lookup; empty = legacy method+path scan
	Method          string
	Path            string // MUST be raw un-normalized path including query string
	Host            string // Host header - hard filter if present on both sides
	UserAgent       string // tie-breaker for multiple matches
	SourceContainer string // container/service that logged the request
	StatusCode      int    // status code from log line - HARD FILTER (hard filter)
	Timestamp       time.Time
	Window          time.Duration // correlation window (default 500ms)
	ExpectedBytes   int64         // response bytes from access log - ranking signal for orphan disambiguation
}

// Lookup performs L7 heuristic correlation.
//
// Hard filters (must match exactly):
//   - Method
//   - Path (raw, including query string)
//   - StatusCode (if > 0 in request - a 404 and 200 are NOT the same transaction)
//   - Host (if non-empty on both sides)
//
// Section 3 / Finding 10: SourceContainer is no longer filtered on. The
// AF_PACKET sniffer never populates entry.SourceContainer (it sees wire
// packets, not container attribution), so the filter was always a no-op.
// req.SourceContainer is still accepted by callers but currently unused.
//
// Returns all matching candidates - the caller decides confidence based on count
// and uses UserAgent as a tie-breaker if needed.
//
// Called by the analyzer goroutine after LLM classification. Takes a WRITE
// lock (Part 2): matched ring entries are stamped everSelected. That stamp is
// telemetry only - being selected never changes an entry's eviction order or
// byte charge (a lookup candidate is not selected evidence).
func (rb *RingBuffer) Lookup(req LookupRequest) []CapturedResponse {
	rb.mu.Lock()
	defer rb.mu.Unlock()

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

		// Method + Path are the core identity - BUT only when the stored
		// entry has request info. On namespace capture (single-node Swarm),
		// the sniffer sees incoming responses from the backend but NOT the
		// outgoing proxy request (TLS terminates at nginx, so the inbound
		// request is encrypted on port 443, and the outbound proxy request
		// is an outgoing packet that AF_PACKET doesn't capture).
		// These "orphan" responses have empty Method/Path but valid
		// StatusCode, ContentType, and Body. Matching on StatusCode +
		// timestamp is sufficient for low-traffic servers.
		if entry.Method != "" {
			// Entry has request info - match exactly
			if entry.Method != req.Method || entry.Path != req.Path {
				continue
			}
		} else {
			// Orphan response (pair miss) - Method/Path filter is unavailable,
			// so we rely on StatusCode + timestamp + Host below. BUT we also
			// need to gate on body size compatibility, otherwise a tiny
			// healthcheck UUID body (cl=36) can match a real attack response
			// (cl=2401) just because they share status=200 and a 5-second
			// timestamp window. That false correlation actually fired in
			// production - a captain-identifier-healthcheck body downgraded
			// an XDEBUG curl event because the LLM looked at the wrong body.
			//
			// Tolerance: response bytes from the access log (req.ExpectedBytes)
			// should be plausibly compatible with captured ContentLength.
			// Reject orphan if both are known and they disagree by more than
			// max(10%, 256 bytes). When either side is unknown (zero/unset),
			// don't filter - fall through and let other gates decide.
			if !orphanBytesCompatible(req.ExpectedBytes, entry.ContentLength) {
				continue
			}
		}

		// Status code is a HARD filter, not a soft downgrade.
		// If the log says 404 and the wire says 200, these are definitively
		// different transactions. ()
		if req.StatusCode > 0 && entry.StatusCode != req.StatusCode {
			continue
		}

		// Host is a hard filter - same path on different virtual hosts
		// is NOT the same transaction. Critical on CapRover where multiple
		// services share one nginx.
		if req.Host != "" && entry.Host != "" && entry.Host != req.Host {
			continue
		}

		// Section 3 / Finding 10: the SourceContainer filter that used to
		// live here was dead code - the AF_PACKET sniffer never populates
		// CapturedResponse.SourceContainer (it sees wire packets, not
		// container attribution), so the inner condition was always false.
		// Removed entirely. If we ever wire container attribution at the
		// packet layer, restore the filter and a real assignment together.

		rb.entries[idx].everSelected = true
		candidates = append(candidates, entry)
	}

	return candidates
}

// markEntry finds the LIVE ring entry with the given CaptureID and applies
// mark to it. A no-op when the entry was already evicted or never inserted
// (captureID 0). Keys strictly off CaptureID - slot indexes are reused and
// must never be used as identity.
func (rb *RingBuffer) markEntry(captureID uint64, mark func(*CapturedResponse)) {
	if captureID == 0 {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for i := 0; i < rb.count; i++ {
		idx := (rb.head - 1 - i + rb.config.MaxEntries) % rb.config.MaxEntries
		if rb.entries[idx].CaptureID == captureID {
			mark(&rb.entries[idx])
			return
		}
	}
}

// markSelectedBest records that the entry was chosen as the best candidate
// of a Lookup. Telemetry only - selection never affects eviction, charging,
// or lifetime ("read" is not "safe to lose").
func (rb *RingBuffer) markSelectedBest(captureID uint64) {
	rb.markEntry(captureID, func(e *CapturedResponse) { e.selectedBest = true })
}

// markKnownDemand records that a PrePin/VIP request matched this entry, so a
// later eviction of it counts as demandedEvidenceEvicted. Observed demand
// only - it proves someone wanted this entry, not that unmarked entries were
// unwanted.
func (rb *RingBuffer) markKnownDemand(captureID uint64) {
	rb.markEntry(captureID, func(e *CapturedResponse) { e.knownDemand = true })
}

// Stats returns current buffer utilization and eviction pressure (for monitoring/debugging).
func (rb *RingBuffer) Stats() BufferStats {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return BufferStats{
		Entries:                 rb.count,
		TotalBytes:              rb.total,
		EvictionsTotal:          rb.evictionsTotal,
		EvictionsCapacity:       rb.evictionsCapacity,
		EvictionsAge:            rb.evictionsAge,
		EvictionsBytes:          rb.evictionsBytes,
		RejectedOversized:       rb.rejectedOversized,
		RejectedBudget:          rb.rejectedBudget,
		DemandedEvidenceEvicted: rb.demandedEvidenceEvicted,
		VIPReacquireRejected:    rb.vipReacquireRejected,
		EvictedEverSelected:     rb.evictedEverSelected,
		EvictedNeverSelected:    rb.evictedNeverSelected,
	}
}

// evictExpired removes entries older than MaxAge. Must hold write lock.
func (rb *RingBuffer) evictExpired() {
	cutoff := time.Now().Add(-rb.config.MaxAge)
	for rb.count > 0 {
		oldestIdx := (rb.head - rb.count + rb.config.MaxEntries) % rb.config.MaxEntries
		if rb.entries[oldestIdx].Timestamp.Before(cutoff) {
			rb.noteEvictedLocked(oldestIdx)
			rb.releaseSlotBodyLocked(oldestIdx)
			rb.total -= rb.entries[oldestIdx].entryBytes
			rb.entries[oldestIdx] = emptyResponse // zero for GC
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
	rb.noteEvictedLocked(oldestIdx)
	rb.releaseSlotBodyLocked(oldestIdx)
	rb.total -= rb.entries[oldestIdx].entryBytes
	rb.entries[oldestIdx] = emptyResponse // zero for GC
	rb.count--
}

// orphanBytesCompatible decides whether an orphan response (no Method/Path)
// could plausibly be the response to a request whose access log says
// expectedBytes. Used as a sanity gate to prevent tiny healthcheck bodies
// from matching large attack responses.
//
// When either side is unknown (<=0), returns true - we don't have enough
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
