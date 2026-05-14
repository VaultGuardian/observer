// internal/coordinator/expected_endpoint.go
package coordinator

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Expected Endpoint Tracker — Path-Scoped Operator Confirmations
// =============================================================================
//
// In-memory hot-path lookup for Option 4 corrections ("this endpoint is
// supposed to return sensitive-looking data"). The tracker lives in this
// package for type-locality with the coordinator's other building blocks,
// but the coordinator itself does NOT invoke Check() — the check runs inside
// the evidence callback (main.go: makeEvidenceCheckCallback) so it can
// short-circuit reclass cache + LLM lookups using the redacted shape hash.
//
// =============================================================================
// Why this is structured the way it is
// =============================================================================
//
// Three correctness invariants set by the May 11 2026 design team review:
//
//   1. The match key is the REDACTED response-shape hash, not the raw
//      transport hash. Auth/token endpoints return rotating values; only
//      the redacted shape hash (rec.HashBody(SafeBodyPreview)) is stable
//      across rotations. The same hash is used as the reclass cache key,
//      so a single computation serves both subsystems.
//
//   2. The check fires BEFORE reclass cache and BEFORE LLM. Operator-explicit
//      truth beats both emergent inference (cache) and model judgment (LLM).
//      A stale "token-looking = malicious" cache entry must not be allowed
//      to pre-empt an operator-confirmed downgrade.
//
//   3. Multiple body_hashes per (host, method, path, status) accumulate
//      additively. Auth endpoints legitimately return different shapes
//      (admin vs user, role-flagged, paginated). Each operator click
//      broadens the legitimate-response surface for that endpoint. the design review's
//      literal reading of the key tuple, design team converged.
//
// Architectural distinction from CatchAll:
//
//   catchall_verified_v2  — emergent, statistical, path-agnostic
//                           Threshold of 5 distinct paths sharing the same
//                           body hash before verification runs. Catches
//                           generic 404/error templates served across many
//                           paths.
//
//   expected_endpoints    — explicit, deterministic, path-scoped
//                           Single operator click = single rule. Path and
//                           status are part of the key. No threshold, no LLM
//                           verification — the human IS the verification.
//
// =============================================================================
// Concurrency
// =============================================================================
//
//   - entries map: protected by RWMutex.
//   - entry.Reason: only mutated under write-lock by SeedVerified; readers
//     copy under RLock before formatting (race-safe).
//   - entry.Suppressed: atomic.Int64, mutated outside any lock.
//   - totalSuppressed: atomic.Int64, mutated outside any lock.
//   - Stats() reads len(entries) under RLock; suppressed via atomic load.

const (
	// DefaultExpectedEndpointCap mirrors CatchAll's maxFingerprints. With the
	// key now scoped to (host, method, path, status, shapeHash), the number
	// of legit sensitive endpoints per deployment is small (login, password
	// reset, OAuth token, API key creation — call it 5-20 per app × maybe
	// 3-5 shapes each). 500 is generous headroom that also caps damage if a
	// future bug accidentally inserts duplicates.
	//
	// Note: keying on the REDACTED shape hash (not raw transport hash) means
	// rotating tokens don't burn through cap — same redacted shape hashes
	// to the same value regardless of token value.
	DefaultExpectedEndpointCap = 500
)

// ExpectedEndpointFingerprint is the full key — every field is part of the
// match. Status is included to prevent collisions between e.g. a 200 expected
// token response and a 401 error with similar body shape. (code review P1, locked
// in May 11 2026.)
//
// BodyPreviewHash here is specifically the REDACTED response-shape hash
// (rec.HashBody(SafeBodyPreview) at evidence-callback time, decision.CacheKey
// at correction-handler time). NEVER the raw transport hash.
type ExpectedEndpointFingerprint struct {
	Host            string
	Method          string
	Path            string
	Status          int
	BodyPreviewHash string // = redacted shape hash; never raw transport hash
}

func (f ExpectedEndpointFingerprint) String() string {
	hash := f.BodyPreviewHash
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return fmt.Sprintf("%s %s%s [status=%d shape=%s]", f.Method, f.Host, f.Path, f.Status, hash)
}

// expectedEndpointEntry holds the stored value behind a fingerprint.
// Suppressed is atomic so Check() can increment without holding the map lock.
type expectedEndpointEntry struct {
	Reason     string       // operator description; protected by tracker.mu
	AddedAt    time.Time    // when this fingerprint was seeded; protected by tracker.mu
	Suppressed atomic.Int64 // per-rule hit counter for future pattern-review UI
}

// ExpectedEndpointTracker holds operator-confirmed expected-response rules.
// Thread-safe; intended single-instance lifecycle: constructed in main.go,
// passed to both the evidence callback (for Check) and the API server (for
// SeedVerified via correction handler, plus Stats for /api/stats).
type ExpectedEndpointTracker struct {
	mu      sync.RWMutex
	entries map[ExpectedEndpointFingerprint]*expectedEndpointEntry
	cap     int

	// totalSuppressed is the cross-rule hit counter exposed to /api/stats.
	// Atomic so it can be incremented from Check() and read from Stats()
	// without coordinating with the entries map lock.
	totalSuppressed atomic.Int64
}

// NewExpectedEndpointTracker constructs a tracker with the given cap. A
// non-positive cap falls back to DefaultExpectedEndpointCap.
func NewExpectedEndpointTracker(cap int) *ExpectedEndpointTracker {
	if cap <= 0 {
		cap = DefaultExpectedEndpointCap
	}
	return &ExpectedEndpointTracker{
		entries: make(map[ExpectedEndpointFingerprint]*expectedEndpointEntry),
		cap:     cap,
	}
}

// NormalizeMethodPath canonicalizes an HTTP method and path so that DB rows
// written by the API handler key-match the runtime tracker's lookups. The
// rules are intentionally tiny so they're easy to audit and stay stable:
//
//   - method:  uppercased (lowercase variants from logs vs. uppercased
//     variants from header parsing collapse to a single form)
//   - path:    query string stripped at the first '?' (query params don't
//     affect endpoint identity for this feature)
//
// Both the tracker's fingerprint constructor and the API handler's DB save
// path call this. Without a shared helper the two would drift over time:
// the tracker would normalize, the DB row would not, and pattern-review UI
// would later see DB rows that look like duplicates but match a single live
// rule. (code review P2, May 11 2026.)
func NormalizeMethodPath(method, path string) (canonicalMethod, canonicalPath string) {
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}
	return strings.ToUpper(method), path
}

// newExpectedEndpointFingerprint builds the tracker's hot-path lookup key.
// Used internally by Check() and SeedVerified() so live keys and stored
// rows share the same canonical form.
func newExpectedEndpointFingerprint(host, method string, status int, path, bodyPreviewHash string) ExpectedEndpointFingerprint {
	canonicalMethod, canonicalPath := NormalizeMethodPath(method, path)
	return ExpectedEndpointFingerprint{
		Host:            host,
		Method:          canonicalMethod,
		Path:            canonicalPath,
		Status:          status,
		BodyPreviewHash: bodyPreviewHash,
	}
}

// Check tests whether (host, method, status, path, bodyPreviewHash) matches
// an operator-confirmed expected endpoint. Returns true + reason if the
// alert should be auto-downgraded.
//
// CRITICAL: bodyPreviewHash MUST be the REDACTED response-shape hash
// (rec.HashBody(SafeBodyPreview)), NOT the raw transport hash. Calling this
// with the raw transport hash will silently never match for auth endpoints
// with rotating tokens — defeating the whole point of the feature. The
// caller (evidence callback) computes the redacted hash; the correction
// handler reads it from decision.CacheKey.
//
// Race discipline (code review P0 fix, May 11 2026):
//   - entry pointer + Reason are read under RLock
//   - Reason is COPIED before the lock is released; never read outside
//   - Suppressed counters are atomic; no lock needed for increment
func (t *ExpectedEndpointTracker) Check(host, method string, status int, path, bodyPreviewHash string) (matched bool, reason string) {
	if host == "" || bodyPreviewHash == "" {
		return false, ""
	}

	fp := newExpectedEndpointFingerprint(host, method, status, path, bodyPreviewHash)

	// Read the entry pointer AND copy entry.Reason under RLock. After the
	// unlock we still hold the pointer (Go's GC keeps it alive), but we
	// never touch entry.Reason again — only the local copy.
	t.mu.RLock()
	entry, ok := t.entries[fp]
	var entryReason string
	if ok {
		entryReason = entry.Reason
	}
	t.mu.RUnlock()

	if !ok {
		return false, ""
	}

	entry.Suppressed.Add(1)
	t.totalSuppressed.Add(1)

	reason = fmt.Sprintf(
		"Expected endpoint: operator confirmed %s %s%s [status %d] returns sensitive-looking response by design (shape hash %.16s) — %s",
		fp.Method, fp.Host, fp.Path, fp.Status, fp.BodyPreviewHash, entryReason,
	)
	return true, reason
}

// SeedVerified bulk-inserts fingerprints from persistent storage at startup,
// or wires in a single new fingerprint from a live operator click. Drops
// inserts that would exceed cap; logs once per overflow event so silent
// growth-cap blockage is visible.
//
// Idempotent on re-seed of an existing fingerprint: refreshes Reason and
// AddedAt under the write lock, preserves the Suppressed counter.
//
// v1.x note (deferred): if cap is reached during a live operator click, the
// API handler will return success because this function has no return value.
// code review flagged this as a future "UX lie" — when cap is reached the seed
// silently fails. Acceptable at v1.0 because cap=500 is plenty of headroom
// for normal deployments; v1.1 should make SeedVerified return inserted/dropped
// counts so the API can surface a warning to the operator.
func (t *ExpectedEndpointTracker) SeedVerified(fps []ExpectedEndpointFingerprint, reasons []string) {
	if len(fps) == 0 {
		return
	}

	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	var dropped int
	for i, raw := range fps {
		// Normalize on seed so write-time and read-time use the same key shape.
		fp := newExpectedEndpointFingerprint(raw.Host, raw.Method, raw.Status, raw.Path, raw.BodyPreviewHash)

		// Update in-place if it already exists (operator re-clicked / startup
		// re-seed) — refreshes Reason and AddedAt, preserves Suppressed.
		if existing, ok := t.entries[fp]; ok {
			existing.AddedAt = now
			if i < len(reasons) && reasons[i] != "" {
				existing.Reason = reasons[i]
			}
			continue
		}

		if len(t.entries) >= t.cap {
			dropped++
			continue
		}

		reason := ""
		if i < len(reasons) {
			reason = reasons[i]
		}
		t.entries[fp] = &expectedEndpointEntry{
			Reason:  reason,
			AddedAt: now,
		}
	}

	if dropped > 0 {
		log.Printf("[expected_endpoint] WARNING: %d fingerprints dropped (cap %d reached). Pattern-review UI / older rules may need pruning. New operator corrections will not take effect until cap pressure clears.",
			dropped, t.cap)
	}
}

// Stats returns telemetry for /api/stats.
func (t *ExpectedEndpointTracker) Stats() (total int, suppressed int64) {
	t.mu.RLock()
	total = len(t.entries)
	t.mu.RUnlock()
	suppressed = t.totalSuppressed.Load()
	return total, suppressed
}
