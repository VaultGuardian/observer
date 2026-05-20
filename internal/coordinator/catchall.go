// internal/coordinator/catchall.go
package coordinator

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Catch-All Tracker — Structural Inference + One-Time Verification Gate
// =============================================================================
//
// Fix 2 (v1.0 hardening): Fingerprint key changed from ResponseBytes to
// BodyPreviewHash (SHA-256). Prevents "accordion padding" attack where
// attacker varies query params to change response size and trick the
// catch-all into auto-downgrading real data exfiltration.
//
// The body hash is already computed per response by the sniffer. The
// catch-all tracker just needs to key on it instead of byte count.
//
// design rule: "Body hash, not body size. Non-negotiable."
//
// =============================================================================
// Section 3 fix — Landmine A (v1.0 hardening, hardening catch):
// =============================================================================
// CheckFallbackByBytes is the Phase 3 fallback used when REC misses entirely
// and we have only a response byte count from the access log. It previously
// suppressed ANY (host, method, status) match under 10KB regardless of the
// verified entry's actual response size — i.e. a verified 50-byte health
// check would suppress a 9KB JSON response that REC missed.
//
// We now store the verified body's full byte count on the entry at
// verification time and require the access-log byte count to be within
// tolerance of that stored value. This closes the "verified entry suppresses
// arbitrary same-tuple traffic" hole.
// =============================================================================

const (
	DefaultCatchAllThreshold = 5
	maxFingerprints          = 500
	maxPathsPerFingerprint   = 10
	maxConcurrentVerifiers   = 5             // v0.52: bound goroutine spray from path spray attacks
	verifiedEntryTTL         = 4 * time.Hour // v0.52: verified entries evictable after TTL
)

type catchAllState string

const (
	StateCandidate           catchAllState = "candidate"
	StatePendingVerification catchAllState = "pending_verification"
	StateVerified            catchAllState = "verified"
	StateRejected            catchAllState = "rejected"
)

// CatchAllFingerprint is the key: (host, method, status, bodyPreviewHash).
type CatchAllFingerprint struct {
	Host            string
	Method          string
	StatusCode      int
	BodyPreviewHash string
}

func (f CatchAllFingerprint) String() string {
	hash := f.BodyPreviewHash
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return fmt.Sprintf("%s/%s/%d/%s", f.Host, f.Method, f.StatusCode, hash)
}

// VerifyRequest is passed to the VerifyFunc when a fingerprint needs confirmation.
type VerifyRequest struct {
	Fingerprint CatchAllFingerprint
	SamplePath  string
}

// VerifyResult is returned by the VerifyFunc after active verification.
//
// Section 3 / Landmine A: ResponseBytes added so the Phase 3 fallback can
// compare access-log byte counts against the actual verified body size
// rather than blanket-suppressing any same-tuple traffic under 10KB.
type VerifyResult struct {
	Confirmed     bool
	Reason        string
	ContentType   string
	BodyHash      string
	ResponseBytes int64 // total response body size observed during verification
}

// VerifyFunc is called once per fingerprint lifetime to confirm the catch-all
// is benign. main.go provides the implementation with HTTP client + LLM access.
type VerifyFunc func(req VerifyRequest) *VerifyResult

// catchAllEntry tracks the state of one fingerprint.
//
// Section 3 / Landmine A: ResponseBytes records the full response size
// observed at verification. CheckFallbackByBytes uses this to bound the
// fallback to byte-similar responses only.
type catchAllEntry struct {
	Paths         map[string]bool
	TotalPaths    int
	FirstSeen     time.Time
	LastSeen      time.Time
	State         catchAllState
	Suppressed    int64
	VerifyReason  string
	ContentType   string
	BodyHash      string
	ResponseBytes int64
}

// CatchAllTracker accumulates evidence, verifies candidates, and suppresses
// confirmed catch-all patterns. Thread-safe.
type CatchAllTracker struct {
	mu        sync.Mutex
	entries   map[CatchAllFingerprint]*catchAllEntry
	threshold int
	verify    VerifyFunc
	verifySem chan struct{} // v0.52: bounds concurrent verification goroutines
}

// NewCatchAllTracker creates a tracker with the given threshold and verify callback.
func NewCatchAllTracker(threshold int, verify VerifyFunc) *CatchAllTracker {
	if threshold <= 0 {
		threshold = DefaultCatchAllThreshold
	}
	return &CatchAllTracker{
		entries:   make(map[CatchAllFingerprint]*catchAllEntry),
		threshold: threshold,
		verify:    verify,
		verifySem: make(chan struct{}, maxConcurrentVerifiers),
	}
}

// Check tests whether a (host, method, status, bodyPreviewHash, path) combination
// is a known verified catch-all. Returns true + reason if the alert should be
// auto-downgraded.
func (t *CatchAllTracker) Check(host, method string, statusCode int, bodyPreviewHash string, path string) (isCatchAll bool, reason string) {
	if host == "" || bodyPreviewHash == "" {
		return false, ""
	}

	methodUpper := strings.ToUpper(method)
	eligible := methodUpper == "GET" || methodUpper == "HEAD"

	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}

	fp := CatchAllFingerprint{
		Host:            host,
		Method:          methodUpper,
		StatusCode:      statusCode,
		BodyPreviewHash: bodyPreviewHash,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.entries[fp]
	if !exists {
		if len(t.entries) >= maxFingerprints {
			t.evictOldest()
		}
		entry = &catchAllEntry{
			Paths:      map[string]bool{path: true},
			TotalPaths: 1,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			State:      StateCandidate,
		}
		t.entries[fp] = entry
		return false, ""
	}

	entry.LastSeen = time.Now()

	if !entry.Paths[path] {
		entry.TotalPaths++
		if len(entry.Paths) < maxPathsPerFingerprint {
			entry.Paths[path] = true
		}
	}

	switch entry.State {
	case StateCandidate:
		if eligible && entry.TotalPaths >= t.threshold && t.verify != nil {
			entry.State = StatePendingVerification
			samplePath := firstPath(entry.Paths)

			log.Printf("[catchall] Threshold crossed — requesting verification: host=%s method=%s status=%d hash=%.16s paths=%d sample=%s",
				host, methodUpper, statusCode, bodyPreviewHash, entry.TotalPaths, samplePath)

			// v0.52: Bounded verifier goroutines. Without a semaphore, a path
			// spray attack could launch hundreds of concurrent verification
			// goroutines blocked on HTTP probes or LLM slots.
			go func() {
				select {
				case t.verifySem <- struct{}{}:
					defer func() { <-t.verifySem }()
					t.runVerification(fp, samplePath)
				default:
					log.Printf("[catchall] Verifier semaphore full — deferring verification for %s", fp)
					t.mu.Lock()
					if e, ok := t.entries[fp]; ok && e.State == StatePendingVerification {
						e.State = StateCandidate // reset so it retriggers next threshold cross
					}
					t.mu.Unlock()
				}
			}()
		}
		return false, ""

	case StatePendingVerification:
		return false, ""

	case StateVerified:
		entry.Suppressed++
		reason = fmt.Sprintf("Verified catch-all: %d distinct paths on %s all returned identical %s %d response (body hash %.16s) — %s",
			entry.TotalPaths, host, methodUpper, statusCode, bodyPreviewHash, entry.VerifyReason)
		return true, reason

	case StateRejected:
		return false, ""
	}

	return false, ""
}

// CheckFallbackByBytes is the Phase 3 fallback for REC-miss events.
// Called only at dispatch timeout when no evidence arrived and no body hash
// is available. Checks whether a verified catch-all exists for the broader
// (host, method, status) tuple AND whether the access-log responseBytes is
// byte-similar to the verified entry's recorded size.
//
// Safety: only matches against VERIFIED entries. If any entry for this
// (host, method, status) was REJECTED, the fallback refuses to suppress.
//
// Section 3 fix (Landmine A — hardening catch):
//
//	Previous behavior allowed ANY (host, method, status) verified entry to
//	suppress ANY response under 10KB on that tuple, regardless of size.
//	A verified 50-byte health check would suppress a 9KB JSON response
//	that REC happened to miss. We now require the access-log responseBytes
//	to be within tolerance of the verified entry's recorded size.
//
// the design review threat model: REC-miss means nginx handled the request at the edge,
// so no exfiltration occurred. Accordion padding on edge 404s produces noisy
// emails but not silent breaches. Acceptable tradeoff.
func (t *CatchAllTracker) CheckFallbackByBytes(host, method string, statusCode int, responseBytes int64, path string) (isCatchAll bool, reason string) {
	if host == "" || responseBytes <= 0 {
		return false, ""
	}

	const maxEdgeResponseBytes = 10000
	if responseBytes > maxEdgeResponseBytes {
		return false, ""
	}

	methodUpper := strings.ToUpper(method)
	if methodUpper != "GET" && methodUpper != "HEAD" {
		return false, ""
	}

	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var verifiedEntry *catchAllEntry
	var verifiedFP CatchAllFingerprint
	for fp, entry := range t.entries {
		if fp.Host != host || fp.Method != methodUpper || fp.StatusCode != statusCode {
			continue
		}
		if entry.State == StateRejected {
			return false, ""
		}
		if entry.State == StateVerified && verifiedEntry == nil {
			// Section 3 / Landmine A: require byte-similarity to the verified
			// entry's recorded response size. A verified 50-byte health-check
			// entry must not suppress a 9KB response, even if both are <10KB.
			if !bytesCompatible(responseBytes, entry.ResponseBytes) {
				continue
			}
			verifiedEntry = entry
			verifiedFP = fp
		}
	}

	if verifiedEntry == nil {
		return false, ""
	}

	verifiedEntry.Suppressed++
	reason = fmt.Sprintf("Catch-all fallback (REC-miss): verified pattern exists for %s %s %d (hash %.16s, %d prior paths, verified bytes=%d) — log responseBytes=%d within tolerance",
		methodUpper, host, statusCode, verifiedFP.BodyPreviewHash, verifiedEntry.TotalPaths, verifiedEntry.ResponseBytes, responseBytes)

	log.Printf("[catchall:fallback] Suppressed via byte-similar fallback: host=%s method=%s status=%d log_bytes=%d verified_bytes=%d hash=%.16s path=%s",
		host, methodUpper, statusCode, responseBytes, verifiedEntry.ResponseBytes, verifiedFP.BodyPreviewHash, path)

	return true, reason
}

// bytesCompatible returns true when an access-log responseBytes is plausibly
// the same response as a verified entry of size verifiedBytes. Tolerance is
// ±max(15%, 256 bytes) — generous enough to absorb HTTP header variation
// (chunked encoding overhead, gzip differences, extra response headers) but
// tight enough to reject responses that are clearly different content.
//
// When verifiedBytes <= 0 (legacy entries seeded before this field existed),
// returns false — we conservatively refuse to suppress until we've actually
// re-verified and recorded the size.
func bytesCompatible(actualBytes, verifiedBytes int64) bool {
	if verifiedBytes <= 0 {
		return false
	}
	if actualBytes <= 0 {
		return false
	}
	diff := actualBytes - verifiedBytes
	if diff < 0 {
		diff = -diff
	}
	tolerance := verifiedBytes * 15 / 100
	if tolerance < 256 {
		tolerance = 256
	}
	return diff <= tolerance
}

// runVerification calls the VerifyFunc and updates the entry state.
//
// Section 3 / Landmine A: Records ResponseBytes from VerifyResult so the
// Phase 3 fallback can compare access-log byte counts against the actual
// verified body size.
func (t *CatchAllTracker) runVerification(fp CatchAllFingerprint, samplePath string) {
	result := t.verify(VerifyRequest{
		Fingerprint: fp,
		SamplePath:  samplePath,
	})

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, ok := t.entries[fp]
	if !ok || entry.State != StatePendingVerification {
		return
	}

	if result != nil && result.Confirmed {
		entry.State = StateVerified
		entry.VerifyReason = result.Reason
		entry.ContentType = result.ContentType
		entry.BodyHash = result.BodyHash
		entry.ResponseBytes = result.ResponseBytes

		log.Printf("[catchall] VERIFIED catch-all: host=%s method=%s status=%d hash=%.16s bytes=%d reason=%s",
			fp.Host, fp.Method, fp.StatusCode, fp.BodyPreviewHash, result.ResponseBytes, truncateReason(result.Reason, 100))
	} else {
		entry.State = StateRejected
		reason := "verification failed or returned sensitive content"
		if result != nil {
			reason = result.Reason
		}
		entry.VerifyReason = reason

		log.Printf("[catchall] REJECTED catch-all: host=%s method=%s status=%d hash=%.16s reason=%s",
			fp.Host, fp.Method, fp.StatusCode, fp.BodyPreviewHash, truncateReason(reason, 100))
	}
}

// SeedVerified injects known-good catch-alls from the database on startup.
//
// Section 3 / Landmine A: Now also seeds ResponseBytes when available. Legacy
// rows from before the schema migration arrive with responseBytes=0; entries
// seeded that way will be skipped by the Phase 3 fallback (bytesCompatible
// returns false for verifiedBytes<=0) until they're re-verified and persisted
// with a real byte count. Conservative by design — better to email noisy than
// suppress real traffic.
func (t *CatchAllTracker) SeedVerified(fps []CatchAllFingerprint, reasons []string, responseBytesList []int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	seeded := 0
	zeroBytes := 0
	for i, fp := range fps {
		// v0.52: Enforce maxFingerprints during seed. Without this check,
		// a database with thousands of verified catch-alls would load them
		// all into memory at startup, bypassing the cap that Check() enforces.
		if len(t.entries) >= maxFingerprints {
			log.Printf("[catchall] SeedVerified: hit cap (%d) — skipped %d remaining entries", maxFingerprints, len(fps)-i)
			break
		}

		reason := ""
		if i < len(reasons) {
			reason = reasons[i]
		}
		var responseBytes int64
		if i < len(responseBytesList) {
			responseBytes = responseBytesList[i]
		}
		if responseBytes <= 0 {
			zeroBytes++
		}

		t.entries[fp] = &catchAllEntry{
			Paths:         make(map[string]bool),
			TotalPaths:    t.threshold,
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
			State:         StateVerified,
			VerifyReason:  reason,
			ResponseBytes: responseBytes,
		}
		seeded++
	}

	if seeded > 0 {
		log.Printf("[catchall] Pre-warmed %d verified catch-all fingerprints from database", seeded)
		if zeroBytes > 0 {
			log.Printf("[catchall] WARNING: %d/%d seeded entries have responseBytes=0 (pre-migration). Phase 3 fallback will skip these until re-verified.", zeroBytes, seeded)
		}
	}
}

// VerifiedCatchAll holds metadata for a verified fingerprint.
type VerifiedCatchAll struct {
	Fingerprint   CatchAllFingerprint
	VerifyReason  string
	ContentType   string
	BodyHash      string
	SamplePath    string
	ResponseBytes int64
}

// GetNewlyVerified returns all verified fingerprints that need to be persisted.
func (t *CatchAllTracker) GetNewlyVerified() []VerifiedCatchAll {
	t.mu.Lock()
	defer t.mu.Unlock()

	var result []VerifiedCatchAll
	for fp, entry := range t.entries {
		if entry.State == StateVerified {
			result = append(result, VerifiedCatchAll{
				Fingerprint:   fp,
				VerifyReason:  entry.VerifyReason,
				ContentType:   entry.ContentType,
				BodyHash:      entry.BodyHash,
				SamplePath:    firstPath(entry.Paths),
				ResponseBytes: entry.ResponseBytes,
			})
		}
	}
	return result
}

// Stats returns a summary of tracker state for telemetry.
func (t *CatchAllTracker) Stats() (total, candidates, pending, verified, rejected int, suppressed int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, entry := range t.entries {
		total++
		switch entry.State {
		case StateCandidate:
			candidates++
		case StatePendingVerification:
			pending++
		case StateVerified:
			verified++
			suppressed += entry.Suppressed
		case StateRejected:
			rejected++
		}
	}
	return
}

// evictOldest removes the entry with the oldest LastSeen. Must be called with mu held.
//
// v0.52: Verified entries are no longer immortal. Eviction prefers non-verified
// entries first. If only verified entries remain, evicts the oldest one past TTL.
// If ALL entries are verified and within TTL, evicts the oldest anyway — the hard
// cap is non-negotiable (prevents unbounded growth from SeedVerified + Check).
func (t *CatchAllTracker) evictOldest() {
	var bestFP CatchAllFingerprint
	var bestTime time.Time
	bestIsVerified := true
	found := false
	now := time.Now()

	for fp, entry := range t.entries {
		isVerified := entry.State == StateVerified
		isPastTTL := isVerified && now.Sub(entry.LastSeen) > verifiedEntryTTL

		// Prefer non-verified over verified, prefer past-TTL verified over fresh verified
		better := false
		if !found {
			better = true
		} else if !isVerified && bestIsVerified {
			// Non-verified always beats verified
			better = true
		} else if isVerified && bestIsVerified {
			// Both verified: prefer past-TTL, then oldest
			if isPastTTL && entry.LastSeen.Before(bestTime) {
				better = true
			} else if !found || entry.LastSeen.Before(bestTime) {
				better = true
			}
		} else if !isVerified && !bestIsVerified {
			// Both non-verified: oldest wins
			if entry.LastSeen.Before(bestTime) {
				better = true
			}
		}

		if better {
			bestFP = fp
			bestTime = entry.LastSeen
			bestIsVerified = isVerified
			found = true
		}
	}
	if found {
		delete(t.entries, bestFP)
	}
}

func firstPath(paths map[string]bool) string {
	for p := range paths {
		return p
	}
	return ""
}

func samplePaths(paths map[string]bool, max int) string {
	result := ""
	count := 0
	for p := range paths {
		if count > 0 {
			result += ", "
		}
		result += p
		count++
		if count >= max {
			break
		}
	}
	return result
}

func truncateReason(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
