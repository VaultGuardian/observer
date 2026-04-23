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
// the design review mandate: "Body hash, not body size. Non-negotiable."

const (
	DefaultCatchAllThreshold = 5
	maxFingerprints          = 500
	maxPathsPerFingerprint   = 10
)

type catchAllState string

const (
	StateCandidate           catchAllState = "candidate"
	StatePendingVerification catchAllState = "pending_verification"
	StateVerified            catchAllState = "verified"
	StateRejected            catchAllState = "rejected"
)

// CatchAllFingerprint is the key: (host, method, status, bodyPreviewHash).
//
// Fix 2: ResponseBytes replaced with BodyPreviewHash (SHA-256).
// An attacker can vary response size by padding but cannot forge
// the SHA-256 hash of the redacted body preview.
//
// Method is included per code review's safety recommendation — POST fingerprints
// must not auto-suppress based on GET verification results.
type CatchAllFingerprint struct {
	Host            string
	Method          string
	StatusCode      int
	BodyPreviewHash string // SHA-256 of response body preview — replaces ResponseBytes
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
type VerifyResult struct {
	Confirmed   bool
	Reason      string
	ContentType string
	BodyHash    string // hash of redacted body for persistence
}

// VerifyFunc is called once per fingerprint lifetime to confirm the catch-all
// is benign. main.go provides the implementation with HTTP client + LLM access.
type VerifyFunc func(req VerifyRequest) *VerifyResult

// catchAllEntry tracks the state of one fingerprint.
type catchAllEntry struct {
	Paths        map[string]bool
	TotalPaths   int
	FirstSeen    time.Time
	LastSeen     time.Time
	State        catchAllState
	Suppressed   int64
	VerifyReason string
	ContentType  string
	BodyHash     string
}

// CatchAllTracker accumulates (host, method, status, bodyHash) evidence, verifies
// candidates, and suppresses confirmed catch-all patterns. Thread-safe.
type CatchAllTracker struct {
	mu        sync.Mutex
	entries   map[CatchAllFingerprint]*catchAllEntry
	threshold int
	verify    VerifyFunc
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
	}
}

// Check tests whether a (host, method, status, bodyPreviewHash, path) combination
// is a known verified catch-all. Returns true + reason if the alert should be
// auto-downgraded.
//
// Fix 2: bodyPreviewHash parameter replaces responseBytes.
func (t *CatchAllTracker) Check(host, method string, statusCode int, bodyPreviewHash string, path string) (isCatchAll bool, reason string) {
	if host == "" || bodyPreviewHash == "" {
		return false, ""
	}

	// Only auto-suppress GET/HEAD fingerprints in v1.
	methodUpper := strings.ToUpper(method)
	eligible := methodUpper == "GET" || methodUpper == "HEAD"

	// Strip query string
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

	// Record new distinct path
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

			go t.runVerification(fp, samplePath)
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
// (host, method, status) tuple — ignoring body hash since we don't have one.
//
// Safety: only matches against VERIFIED entries (which passed the full
// body-hash + self-check + LLM verification pipeline). If any entry for
// this (host, method, status) was REJECTED, the fallback refuses to suppress.
//
// the design review threat model: REC-miss means nginx handled the request at the edge,
// so no exfiltration occurred. Accordion padding on edge 404s produces noisy
// emails but not silent breaches. Acceptable tradeoff.
func (t *CatchAllTracker) CheckFallbackByBytes(host, method string, statusCode int, responseBytes int64, path string) (isCatchAll bool, reason string) {
	if host == "" || responseBytes <= 0 {
		return false, ""
	}

	// Edge-generated responses (nginx default 404, 302 redirects) are small.
	// Real backend content is typically much larger. This cap prevents the
	// fallback from suppressing responses that are clearly not edge templates.
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

	// Scan all entries for matching (host, method, status).
	// If any match is REJECTED, refuse the fallback entirely.
	// If at least one match is VERIFIED, suppress.
	var verifiedEntry *catchAllEntry
	var verifiedFP CatchAllFingerprint
	for fp, entry := range t.entries {
		if fp.Host != host || fp.Method != methodUpper || fp.StatusCode != statusCode {
			continue
		}
		if entry.State == StateRejected {
			// A rejection for this combo means we can't blindly suppress.
			return false, ""
		}
		if entry.State == StateVerified && verifiedEntry == nil {
			verifiedEntry = entry
			verifiedFP = fp
		}
	}

	if verifiedEntry == nil {
		return false, ""
	}

	verifiedEntry.Suppressed++
	reason = fmt.Sprintf("Catch-all fallback (REC-miss): verified pattern exists for %s %s %d (hash %.16s, %d prior paths) — ResponseBytes=%d, no body hash available",
		methodUpper, host, statusCode, verifiedFP.BodyPreviewHash, verifiedEntry.TotalPaths, responseBytes)

	log.Printf("[catchall:fallback] Suppressed via ResponseBytes: host=%s method=%s status=%d resp_bytes=%d verified_hash=%.16s path=%s",
		host, methodUpper, statusCode, responseBytes, verifiedFP.BodyPreviewHash, path)

	return true, reason
}

// runVerification calls the VerifyFunc and updates the entry state.
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

		log.Printf("[catchall] VERIFIED catch-all: host=%s method=%s status=%d hash=%.16s reason=%s",
			fp.Host, fp.Method, fp.StatusCode, fp.BodyPreviewHash, truncateReason(result.Reason, 100))
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
func (t *CatchAllTracker) SeedVerified(fps []CatchAllFingerprint, reasons []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	seeded := 0
	for i, fp := range fps {
		reason := ""
		if i < len(reasons) {
			reason = reasons[i]
		}

		t.entries[fp] = &catchAllEntry{
			Paths:        make(map[string]bool),
			TotalPaths:   t.threshold,
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			State:        StateVerified,
			VerifyReason: reason,
		}
		seeded++
	}

	if seeded > 0 {
		log.Printf("[catchall] Pre-warmed %d verified catch-all fingerprints from database (v2, body hash keyed)", seeded)
	}
}

// VerifiedCatchAll holds metadata for a verified fingerprint.
type VerifiedCatchAll struct {
	Fingerprint  CatchAllFingerprint
	VerifyReason string
	ContentType  string
	BodyHash     string
	SamplePath   string
}

// GetNewlyVerified returns all verified fingerprints that need to be persisted.
func (t *CatchAllTracker) GetNewlyVerified() []VerifiedCatchAll {
	t.mu.Lock()
	defer t.mu.Unlock()

	var result []VerifiedCatchAll
	for fp, entry := range t.entries {
		if entry.State == StateVerified {
			result = append(result, VerifiedCatchAll{
				Fingerprint:  fp,
				VerifyReason: entry.VerifyReason,
				ContentType:  entry.ContentType,
				BodyHash:     entry.BodyHash,
				SamplePath:   firstPath(entry.Paths),
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
func (t *CatchAllTracker) evictOldest() {
	var oldestFP CatchAllFingerprint
	var oldestTime time.Time
	first := true
	for fp, entry := range t.entries {
		if entry.State == StateVerified {
			continue
		}
		if first || entry.LastSeen.Before(oldestTime) {
			oldestFP = fp
			oldestTime = entry.LastSeen
			first = false
		}
	}
	if !first {
		delete(t.entries, oldestFP)
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