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
// ARCHITECTURE (design consensus, 2026-03-31):
//   Structural inference NOMINATES catch-all candidates.
//   One-time active verification CONFIRMS them before permanent suppression.
//   Verified fingerprints PERSIST to SQLite across restarts.
//
//   "Don't assume, verify." — Observer's core principle.
//
//   State machine per fingerprint:
//     candidate → pending_verification → verified (suppress forever)
//                                      → rejected (keep alerting)
//
//   the design review: structural inference identifies WHICH responses to verify.
//   code review: one-time verify closes the safety gap.
//   the team: verification uses existing redaction + re-classification pipeline.
//
// COST:
//   One HTTP request + one LLM call per fingerprint LIFETIME.
//   At current scanner rates: ~3-5 verify requests per week total.

const (
	DefaultCatchAllThreshold = 5
	maxFingerprints          = 500
	maxPathsPerFingerprint   = 10
)

// catchAllState represents the lifecycle of a fingerprint.
type catchAllState string

const (
	StateCandidate           catchAllState = "candidate"
	StatePendingVerification catchAllState = "pending_verification"
	StateVerified            catchAllState = "verified"
	StateRejected            catchAllState = "rejected"
)

// CatchAllFingerprint is the key: (host, method, status, responseBytes).
// Method is included per code review's safety recommendation — POST fingerprints
// must not auto-suppress based on GET verification results.
type CatchAllFingerprint struct {
	Host          string
	Method        string
	StatusCode    int
	ResponseBytes int64
}

func (f CatchAllFingerprint) String() string {
	return fmt.Sprintf("%s/%s/%d/%d", f.Host, f.Method, f.StatusCode, f.ResponseBytes)
}

// VerifyRequest is passed to the VerifyFunc when a fingerprint needs confirmation.
type VerifyRequest struct {
	Fingerprint CatchAllFingerprint
	SamplePath  string // one of the paths that triggered this fingerprint
}

// VerifyResult is returned by the VerifyFunc after active verification.
type VerifyResult struct {
	Confirmed   bool   // true if response matched AND LLM confirmed benign
	Reason      string // human-readable explanation
	ContentType string // observed content-type
	BodyHash    string // hash of redacted body for persistence
}

// VerifyFunc is called once per fingerprint lifetime to confirm the catch-all
// is benign. main.go provides the implementation with HTTP client + LLM access.
type VerifyFunc func(req VerifyRequest) *VerifyResult

// catchAllEntry tracks the state of one fingerprint.
type catchAllEntry struct {
	Paths        map[string]bool // distinct paths seen (capped at maxPathsPerFingerprint)
	TotalPaths   int             // total distinct paths seen (uncapped count)
	FirstSeen    time.Time
	LastSeen     time.Time
	State        catchAllState
	Suppressed   int64  // how many alerts auto-downgraded by this fingerprint
	VerifyReason string // reason from verification (benign or rejected)
	ContentType  string // from verification
	BodyHash     string // from verification
}

// CatchAllTracker accumulates (host, method, status, bytes) evidence, verifies
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

// Check tests whether a (host, method, status, bytes, path) combination is a known
// verified catch-all. Returns true + reason if the alert should be auto-downgraded.
//
// Side effects:
//   - Records the path for the fingerprint
//   - If threshold crossed, triggers async verification (returns false until verified)
func (t *CatchAllTracker) Check(host, method string, statusCode int, responseBytes int64, path string) (isCatchAll bool, reason string) {
	if host == "" || responseBytes <= 0 {
		return false, ""
	}

	// Only auto-suppress GET/HEAD fingerprints in v1.
	// POST/PUT/PATCH/DELETE are tracked but not eligible for promotion.
	// (code review safety recommendation, 2026-03-31)
	methodUpper := strings.ToUpper(method)
	eligible := methodUpper == "GET" || methodUpper == "HEAD"

	// Strip query string — distinct routes, not distinct parameters.
	// ( audit, 2026-03-31)
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		path = path[:idx]
	}

	fp := CatchAllFingerprint{
		Host:          host,
		Method:        methodUpper,
		StatusCode:    statusCode,
		ResponseBytes: responseBytes,
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
		// Check if we just crossed the threshold
		if eligible && entry.TotalPaths >= t.threshold && t.verify != nil {
			entry.State = StatePendingVerification
			samplePath := firstPath(entry.Paths)

			log.Printf("[catchall] Threshold crossed — requesting verification: host=%s method=%s status=%d bytes=%d paths=%d sample=%s",
				host, methodUpper, statusCode, responseBytes, entry.TotalPaths, samplePath)

			// Async verification — don't block the coordinator
			go t.runVerification(fp, samplePath)
		}
		return false, ""

	case StatePendingVerification:
		// Still verifying — let alerts through normally
		return false, ""

	case StateVerified:
		entry.Suppressed++
		reason = fmt.Sprintf("Verified catch-all: %d distinct paths on %s all returned identical %s %d/%d-byte response — %s",
			entry.TotalPaths, host, methodUpper, statusCode, responseBytes, entry.VerifyReason)
		return true, reason

	case StateRejected:
		// Verification said this is NOT benign — keep alerting
		return false, ""
	}

	return false, ""
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
		return // entry was evicted or state changed while we were verifying
	}

	if result != nil && result.Confirmed {
		entry.State = StateVerified
		entry.VerifyReason = result.Reason
		entry.ContentType = result.ContentType
		entry.BodyHash = result.BodyHash

		log.Printf("[catchall] VERIFIED catch-all: host=%s method=%s status=%d bytes=%d reason=%s",
			fp.Host, fp.Method, fp.StatusCode, fp.ResponseBytes, truncateReason(result.Reason, 100))
	} else {
		entry.State = StateRejected
		reason := "verification failed or returned sensitive content"
		if result != nil {
			reason = result.Reason
		}
		entry.VerifyReason = reason

		log.Printf("[catchall] REJECTED catch-all: host=%s method=%s status=%d bytes=%d reason=%s",
			fp.Host, fp.Method, fp.StatusCode, fp.ResponseBytes, truncateReason(reason, 100))
	}
}

// SeedVerified injects known-good catch-alls from the database on startup.
// These were previously verified by active verification and persisted.
// No re-verification needed — trust the database.
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
		log.Printf("[catchall] Pre-warmed %d verified catch-all fingerprints from database", seeded)
	}
}

// VerifiedCatchAll holds metadata for a verified fingerprint.
// Used for persistence to SQLite.
type VerifiedCatchAll struct {
	Fingerprint  CatchAllFingerprint
	VerifyReason string
	ContentType  string
	BodyHash     string
	SamplePath   string
}

// GetNewlyVerified returns all verified fingerprints that need to be persisted.
// Called after verification completes to save to SQLite.
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
			continue // don't evict active catch-alls
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