package coordinator

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// =============================================================================
// Catch-All Tracker — Passive Structural Inference (Tier 2)
// =============================================================================
//
// WHY THIS EXISTS:
//   Scanners spray dozens of paths at a host. When the server returns the
//   same (status, body_bytes) for every path, it's a catch-all: a default
//   page, a login redirect, an error template. These are not security events.
//
//   Examples from production:
//     - media-api.admin.kovicloud.com: 302/138 on every path (HTTP→HTTPS redirect)
//     - media.admin.kovicloud.com: 200/1309 on every path (MinIO login page)
//     - 404/2401 on random paths (nginx default 404)
//
// HOW IT WORKS:
//   Track (host, status, responseBytes) tuples. Count distinct request paths
//   per tuple. Once a tuple has been seen with N different paths, mark it as
//   a "catch-all fingerprint." Future alerts matching that fingerprint are
//   auto-downgraded without evidence check or LLM call.
//
// DESIGN DECISION (2026-03-31):
//   the team, code review, and  independently converged on structural
//   inference over active verification. the design review's framing: "Don't ask the
//   server what it did. The server already told you in the nginx log."
//   code review's refinement: treat as strong evidence, not absolute proof.
//   Same (host, status, bytes) across many scanner-like paths is convincing.

const (
	// DefaultCatchAllThreshold is how many distinct paths with the same
	// (host, status, bytes) tuple must be seen before marking it as a catch-all.
	// 5 is conservative enough to avoid false positives from legitimate routes
	// that happen to share a response size.
	DefaultCatchAllThreshold = 5

	// maxFingerprints limits memory. Each fingerprint is tiny (~100 bytes),
	// but unbounded maps are a liability. 500 covers any realistic deployment.
	maxFingerprints = 500

	// maxPathsPerFingerprint limits how many sample paths we store per tuple.
	// Only used for logging/diagnostics — we stop storing paths once the
	// threshold is reached, but keep counting.
	maxPathsPerFingerprint = 10
)

// CatchAllFingerprint is the key: (host, status, responseBytes).
// A tuple that recurs across many distinct paths is a catch-all.
type CatchAllFingerprint struct {
	Host          string
	StatusCode    int
	ResponseBytes int64
}

func (f CatchAllFingerprint) String() string {
	return fmt.Sprintf("%s/%d/%d", f.Host, f.StatusCode, f.ResponseBytes)
}

// catchAllEntry tracks how many distinct paths have been seen for one fingerprint.
type catchAllEntry struct {
	Paths       map[string]bool // distinct paths seen (capped at maxPathsPerFingerprint)
	TotalPaths  int             // total distinct paths seen (uncapped count)
	FirstSeen   time.Time
	LastSeen    time.Time
	IsCatchAll  bool            // flipped to true once threshold is reached
	Suppressed  int64           // how many alerts were auto-downgraded by this fingerprint
}

// CatchAllTracker accumulates (host, status, bytes) evidence and identifies
// catch-all response patterns. Thread-safe.
type CatchAllTracker struct {
	mu        sync.Mutex
	entries   map[CatchAllFingerprint]*catchAllEntry
	threshold int
}

// NewCatchAllTracker creates a tracker with the given threshold.
func NewCatchAllTracker(threshold int) *CatchAllTracker {
	if threshold <= 0 {
		threshold = DefaultCatchAllThreshold
	}
	return &CatchAllTracker{
		entries:   make(map[CatchAllFingerprint]*catchAllEntry),
		threshold: threshold,
	}
}

// Check tests whether a (host, status, bytes, path) combination is a known
// catch-all. Returns true + reason if the alert should be auto-downgraded.
//
// Side effect: always records the path for the fingerprint, potentially
// promoting the fingerprint to catch-all status.
func (t *CatchAllTracker) Check(host string, statusCode int, responseBytes int64, path string) (isCatchAll bool, reason string) {
	// Skip if we don't have enough metadata to fingerprint.
	// ResponseBytes == 0 means extractResponseBytes() couldn't parse it.
	if host == "" || responseBytes <= 0 {
		return false, ""
	}

	fp := CatchAllFingerprint{
		Host:          host,
		StatusCode:    statusCode,
		ResponseBytes: responseBytes,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	entry, exists := t.entries[fp]
	if !exists {
		// Evict oldest if at capacity
		if len(t.entries) >= maxFingerprints {
			t.evictOldest()
		}

		entry = &catchAllEntry{
			Paths:     map[string]bool{path: true},
			TotalPaths: 1,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
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

	// Check if we just crossed the threshold
	if !entry.IsCatchAll && entry.TotalPaths >= t.threshold {
		entry.IsCatchAll = true
		log.Printf("[catchall] NEW catch-all detected: host=%s status=%d bytes=%d paths=%d (first path examples: %s)",
			host, statusCode, responseBytes, entry.TotalPaths, samplePaths(entry.Paths, 3))
	}

	if entry.IsCatchAll {
		entry.Suppressed++
		reason = fmt.Sprintf("Structural inference: %d distinct paths on %s all returned identical %d/%d-byte response — catch-all page (not path-specific content)",
			entry.TotalPaths, host, statusCode, responseBytes)
		return true, reason
	}

	return false, ""
}

// IsCatchAll checks if a fingerprint is already marked as catch-all
// without recording a new path. Used for pre-checks where you don't
// want to mutate state.
func (t *CatchAllTracker) IsCatchAll(host string, statusCode int, responseBytes int64) bool {
	if host == "" || responseBytes <= 0 {
		return false
	}
	fp := CatchAllFingerprint{
		Host:          host,
		StatusCode:    statusCode,
		ResponseBytes: responseBytes,
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if entry, ok := t.entries[fp]; ok {
		return entry.IsCatchAll
	}
	return false
}

// Stats returns a summary of tracker state for telemetry.
func (t *CatchAllTracker) Stats() (total int, catchAlls int, suppressed int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, entry := range t.entries {
		total++
		if entry.IsCatchAll {
			catchAlls++
			suppressed += entry.Suppressed
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
		// Don't evict active catch-alls — they're doing work
		if entry.IsCatchAll {
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