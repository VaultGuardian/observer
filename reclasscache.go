package main

import (
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/vaultguardian/observer/internal/llm"
)

// =============================================================================
// Re-Classification Cache
// =============================================================================
//
// When the LLM re-classifies an alert with response evidence, we cache the
// result keyed on the REDACTED BODY PREVIEW HASH.
//
// WHY BODY HASH:
//   The response body IS the evidence. Same body = same conclusion.
//   The Laravel welcome page is always the Laravel welcome page, whether
//   the attack was SQL injection, path traversal, or command injection.
//   If the body changes (app update, different error page, or the attack
//   actually succeeded and returned real data), the hash changes and we
//   call the LLM fresh.
//
// COST IMPACT:
//   Without cache: 100 identical attacks × 2 LLM calls each = 200 calls/day
//   With cache: 1 LLM classify + 1 LLM re-classify + 198 cache hits = 2 calls/day
//   At $1.35/500K tokens, this is the difference between pennies and dollars.
//
// MEMORY:
//   Bounded to 1000 entries. In practice, a server has a small number of
//   distinct response bodies (welcome page, 404 page, API status, etc.)
//   so this rarely exceeds a dozen entries.

const maxReclassCacheEntries = 1000

type reclassCacheEntry struct {
	downgraded  bool
	escalated   bool
	reason      string
	newSeverity string // only set when escalated
}

type reclassCache struct {
	mu      sync.RWMutex
	entries map[string]reclassCacheEntry // bodyPreviewHash → result

	// flight coalesces concurrent T2 reclassifications of the same redacted
	// body shape into a single in-flight LLM call (same key namespace as
	// entries: the redacted shape hash). It lives alongside the durable
	// cache so the two share a lifecycle, but the correction-path delete()
	// does not interact with in-flight calls. Zero value is ready to use.
	flight singleflight.Group
}

// reclassFlightResult is the shared outcome of one coalesced T2
// reclassification. Mirrors analyzer.classifyFlightResult: the leader is
// identified by LeaderEventID == its own snapshot.EventID — NOT by
// singleflight's shared bool (the leader can also observe shared==true).
// Followers read Reclass but never mutate it.
type reclassFlightResult struct {
	Reclass       *llm.ReclassifyVerdict
	LeaderEventID string
}

func newReclassCache() *reclassCache {
	return &reclassCache{
		entries: make(map[string]reclassCacheEntry),
	}
}

func (c *reclassCache) get(bodyHash string) (reclassCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[bodyHash]
	return entry, ok
}

func (c *reclassCache) put(bodyHash string, downgraded bool, escalated bool, reason string, newSeverity string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Bounded: if cache is full, clear it and start fresh.
	// In practice this almost never happens — distinct response bodies
	// are a small set (welcome page, 404, API status, etc.)
	if len(c.entries) >= maxReclassCacheEntries {
		c.entries = make(map[string]reclassCacheEntry)
	}

	c.entries[bodyHash] = reclassCacheEntry{
		downgraded:  downgraded,
		escalated:   escalated,
		reason:      reason,
		newSeverity: newSeverity,
	}
}

// delete removes a specific body hash from the cache. Called when a human
// correction overrides a Tier 2 evidence decision — the old cached verdict
// must not persist. (design consensus: if you leave the wrong answer in
// the fast-access cache, you haven't actually fixed the problem.)
func (c *reclassCache) delete(bodyHash string) {
	if bodyHash == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, bodyHash)
}
