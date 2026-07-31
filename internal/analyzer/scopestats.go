package analyzer

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/vaultguardian/observer/internal/patternstore"
)

// Per-scope classification-flow telemetry. Read-only observability: nothing
// here influences classification, learning, or scheduling decisions.
//
// The registry tracks up to maxTrackedScopes distinct scope keys; events for
// scopes beyond the cap are attributed to a shared "other" overflow bucket.
// The overflow bucket may only ever drive an "exceeded tracked-scope limit"
// message on the dashboard, never a per-scope warning.

const (
	maxTrackedScopes = 256
	overflowScopeKey = "other"
)

// scopeStats holds the per-scope counters. All fields are atomics so the hot
// path increments through a resolved pointer without holding any lock.
type scopeStats struct {
	eventsTotal           atomic.Int64
	deterministicResolved atomic.Int64
	initialPatternHits    atomic.Int64
	initialPatternMisses  atomic.Int64
	retryPatternHits      atomic.Int64
	backpressureDeferred  atomic.Int64
	llmCalls              atomic.Int64
	llmResolvedEvents     atomic.Int64
	hashLearnAttempts     atomic.Int64
	hashLearnInserted     atomic.Int64
	hashLearnDuplicates   atomic.Int64
	hashLearnRejected     atomic.Int64
}

// recordHashLearn counts one exact-hash learn attempt and its outcome.
// Called at each actual LearnHash call site (not at learnFromVerdict entry),
// so inserted + duplicates + rejected always sums to attempts.
func (ss *scopeStats) recordHashLearn(result patternstore.LearnResult) {
	ss.hashLearnAttempts.Add(1)
	switch result {
	case patternstore.LearnInserted:
		ss.hashLearnInserted.Add(1)
	case patternstore.LearnDuplicate:
		ss.hashLearnDuplicates.Add(1)
	case patternstore.LearnRejected:
		ss.hashLearnRejected.Add(1)
	}
}

// scopeRegistry maps scope keys to their stats, capped at maxTrackedScopes
// plus the shared overflow bucket.
type scopeRegistry struct {
	mu     sync.RWMutex
	scopes map[string]*scopeStats
	other  scopeStats

	scopesCreated  atomic.Int64 // admissions to the tracked map
	overflowEvents atomic.Int64 // events attributed to the overflow bucket
}

// resolve returns the stats bucket for scopeKey and whether it is the
// overflow bucket. Hot path is an RLock lookup; a miss upgrades to the write
// lock with a double-check before inserting.
func (r *scopeRegistry) resolve(scopeKey string) (ss *scopeStats, isOther bool) {
	r.mu.RLock()
	ss = r.scopes[scopeKey]
	r.mu.RUnlock()
	if ss != nil {
		return ss, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if ss = r.scopes[scopeKey]; ss != nil {
		return ss, false
	}
	if len(r.scopes) >= maxTrackedScopes {
		return &r.other, true
	}
	ss = &scopeStats{}
	r.scopes[scopeKey] = ss
	r.scopesCreated.Add(1)
	return ss, false
}

// ScopeSnapshot is the exported per-scope counter snapshot rendered by
// /api/stats under pipeline_health.normalizer.scopes.
type ScopeSnapshot struct {
	Scope                      string `json:"scope"`
	EventsTotal                int64  `json:"events_total"`
	DeterministicResolvedTotal int64  `json:"deterministic_resolved_total"`
	InitialPatternHits         int64  `json:"initial_pattern_hits"`
	InitialPatternMisses       int64  `json:"initial_pattern_misses"`
	RetryPatternHits           int64  `json:"retry_pattern_hits"`
	BackpressureDeferredEvents int64  `json:"backpressure_deferred_events"`
	LLMCalls                   int64  `json:"llm_calls"`
	LLMResolvedEvents          int64  `json:"llm_resolved_events"`
	HashLearnAttempts          int64  `json:"hash_learn_attempts"`
	HashLearnInserted          int64  `json:"hash_learn_inserted"`
	HashLearnDuplicates        int64  `json:"hash_learn_duplicates"`
	HashLearnRejected          int64  `json:"hash_learn_rejected"`
}

// ScopeStatsSnapshot is the registry-level snapshot: counters plus all
// tracked scopes (max 257 entries including "other"), cumulative since
// startup, sorted by scope key. No server-side ranking or truncation.
type ScopeStatsSnapshot struct {
	TrackedScopes      int             `json:"tracked_scopes"`
	ScopesCreatedTotal int64           `json:"scopes_created_total"`
	OverflowEvents     int64           `json:"overflow_events"`
	Scopes             []ScopeSnapshot `json:"scopes"`
}

func snapshotScope(name string, ss *scopeStats) ScopeSnapshot {
	return ScopeSnapshot{
		Scope:                      name,
		EventsTotal:                ss.eventsTotal.Load(),
		DeterministicResolvedTotal: ss.deterministicResolved.Load(),
		InitialPatternHits:         ss.initialPatternHits.Load(),
		InitialPatternMisses:       ss.initialPatternMisses.Load(),
		RetryPatternHits:           ss.retryPatternHits.Load(),
		BackpressureDeferredEvents: ss.backpressureDeferred.Load(),
		LLMCalls:                   ss.llmCalls.Load(),
		LLMResolvedEvents:          ss.llmResolvedEvents.Load(),
		HashLearnAttempts:          ss.hashLearnAttempts.Load(),
		HashLearnInserted:          ss.hashLearnInserted.Load(),
		HashLearnDuplicates:        ss.hashLearnDuplicates.Load(),
		HashLearnRejected:          ss.hashLearnRejected.Load(),
	}
}

// ScopeStats returns the full per-scope telemetry snapshot. It copies
// names and pointers under RLock, then reads the atomics outside the lock.
func (a *Analyzer) ScopeStats() ScopeStatsSnapshot {
	r := &a.scopes
	r.mu.RLock()
	names := make([]string, 0, len(r.scopes))
	ptrs := make([]*scopeStats, 0, len(r.scopes))
	for name, ss := range r.scopes {
		names = append(names, name)
		ptrs = append(ptrs, ss)
	}
	tracked := len(r.scopes)
	r.mu.RUnlock()

	snap := ScopeStatsSnapshot{
		TrackedScopes:      tracked,
		ScopesCreatedTotal: r.scopesCreated.Load(),
		OverflowEvents:     r.overflowEvents.Load(),
		Scopes:             make([]ScopeSnapshot, 0, len(names)+1),
	}
	for i, name := range names {
		snap.Scopes = append(snap.Scopes, snapshotScope(name, ptrs[i]))
	}
	if r.other.eventsTotal.Load() > 0 || r.overflowEvents.Load() > 0 {
		snap.Scopes = append(snap.Scopes, snapshotScope(overflowScopeKey, &r.other))
	}
	sort.Slice(snap.Scopes, func(i, j int) bool {
		return snap.Scopes[i].Scope < snap.Scopes[j].Scope
	})
	return snap
}

// RecordRetryEnqueued attributes one backpressure-deferred event to the
// scope. Called by main after every SUCCESSFUL send to the retry queue, and
// nowhere else: not on failed sends, not inside the classify flight, not at
// scheduler TryAcquire failure.
func (a *Analyzer) RecordRetryEnqueued(scopeKey string) {
	ss, _ := a.scopes.resolve(scopeKey)
	ss.backpressureDeferred.Add(1)
}
