package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/patternstore"
)

// llmStub serves a fixed verdict JSON in the inference-server response shape.
func llmStub(t *testing.T, verdictJSON string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": verdictJSON}},
			},
			"usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	return server
}

func newScopeTestAnalyzer(t *testing.T, llmURL string, scheduler LLMScheduler) (*Analyzer, *patternstore.Store) {
	t.Helper()
	patterns, err := patternstore.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	llmClient := llm.NewClient(llmURL, "test-model", "", "low", "medium")
	return New(normalizer.NewRegistry(), patterns, llmClient, scheduler), patterns
}

func testEvent(sourceName, line string) *event.Event {
	return &event.Event{
		ID:          event.NewID(),
		SourceType:  "docker",
		SourceName:  sourceName,
		Line:        line,
		Stream:      "stdout",
		Timestamp:   time.Now(),
		ProcessedAt: time.Now(),
	}
}

func findScope(t *testing.T, a *Analyzer, key string) ScopeSnapshot {
	t.Helper()
	for _, s := range a.ScopeStats().Scopes {
		if s.Scope == key {
			return s
		}
	}
	t.Fatalf("scope %q not found in snapshot", key)
	return ScopeSnapshot{}
}

const (
	scopeTestSource = "captain-nginx"
	scopeTestKey    = "docker:" + scopeTestSource
	failedProbeLine = "captain.admin.kovicloud.com GET /favicon.ico HTTP/1.1 404"
	unknownLine     = "captain.admin.kovicloud.com GET /favicon.ico HTTP/1.1 200"
)

const allowVerdictJSON = `{"classification":"safe","confidence":0.95,"reason":"static asset request, normal traffic","action":"allow","pattern_type":"prefix","pattern":"captain.admin.kovicloud.com GET /favicon.ico"}`

// TestScopeStats_DeterministicResolved: a failed-probe line resolves in the
// deterministic layer and counts events_total + deterministic_resolved_total,
// nothing else.
func TestScopeStats_DeterministicResolved(t *testing.T) {
	a, _ := newScopeTestAnalyzer(t, "http://unused.invalid", newCountingScheduler(1))

	result := a.Analyze(context.Background(), testEvent(scopeTestSource, failedProbeLine))
	if result.Source != "noise_filter" {
		t.Fatalf("result source = %q, want noise_filter (test line must resolve deterministically)", result.Source)
	}

	ss := findScope(t, a, scopeTestKey)
	if ss.EventsTotal != 1 || ss.DeterministicResolvedTotal != 1 {
		t.Errorf("events_total=%d deterministic=%d, want 1 and 1", ss.EventsTotal, ss.DeterministicResolvedTotal)
	}
	if ss.InitialPatternHits != 0 || ss.InitialPatternMisses != 0 || ss.LLMCalls != 0 {
		t.Errorf("deterministic path leaked into other counters: %+v", ss)
	}

	snap := a.ScopeStats()
	if snap.TrackedScopes != 1 || snap.ScopesCreatedTotal != 1 || snap.OverflowEvents != 0 {
		t.Errorf("registry = tracked %d, created %d, overflow %d; want 1, 1, 0",
			snap.TrackedScopes, snap.ScopesCreatedTotal, snap.OverflowEvents)
	}
}

// TestScopeStats_MissRetryAndHit walks one event through backpressure and
// retry: the initial Analyze is a pattern miss counted once, AnalyzeRetry
// never adds to events_total, and its initial pattern check counts
// retry_pattern_hits. A later fresh Analyze of the now-cached line counts
// initial_pattern_hits.
func TestScopeStats_MissRetryAndHit(t *testing.T) {
	// Zero-capacity scheduler: TryAcquire always fails, so Analyze defers.
	a, patterns := newScopeTestAnalyzer(t, "http://unused.invalid", newCountingScheduler(0))

	evt := testEvent(scopeTestSource, unknownLine)
	result := a.Analyze(context.Background(), evt)
	if result.Source != "backpressure" {
		t.Fatalf("result source = %q, want backpressure", result.Source)
	}

	ss := findScope(t, a, scopeTestKey)
	if ss.EventsTotal != 1 || ss.InitialPatternMisses != 1 || ss.InitialPatternHits != 0 {
		t.Errorf("after deferred Analyze: events_total=%d misses=%d hits=%d, want 1, 1, 0",
			ss.EventsTotal, ss.InitialPatternMisses, ss.InitialPatternHits)
	}

	// The pattern is learned while the event sits in the retry queue.
	if err := patterns.Learn(scopeTestKey, patternstore.VerdictAllow, patternstore.LearnedPattern{
		Type:      patternstore.PatternHash,
		Value:     evt.Hash,
		Source:    "human",
		Reason:    "operator confirmed",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Learn: %v", err)
	}

	retryResult := a.AnalyzeRetry(context.Background(), evt)
	if retryResult.Verdict != patternstore.VerdictAllow {
		t.Fatalf("retry verdict = %q, want allow via pattern", retryResult.Verdict)
	}

	ss = findScope(t, a, scopeTestKey)
	if ss.EventsTotal != 1 {
		t.Errorf("events_total = %d after retry, want 1 (retry must not double-count)", ss.EventsTotal)
	}
	if ss.RetryPatternHits != 1 {
		t.Errorf("retry_pattern_hits = %d, want 1 (AnalyzeRetry initial check)", ss.RetryPatternHits)
	}
	if ss.InitialPatternHits != 0 {
		t.Errorf("initial_pattern_hits = %d after retry, want 0", ss.InitialPatternHits)
	}

	// A fresh event with the same line now hits the initial pattern check.
	a.Analyze(context.Background(), testEvent(scopeTestSource, unknownLine))
	ss = findScope(t, a, scopeTestKey)
	if ss.EventsTotal != 2 || ss.InitialPatternHits != 1 {
		t.Errorf("after cached Analyze: events_total=%d hits=%d, want 2 and 1", ss.EventsTotal, ss.InitialPatternHits)
	}
}

// TestScopeStats_DisclosureOverrideCountsAsMiss: a cached suppress verdict on
// a disclosure-bearing line is overridden and must count as an initial
// pattern miss, never a hit.
func TestScopeStats_DisclosureOverrideCountsAsMiss(t *testing.T) {
	// Low confidence so the LLM path learns nothing on its own.
	server := llmStub(t, `{"classification":"unclear","confidence":0.5,"reason":"unsure","action":"alert"}`)
	a, patterns := newScopeTestAnalyzer(t, server.URL, newCountingScheduler(4))

	line := `ERROR dumped root:x:0:0:root credentials in response body`
	evt := testEvent(scopeTestSource, line)
	a.Analyze(context.Background(), evt)

	ss := findScope(t, a, scopeTestKey)
	if ss.InitialPatternMisses != 1 || ss.InitialPatternHits != 0 {
		t.Fatalf("first pass: misses=%d hits=%d, want 1 and 0", ss.InitialPatternMisses, ss.InitialPatternHits)
	}

	// Poison the cache: a human-sourced suppress hash for the same line.
	if err := patterns.Learn(scopeTestKey, patternstore.VerdictSuppress, patternstore.LearnedPattern{
		Type:      patternstore.PatternHash,
		Value:     evt.Hash,
		Source:    "human",
		Reason:    "historically poisoned entry",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Learn: %v", err)
	}

	result := a.Analyze(context.Background(), testEvent(scopeTestSource, line))
	if result.Source == "suppress" || result.Verdict == patternstore.VerdictSuppress {
		t.Fatalf("disclosure line was suppressed by cache: %+v", result)
	}

	ss = findScope(t, a, scopeTestKey)
	if ss.InitialPatternHits != 0 {
		t.Errorf("initial_pattern_hits = %d, want 0 (overridden hit counts as miss)", ss.InitialPatternHits)
	}
	if ss.InitialPatternMisses != 2 {
		t.Errorf("initial_pattern_misses = %d, want 2", ss.InitialPatternMisses)
	}
}

// TestScopeStats_SingleflightBurst: leader + N followers on one flight yield
// llm_calls=1 and llm_resolved_events=N+1, and exactly one hash-learn attempt
// (the leader's learn).
func TestScopeStats_SingleflightBurst(t *testing.T) {
	const burst = 20

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hold the call open so the whole burst joins the same flight.
		time.Sleep(200 * time.Millisecond)
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": allowVerdictJSON}},
			},
			"usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	a, _ := newScopeTestAnalyzer(t, server.URL, newCountingScheduler(8))

	var start, done sync.WaitGroup
	start.Add(1)
	results := make([]AnalysisResult, burst)
	for i := 0; i < burst; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			evt := testEvent(scopeTestSource, unknownLine)
			start.Wait()
			results[i] = a.Analyze(context.Background(), evt)
		}(i)
	}
	start.Done()
	done.Wait()

	for i, r := range results {
		if r.Source != "llm" {
			t.Fatalf("result[%d] source = %q, want llm", i, r.Source)
		}
	}

	ss := findScope(t, a, scopeTestKey)
	if ss.LLMCalls != 1 {
		t.Errorf("llm_calls = %d, want 1 (leader only)", ss.LLMCalls)
	}
	if ss.LLMResolvedEvents != burst {
		t.Errorf("llm_resolved_events = %d, want %d (leader plus every follower)", ss.LLMResolvedEvents, burst)
	}
	if ss.EventsTotal != burst || ss.InitialPatternMisses != burst {
		t.Errorf("events_total=%d misses=%d, want %d and %d", ss.EventsTotal, ss.InitialPatternMisses, burst, burst)
	}
	if ss.HashLearnAttempts != 1 || ss.HashLearnInserted != 1 {
		t.Errorf("hash learn attempts=%d inserted=%d, want 1 and 1 (leader learns once)",
			ss.HashLearnAttempts, ss.HashLearnInserted)
	}
}

// slowFailScheduler makes TryAcquire hang long enough for a burst to coalesce
// on the leader's flight, then fail - modeling full scheduler saturation.
type slowFailScheduler struct {
	delay   time.Duration
	dropped atomic.Int64
}

func (s *slowFailScheduler) TryAcquire() (func(), bool) {
	time.Sleep(s.delay)
	s.dropped.Add(1)
	return nil, false
}

func (s *slowFailScheduler) AcquireBlocking(ctx context.Context) (func(), bool) {
	return nil, false
}

// TestScopeStats_BackpressureBurst: a failed leader flight with N coalesced
// followers is ONE deferred flight, and each successfully enqueued event
// counts once via RecordRetryEnqueued (called by main after the send).
func TestScopeStats_BackpressureBurst(t *testing.T) {
	const burst = 10

	scheduler := &slowFailScheduler{delay: 500 * time.Millisecond}
	a, _ := newScopeTestAnalyzer(t, "http://unused.invalid", scheduler)

	var start, done sync.WaitGroup
	start.Add(1)
	results := make([]AnalysisResult, burst)
	for i := 0; i < burst; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			evt := testEvent(scopeTestSource, unknownLine)
			start.Wait()
			results[i] = a.Analyze(context.Background(), evt)
		}(i)
	}
	start.Done()
	done.Wait()

	for i, r := range results {
		if r.Source != "backpressure" {
			t.Fatalf("result[%d] source = %q, want backpressure", i, r.Source)
		}
		// Mirror main.go: every SUCCESSFUL retry-queue send records once.
		a.RecordRetryEnqueued(r.Event.ScopeKey())
	}

	if got := scheduler.dropped.Load(); got != 1 {
		t.Errorf("scheduler saw %d TryAcquire failures, want 1 (one deferred flight for the burst)", got)
	}
	if got := a.GetStats().LLMDropped; got != 1 {
		t.Errorf("analyzer LLMDropped = %d, want 1 (per flight, not per event)", got)
	}

	ss := findScope(t, a, scopeTestKey)
	if ss.BackpressureDeferredEvents != burst {
		t.Errorf("backpressure_deferred_events = %d, want %d (every enqueued event counts once)",
			ss.BackpressureDeferredEvents, burst)
	}
	if ss.LLMCalls != 0 || ss.LLMResolvedEvents != 0 {
		t.Errorf("llm counters moved on a backpressure flight: %+v", ss)
	}
}

// TestScopeStats_OverflowBucket: the registry admits 256 scopes; further
// scopes attribute their events to the shared "other" bucket.
func TestScopeStats_OverflowBucket(t *testing.T) {
	a, _ := newScopeTestAnalyzer(t, "http://unused.invalid", newCountingScheduler(1))

	const total = maxTrackedScopes + 2
	for i := 0; i < total; i++ {
		a.Analyze(context.Background(), testEvent(fmt.Sprintf("svc-%04d", i), failedProbeLine))
	}

	snap := a.ScopeStats()
	if snap.TrackedScopes != maxTrackedScopes {
		t.Errorf("tracked_scopes = %d, want %d", snap.TrackedScopes, maxTrackedScopes)
	}
	if snap.ScopesCreatedTotal != maxTrackedScopes {
		t.Errorf("scopes_created_total = %d, want %d", snap.ScopesCreatedTotal, maxTrackedScopes)
	}
	if snap.OverflowEvents != 2 {
		t.Errorf("overflow_events = %d, want 2", snap.OverflowEvents)
	}
	if len(snap.Scopes) != maxTrackedScopes+1 {
		t.Errorf("snapshot has %d scopes, want %d (tracked plus other)", len(snap.Scopes), maxTrackedScopes+1)
	}
	if !sort.SliceIsSorted(snap.Scopes, func(i, j int) bool {
		return snap.Scopes[i].Scope < snap.Scopes[j].Scope
	}) {
		t.Error("snapshot scopes are not sorted by scope key")
	}

	other := findScope(t, a, overflowScopeKey)
	if other.EventsTotal != snap.OverflowEvents {
		t.Errorf("other.events_total = %d, want overflow_events %d", other.EventsTotal, snap.OverflowEvents)
	}
}

// TestScopeStats_RejectedHashStillLearnsGeneralized: an exact-hash learn
// rejected at the auto-learn cap must not block the generalized-pattern
// learning path, and the rejection is visible in the per-scope counters.
func TestScopeStats_RejectedHashStillLearnsGeneralized(t *testing.T) {
	server := llmStub(t, allowVerdictJSON)
	a, patterns := newScopeTestAnalyzer(t, server.URL, newCountingScheduler(4))

	// Fill the allow bucket's hash tier to the auto-learn cap.
	for i := 0; i < patternstore.MaxAutoHashesPerBucket; i++ {
		patterns.LearnHash(scopeTestKey, patternstore.VerdictAllow,
			fmt.Sprintf("fill%060d", i), "filler", "", "evt_fill")
	}

	result := a.Analyze(context.Background(), testEvent(scopeTestSource, unknownLine))
	if result.Source != "llm" {
		t.Fatalf("result source = %q, want llm", result.Source)
	}
	if !result.LLMPatternLearned {
		t.Error("LLMPatternLearned = false: rejected exact hash blocked the generalized learn")
	}
	if got := a.GetStats().PatternsLearned; got != 1 {
		t.Errorf("PatternsLearned = %d, want 1 (generalized prefix)", got)
	}

	ss := findScope(t, a, scopeTestKey)
	if ss.HashLearnAttempts != 1 || ss.HashLearnRejected != 1 || ss.HashLearnInserted != 0 {
		t.Errorf("hash learn attempts=%d rejected=%d inserted=%d, want 1, 1, 0",
			ss.HashLearnAttempts, ss.HashLearnRejected, ss.HashLearnInserted)
	}
}

// TestScopeStats_HashLearnSitesAndSum: each of the three learnFromVerdict
// LearnHash sites (allow/suppress, malicious, alert) counts an attempt, and
// the outcome buckets always sum to attempts.
func TestScopeStats_HashLearnSitesAndSum(t *testing.T) {
	cases := []struct {
		name    string
		source  string
		verdict string
	}{
		{"allow", "svc-allow", `{"classification":"safe","confidence":0.75,"reason":"ok","action":"allow"}`},
		{"malicious", "svc-malicious", `{"classification":"malicious","confidence":0.95,"reason":"credential dump","action":"malicious"}`},
		{"alert", "svc-alert", `{"classification":"suspicious","confidence":0.80,"reason":"odd request","action":"alert"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := llmStub(t, tc.verdict)
			a, _ := newScopeTestAnalyzer(t, server.URL, newCountingScheduler(4))

			// Non-HTTP line so the malicious clamp does not rewrite the action.
			line := "backup job transferred 12 files to offsite storage " + tc.name
			a.Analyze(context.Background(), testEvent(tc.source, line))

			ss := findScope(t, a, "docker:"+tc.source)
			if ss.HashLearnAttempts != 1 {
				t.Errorf("hash_learn_attempts = %d, want 1", ss.HashLearnAttempts)
			}
			sum := ss.HashLearnInserted + ss.HashLearnDuplicates + ss.HashLearnRejected
			if sum != ss.HashLearnAttempts {
				t.Errorf("outcome buckets sum to %d, want attempts %d", sum, ss.HashLearnAttempts)
			}
			if ss.HashLearnInserted != 1 {
				t.Errorf("hash_learn_inserted = %d, want 1", ss.HashLearnInserted)
			}
		})
	}
}
