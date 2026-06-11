package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/patternstore"
)

// newMaliciousLLMStub returns an httptest server whose T1 verdict is always
// action=malicious at high confidence, plus a counter of calls received.
func newMaliciousLLMStub(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var llmCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls.Add(1)
		verdictJSON := `{"classification":"malicious","confidence":0.95,"reason":"SQL injection payload in request","action":"malicious"}`
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
	return server, &llmCalls
}

func newClampTestAnalyzer(t *testing.T, serverURL string) (*Analyzer, *patternstore.Store) {
	t.Helper()
	patterns, err := patternstore.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	llmClient := llm.NewClient(serverURL, "test-model", "", "low", "medium")
	return New(normalizer.NewRegistry(), patterns, llmClient, newCountingScheduler(4)), patterns
}

// TestT1Clamp_HTTPMaliciousCappedToAlert: a T1 LLM "malicious" on an event
// with HTTP identity is applied as alert (outcome claims require response
// evidence), while the recorded verdict keeps the model's original action,
// the clamp counter increments, and the learned hash lands in the ALERT
// bucket — not malicious — so future identical lines route as alert too.
func TestT1Clamp_HTTPMaliciousCappedToAlert(t *testing.T) {
	server, llmCalls := newMaliciousLLMStub(t)
	a, patterns := newClampTestAnalyzer(t, server.URL)

	evt := &event.Event{
		ID:          event.NewID(),
		SourceType:  "docker",
		SourceName:  "captain-nginx",
		Line:        "shop.example.com GET /products?id=1+UNION+SELECT+password,secret+FROM+users HTTP/1.1 200",
		Stream:      "stdout",
		Timestamp:   time.Now(),
		ProcessedAt: time.Now(),
	}
	r := a.Analyze(context.Background(), evt)

	if got := llmCalls.Load(); got != 1 {
		t.Fatalf("LLM called %d times, want 1 (event did not reach the LLM path)", got)
	}
	if r.Source != "llm" {
		t.Fatalf("result source = %q, want \"llm\"", r.Source)
	}
	if r.Verdict != patternstore.VerdictAlert {
		t.Errorf("applied verdict = %q, want %q (clamp did not fire)", r.Verdict, patternstore.VerdictAlert)
	}
	if !r.LLMClampedToAlert {
		t.Errorf("LLMClampedToAlert = false, want true")
	}
	if r.LLMVerdict == nil || r.LLMVerdict.Action != "malicious" {
		t.Errorf("LLMVerdict.Action mutated: got %+v, want original \"malicious\"", r.LLMVerdict)
	}
	if got := a.GetStats().T1MaliciousClamped; got != 1 {
		t.Errorf("T1MaliciousClamped = %d, want 1", got)
	}

	// Learning followed the clamped action: alert bucket, not malicious.
	m := patterns.Match(evt.ScopeKey(), evt.Hash, evt.NormalizedLine)
	if m == nil {
		t.Fatalf("hash was not learned at all")
	}
	if m.Verdict != patternstore.VerdictAlert {
		t.Errorf("learned bucket = %q, want %q — pattern tier would resurrect malicious-without-evidence", m.Verdict, patternstore.VerdictAlert)
	}
}

// TestT1Clamp_NonHTTPMaliciousUnchanged: events without HTTP identity are
// untouched — malicious stays malicious and learns into the malicious bucket.
func TestT1Clamp_NonHTTPMaliciousUnchanged(t *testing.T) {
	server, llmCalls := newMaliciousLLMStub(t)
	a, patterns := newClampTestAnalyzer(t, server.URL)

	evt := &event.Event{
		ID:          event.NewID(),
		SourceType:  "docker",
		SourceName:  "app-backend",
		Line:        "outbound beacon established to c2.evil.example, interval thirty seconds",
		Stream:      "stderr",
		Timestamp:   time.Now(),
		ProcessedAt: time.Now(),
	}
	r := a.Analyze(context.Background(), evt)

	if got := llmCalls.Load(); got != 1 {
		t.Fatalf("LLM called %d times, want 1 (event did not reach the LLM path)", got)
	}
	if r.Verdict != patternstore.VerdictMalicious {
		t.Errorf("applied verdict = %q, want %q (non-HTTP event must not be clamped)", r.Verdict, patternstore.VerdictMalicious)
	}
	if r.LLMClampedToAlert {
		t.Errorf("LLMClampedToAlert = true, want false for non-HTTP event")
	}
	if got := a.GetStats().T1MaliciousClamped; got != 0 {
		t.Errorf("T1MaliciousClamped = %d, want 0", got)
	}

	m := patterns.Match(evt.ScopeKey(), evt.Hash, evt.NormalizedLine)
	if m == nil || m.Verdict != patternstore.VerdictMalicious {
		t.Errorf("learned bucket = %+v, want malicious hash", m)
	}
}

// TestT1Clamp_MorganHTTPMaliciousCappedToAlert: Format 4 (Express/morgan)
// lines are HTTP to the clamp, same as Formats 1-3. Before reHTTPMorgan was
// added, this literal captain-captain line was HTTP to the router (httpparse
// reMorganHTTP) but invisible to parseHTTPIdentity — an LLM-malicious morgan
// line learned into the malicious bucket and routed at malicious severity
// with no evidence.
func TestT1Clamp_MorganHTTPMaliciousCappedToAlert(t *testing.T) {
	server, llmCalls := newMaliciousLLMStub(t)
	a, patterns := newClampTestAnalyzer(t, server.URL)

	evt := &event.Event{
		ID:          event.NewID(),
		SourceType:  "docker",
		SourceName:  "captain-captain",
		Line:        "GET /api/keys 200 0.563 ms - 83",
		Stream:      "stdout",
		Timestamp:   time.Now(),
		ProcessedAt: time.Now(),
	}
	r := a.Analyze(context.Background(), evt)

	if got := llmCalls.Load(); got != 1 {
		t.Fatalf("LLM called %d times, want 1 (morgan line did not reach the LLM path)", got)
	}
	if r.Verdict != patternstore.VerdictAlert {
		t.Errorf("applied verdict = %q, want %q (clamp blind to morgan format)", r.Verdict, patternstore.VerdictAlert)
	}
	if !r.LLMClampedToAlert {
		t.Errorf("LLMClampedToAlert = false, want true")
	}
	if got := a.GetStats().T1MaliciousClamped; got != 1 {
		t.Errorf("T1MaliciousClamped = %d, want 1", got)
	}
	m := patterns.Match(evt.ScopeKey(), evt.Hash, evt.NormalizedLine)
	if m == nil || m.Verdict != patternstore.VerdictAlert {
		t.Errorf("learned bucket = %+v, want alert hash", m)
	}
}

// TestMorganFailedProbe_CleanPathSuppressed: with Format 4 in
// parseHTTPIdentity, isFailedProbe now sees morgan lines too — a clean-path
// morgan 404 is deterministically suppressed without burning an LLM call
// (accepted side effect of parser parity, Jun 2026).
func TestMorganFailedProbe_CleanPathSuppressed(t *testing.T) {
	server, llmCalls := newMaliciousLLMStub(t)
	a, _ := newClampTestAnalyzer(t, server.URL)

	evt := &event.Event{
		ID:          event.NewID(),
		SourceType:  "docker",
		SourceName:  "captain-captain",
		Line:        "GET /api/unknown 404 1.2 ms - 14",
		Stream:      "stdout",
		Timestamp:   time.Now(),
		ProcessedAt: time.Now(),
	}
	r := a.Analyze(context.Background(), evt)

	if r.Verdict != patternstore.VerdictSuppress || r.Source != "noise_filter" {
		t.Errorf("verdict=%q source=%q, want suppress via noise_filter (failed-probe gate)", r.Verdict, r.Source)
	}
	if got := llmCalls.Load(); got != 0 {
		t.Errorf("LLM called %d times, want 0 (deterministic suppression)", got)
	}
}

// TestMorganFailedProbe_AttackShapedReachesLLM: the literal review line
// "GET /api/users?id=1%27%20OR%20SLEEP(5)-- 404 5001.0 ms - 0" is NOT
// deterministically suppressed and proceeds to the LLM tier — but NOT via an
// attack-indicator escape (the v0.47 policy override removed those:
// isFailedProbe is pure status-based). The mechanism is normalization: the
// generic normalizer collapses the 4-digit duration ("5001.0 ms" →
// "<NUM>.0 ms"), which breaks the strict Format 4 tail on the NORMALIZED
// line that isFailedProbe parses. The raw line still matches Format 4, so
// the clamp sees HTTP identity and caps the LLM's malicious to alert.
//
// The subtest pins the policy boundary: the same attack-shaped probe with a
// 3-digit duration survives normalization intact and IS suppressed — failed
// = suppress, regardless of payload (v0.47, reconfirmed Jun 2026).
func TestMorganFailedProbe_AttackShapedReachesLLM(t *testing.T) {
	server, llmCalls := newMaliciousLLMStub(t)
	a, _ := newClampTestAnalyzer(t, server.URL)

	evt := &event.Event{
		ID:          event.NewID(),
		SourceType:  "docker",
		SourceName:  "captain-captain",
		Line:        "GET /api/users?id=1%27%20OR%20SLEEP(5)-- 404 5001.0 ms - 0",
		Stream:      "stdout",
		Timestamp:   time.Now(),
		ProcessedAt: time.Now(),
	}
	r := a.Analyze(context.Background(), evt)

	if got := llmCalls.Load(); got != 1 {
		t.Fatalf("LLM called %d times, want 1 (4-digit duration breaks normalized Format 4 → no deterministic suppression)", got)
	}
	if r.Source != "llm" {
		t.Errorf("source = %q, want \"llm\"", r.Source)
	}
	// Raw line carries HTTP identity → T1 malicious is clamped to alert.
	if r.Verdict != patternstore.VerdictAlert || !r.LLMClampedToAlert {
		t.Errorf("verdict=%q clamped=%v, want alert/true", r.Verdict, r.LLMClampedToAlert)
	}

	t.Run("three_digit_duration_is_suppressed", func(t *testing.T) {
		server2, llmCalls2 := newMaliciousLLMStub(t)
		a2, _ := newClampTestAnalyzer(t, server2.URL)
		evt2 := &event.Event{
			ID:          event.NewID(),
			SourceType:  "docker",
			SourceName:  "captain-captain",
			Line:        "GET /api/users?id=1%27%20OR%20SLEEP(5)-- 404 500.0 ms - 0",
			Stream:      "stdout",
			Timestamp:   time.Now(),
			ProcessedAt: time.Now(),
		}
		r2 := a2.Analyze(context.Background(), evt2)
		if r2.Verdict != patternstore.VerdictSuppress || r2.Source != "noise_filter" {
			t.Errorf("verdict=%q source=%q, want suppress via noise_filter (pure status-based policy)", r2.Verdict, r2.Source)
		}
		if got := llmCalls2.Load(); got != 0 {
			t.Errorf("LLM called %d times, want 0", got)
		}
	})
}

// TestT1Clamp_PatternTierMaliciousUnchanged: deterministic-tier verdicts are
// untouched — a pre-learned malicious hash still fires as malicious for an
// HTTP event, with no LLM call and no clamp.
func TestT1Clamp_PatternTierMaliciousUnchanged(t *testing.T) {
	server, llmCalls := newMaliciousLLMStub(t)
	a, patterns := newClampTestAnalyzer(t, server.URL)

	const line = "shop.example.com GET /admin/export?all=true HTTP/1.1 200"

	// Normalize a twin event to obtain the hash, then pre-learn it as
	// malicious directly (simulating an existing pattern-store entry).
	seed := &event.Event{
		ID:         event.NewID(),
		SourceType: "docker",
		SourceName: "captain-nginx",
		Line:       line,
		Stream:     "stdout",
		Timestamp:  time.Now(),
	}
	normalizer.NewRegistry().NormalizeEvent(seed)
	patterns.LearnHash(seed.ScopeKey(), patternstore.VerdictMalicious, seed.Hash, "pre-learned", seed.NormalizedLine, "evt_origin")

	evt := &event.Event{
		ID:          event.NewID(),
		SourceType:  "docker",
		SourceName:  "captain-nginx",
		Line:        line,
		Stream:      "stdout",
		Timestamp:   time.Now(),
		ProcessedAt: time.Now(),
	}
	r := a.Analyze(context.Background(), evt)

	if got := llmCalls.Load(); got != 0 {
		t.Fatalf("LLM called %d times, want 0 (pattern hit expected)", got)
	}
	if r.Verdict != patternstore.VerdictMalicious {
		t.Errorf("applied verdict = %q, want %q (pattern tier must be untouched)", r.Verdict, patternstore.VerdictMalicious)
	}
	if r.LLMClampedToAlert {
		t.Errorf("LLMClampedToAlert = true, want false for pattern-tier hit")
	}
	if got := a.GetStats().T1MaliciousClamped; got != 0 {
		t.Errorf("T1MaliciousClamped = %d, want 0", got)
	}
}
