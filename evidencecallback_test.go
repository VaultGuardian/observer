// evidencecallback_test.go — Session B behavior tests for the T2 reclassify
// router in makeEvidenceCheckCallback: singleflight coalescing, the two-lane
// durable cache, the ExpectedEndpoint ordering pin, and the slow-response
// transport-downgrade gate.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
	"github.com/vaultguardian/observer/internal/watcher"
)

// stubEvidenceCollector reuses fakeCollector's inert methods but returns a
// configurable Evidence from Lookup.
type stubEvidenceCollector struct {
	fakeCollector
	ev *rec.Evidence
}

func (c *stubEvidenceCollector) Lookup(rec.LookupRequest) *rec.Evidence { return c.ev }

// reclassLLMStub is an httptest server that answers the reclassify chat
// endpoint with a fixed verdict JSON, counting calls and capturing request
// bodies so tests can assert on prompt content.
type reclassLLMStub struct {
	server  *httptest.Server
	calls   atomic.Int64
	delay   time.Duration
	verdict string // JSON content the "model" returns

	mu     sync.Mutex
	bodies []string
}

func newReclassLLMStub(t *testing.T, verdictJSON string, delay time.Duration) *reclassLLMStub {
	t.Helper()
	s := &reclassLLMStub{verdict: verdictJSON, delay: delay}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.bodies = append(s.bodies, string(body))
		s.mu.Unlock()
		if s.delay > 0 {
			// Hold the call open so a concurrent burst piles into one flight.
			time.Sleep(s.delay)
		}
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": s.verdict}},
			},
			"usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *reclassLLMStub) promptContains(substr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.bodies {
		if strings.Contains(b, substr) {
			return true
		}
	}
	return false
}

// Verdict JSONs. Downgraded/Escalated are recomputed client-side from
// originalClassification vs classification, so the snapshot's Classification
// chooses the lane direction together with these.
const (
	verdictGenericDowngrade = `{"classification":"recon_failed","confidence":0.9,"reason":"generic framework page","action":"suppress","generic_response":true}`
	verdictHedgedDowngrade  = `{"classification":"recon_failed","confidence":0.9,"reason":"no breach evident","action":"suppress","generic_response":false}`
	verdictEscalation       = `{"classification":"malicious","confidence":0.95,"reason":"credential dump in body","action":"malicious","generic_response":false}`
)

// callbackHarness bundles everything makeEvidenceCheckCallback needs.
type callbackHarness struct {
	cb        coordinator.EvidenceCheckFunc
	stub      *reclassLLMStub
	cache     *reclassCache
	scheduler *LLMScheduler
	db        *store.Store
	tracker   *coordinator.ExpectedEndpointTracker
}

func newCallbackHarness(t *testing.T, ev *rec.Evidence, verdictJSON string, delay time.Duration, cfgMut func(*Config)) *callbackHarness {
	t.Helper()
	stub := newReclassLLMStub(t, verdictJSON, delay)
	db, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := Config{LLMModel: "test-model", Tier2Effort: "medium", SlowResponseThresholdMs: 3000}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	h := &callbackHarness{
		stub:      stub,
		cache:     newReclassCache(),
		scheduler: NewLLMScheduler(1),
		db:        db,
		tracker:   coordinator.NewExpectedEndpointTracker(0),
	}
	h.cb = makeEvidenceCheckCallback(
		&stubEvidenceCollector{ev: ev},
		llm.NewClient(stub.server.URL, "test-model", "", "low", "medium"),
		h.cache,
		db,
		cfg,
		h.scheduler,
		context.Background(),
		h.tracker,
	)
	return h
}

func (h *callbackHarness) decisionRows(t *testing.T) []store.LLMDecision {
	t.Helper()
	rows, err := h.db.ListLLMDecisions(context.Background(), store.LLMDecisionFilter{Tier: "reclassify"})
	if err != nil {
		t.Fatalf("ListLLMDecisions: %v", err)
	}
	return rows
}

func reclassSnapshot(eventID, classification string) *coordinator.PendingAlert {
	return &coordinator.PendingAlert{
		EventID:        eventID,
		Key:            "example.com|GET|/x|200",
		ScopeKey:       "docker:web",
		SourceType:     "docker",
		SourceName:     "web",
		Reason:         "attack payload detected",
		Line:           `1.2.3.4 - - [t] "GET /x HTTP/1.1" 200 100`,
		NormalizedLine: "example.com GET /x HTTP/1.1 200",
		Verdict:        "malicious",
		Classification: classification,
		Host:           "example.com",
		StatusCode:     200,
		HTTPMethod:     "GET",
		HTTPPath:       "/x",
		Timestamp:      time.Now(),
	}
}

func reclassEvidence(status int, body string, redactions int, dur time.Duration, latencySource string) *rec.Evidence {
	return &rec.Evidence{
		Transport: &rec.TransportEvidence{
			StatusCode:      status,
			ContentType:     "text/html",
			ContentLength:   int64(len(body)),
			BodyPreviewHash: "raw-transport-hash",
			CaptureMode:     "test",
			RequestDuration: dur,
			LatencySource:   latencySource,
		},
		Disclosure:      &rec.DisclosureAnalysis{SensitiveRedactions: redactions},
		SafeBodyPreview: body,
		CandidateCount:  1,
	}
}

// TestEvidenceCallback_CoalescesConcurrentSameBody: N concurrent reclassify
// invocations with the same redacted body shape produce exactly one LLM call,
// one scheduler acquire, and one llm_decisions row (the leader's); every
// decision carries the shared verdict, and only followers carry the
// "coalesced with <leaderEventID>" note.
func TestEvidenceCallback_CoalescesConcurrentSameBody(t *testing.T) {
	const burst = 10
	ev := reclassEvidence(200, "<html>minio console shell</html>", 0, 0, "")
	h := newCallbackHarness(t, ev, verdictGenericDowngrade, 300*time.Millisecond, nil)

	decisions := make([]coordinator.EvidenceDecision, burst)
	eventIDs := make([]string, burst)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := 0; i < burst; i++ {
		eventIDs[i] = fmt.Sprintf("evt_burst_%d", i)
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait() // release together so the burst shares one flight
			decisions[i] = h.cb(reclassSnapshot(eventIDs[i], "malicious"))
		}(i)
	}
	start.Done()
	done.Wait()

	if got := h.stub.calls.Load(); got != 1 {
		t.Errorf("LLM called %d times, want 1 (burst not coalesced)", got)
	}
	if total, _ := h.scheduler.Stats(); total != 1 {
		t.Errorf("scheduler acquired %d slots, want 1 (only the leader takes a slot)", total)
	}

	rows := h.decisionRows(t)
	if len(rows) != 1 {
		t.Fatalf("llm_decisions rows = %d, want 1 (followers must not write audit rows)", len(rows))
	}
	leaderID := rows[0].EventID

	followers := 0
	for i, d := range decisions {
		if !d.Downgraded {
			t.Errorf("decision[%d] not downgraded — verdict not shared", i)
		}
		note := "coalesced with " + leaderID
		isFollower := eventIDs[i] != leaderID
		if isFollower {
			followers++
			if !strings.Contains(d.Reason, note) {
				t.Errorf("follower decision[%d] reason %q missing %q", i, d.Reason, note)
			}
			if !strings.Contains(d.EvidenceJournal, note) {
				t.Errorf("follower decision[%d] journal missing %q", i, note)
			}
		} else if strings.Contains(d.Reason, "coalesced with") {
			t.Errorf("leader decision[%d] reason %q carries a coalesced note", i, d.Reason)
		}
	}
	if followers != burst-1 {
		t.Errorf("followers = %d, want %d", followers, burst-1)
	}
}

// TestEvidenceCallback_LaneA_DurableCache: a downgrade with positive
// boilerplate proof (generic_response=true, zero sensitive redactions) is
// durably cached — the second sequential identical body never reaches the LLM.
func TestEvidenceCallback_LaneA_DurableCache(t *testing.T) {
	ev := reclassEvidence(200, "<html>welcome page</html>", 0, 0, "")
	h := newCallbackHarness(t, ev, verdictGenericDowngrade, 0, nil)

	first := h.cb(reclassSnapshot("evt_a1", "malicious"))
	second := h.cb(reclassSnapshot("evt_a2", "malicious"))

	if !first.Downgraded || !second.Downgraded {
		t.Errorf("decisions not downgraded: first=%v second=%v", first.Downgraded, second.Downgraded)
	}
	if got := h.stub.calls.Load(); got != 1 {
		t.Errorf("LLM called %d times, want 1 (Lane A entry must serve the repeat)", got)
	}
	if rows := h.decisionRows(t); len(rows) != 1 {
		t.Errorf("llm_decisions rows = %d, want 1", len(rows))
	}
}

// TestEvidenceCallback_LaneB_EscalationNotCached: escalations are no longer
// durably replayed — a second sequential identical body gets a fresh LLM call.
func TestEvidenceCallback_LaneB_EscalationNotCached(t *testing.T) {
	ev := reclassEvidence(200, `{"AWS_KEY":"[REDACTED]"}`, 1, 0, "")
	h := newCallbackHarness(t, ev, verdictEscalation, 0, nil)

	first := h.cb(reclassSnapshot("evt_b1", "suspicious"))
	second := h.cb(reclassSnapshot("evt_b2", "suspicious"))

	if !first.Escalated || !second.Escalated {
		t.Errorf("decisions not escalated: first=%v second=%v", first.Escalated, second.Escalated)
	}
	if got := h.stub.calls.Load(); got != 2 {
		t.Errorf("LLM called %d times, want 2 (escalations must not be durably cached)", got)
	}
	if rows := h.decisionRows(t); len(rows) != 2 {
		t.Errorf("llm_decisions rows = %d, want 2", len(rows))
	}
}

// TestEvidenceCallback_LaneB_NotCachedWithoutProof: downgrades without
// positive boilerplate proof — sensitive redactions present, or the model
// declined to assert generic_response — are not durably cached.
func TestEvidenceCallback_LaneB_NotCachedWithoutProof(t *testing.T) {
	cases := []struct {
		name       string
		verdict    string
		redactions int
	}{
		{"sensitive_redactions", verdictGenericDowngrade, 3},
		{"not_generic", verdictHedgedDowngrade, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := reclassEvidence(200, "<html>some page</html>", tc.redactions, 0, "")
			h := newCallbackHarness(t, ev, tc.verdict, 0, nil)

			h.cb(reclassSnapshot("evt_c1", "malicious"))
			h.cb(reclassSnapshot("evt_c2", "malicious"))

			if got := h.stub.calls.Load(); got != 2 {
				t.Errorf("LLM called %d times, want 2 (no durable entry without boilerplate proof)", got)
			}
		})
	}
}

// TestEvidenceCallback_ExpectedEndpointShortCircuit pins the load-bearing
// ordering: an operator-confirmed shape match short-circuits AFTER redaction
// but BEFORE the reclass cache, the singleflight group, and the LLM — zero
// LLM calls, zero scheduler acquires, zero cache entries, zero audit rows.
func TestEvidenceCallback_ExpectedEndpointShortCircuit(t *testing.T) {
	body := `{"token":"[REDACTED]"}`
	ev := reclassEvidence(200, body, 1, 0, "")
	h := newCallbackHarness(t, ev, verdictEscalation, 0, nil)

	bodyHash := rec.HashBody([]byte(body))
	h.tracker.SeedVerified(
		[]coordinator.ExpectedEndpointFingerprint{{
			Host: "example.com", Method: "GET", Path: "/x", Status: 200, BodyPreviewHash: bodyHash,
		}},
		[]string{"operator-approved token endpoint"},
	)

	d := h.cb(reclassSnapshot("evt_ee1", "malicious"))

	if !d.Downgraded {
		t.Errorf("ExpectedEndpoint match did not downgrade")
	}
	if !strings.Contains(d.Reason, "operator-approved token endpoint") {
		t.Errorf("decision reason %q does not carry the operator reason", d.Reason)
	}
	if got := h.stub.calls.Load(); got != 0 {
		t.Errorf("LLM called %d times, want 0 (operator truth must pre-empt the LLM)", got)
	}
	if total, _ := h.scheduler.Stats(); total != 0 {
		t.Errorf("scheduler acquired %d slots, want 0", total)
	}
	if _, ok := h.cache.get(bodyHash); ok {
		t.Errorf("reclass cache touched by ExpectedEndpoint short-circuit")
	}
	if rows := h.decisionRows(t); len(rows) != 0 {
		t.Errorf("llm_decisions rows = %d, want 0", len(rows))
	}
}

// TestEvidenceCallback_ClampedEventEscalates: end-to-end router → coordinator
// → evidence callback for a T1-clamped event. routeAlert must carry the
// APPLIED classification ("suspicious") on the pending alert — not the
// immutable original "malicious" — otherwise ReclassifyWithEvidence receives
// originalClassification="malicious" and isEscalation("malicious",
// "malicious") is false: an evidence-confirmed breach on a clamped event
// could never escalate or notify.
func TestEvidenceCallback_ClampedEventEscalates(t *testing.T) {
	// Disclosure-bearing evidence + escalation verdict from T2.
	ev := reclassEvidence(200, `{"AWS_KEY":"[REDACTED]"}`, 2, 0, "")
	h := newCallbackHarness(t, ev, verdictEscalation, 0, nil)

	type recorded struct {
		snap     coordinator.PendingAlert
		decision coordinator.EvidenceDecision
	}
	recCh := make(chan recorded, 4)
	recordingCheck := func(p *coordinator.PendingAlert) coordinator.EvidenceDecision {
		d := h.cb(p)
		recCh <- recorded{*p, d}
		return d
	}
	coord := coordinator.New(
		context.Background(),
		coordinator.Config{},
		func(coordinator.FinalAlert) {},
		recordingCheck,
		func(coordinator.VerifyRequest) *coordinator.VerifyResult { return nil },
		coordinator.NewSelfSuppressor(),
	)
	router := &resultRouter{
		cfg:              Config{},
		collector:        &stubEvidenceCollector{ev: ev},
		alertCoordinator: coord,
	}

	evt := httpAlertEvent()
	result := analyzer.AnalysisResult{
		Event:             evt,
		Verdict:           patternstore.VerdictAlert, // applied (clamped)
		Source:            "llm",
		Reason:            "SQL injection payload in request",
		LLMClassification: "malicious", // immutable original
		LLMConfidence:     0.95,
		LLMClampedToAlert: true,
	}
	router.routeAlert(evt, &result, watcher.LogLine{})

	// Drive the evidence check synchronously via the VIP push path.
	_, nPath, _, _ := parseNormalizedLine(evt.NormalizedLine)
	key := fmt.Sprintf("example.com|GET|%s|200", canonicalPath(nPath))
	coord.TryResolveVIP(key)

	select {
	case rec := <-recCh:
		if rec.snap.Classification != "suspicious" {
			t.Errorf("pending alert Classification = %q, want \"suspicious\" (applied state; original belongs to the audit row)", rec.snap.Classification)
		}
		if !rec.decision.Escalated {
			t.Errorf("EvidenceDecision.Escalated = false, want true — clamped event cannot escalate on evidence")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("evidence check never ran — TryResolveVIP key mismatch? key=%q", key)
	}
}

// TestEvidenceCallback_ClampLeakBackstop: even if a pending alert arrives
// with the immutable original "malicious" as Classification while routing at
// verdict "alert" (the clamp-leak shape), the callback normalizes it to the
// applied state so escalation math still works.
func TestEvidenceCallback_ClampLeakBackstop(t *testing.T) {
	ev := reclassEvidence(200, `{"AWS_KEY":"[REDACTED]"}`, 2, 0, "")
	h := newCallbackHarness(t, ev, verdictEscalation, 0, nil)

	snap := reclassSnapshot("evt_leak", "malicious") // original leaked through
	snap.Verdict = "alert"                           // but routed clamped

	d := h.cb(snap)
	if !d.Escalated {
		t.Errorf("EvidenceDecision.Escalated = false, want true (backstop must normalize leaked original)")
	}
}

// TestEvidenceCallback_SlowResponseGate: a wire-paired request duration at or
// above the threshold withholds the Path-1 transport downgrade and routes the
// event to the LLM with the latency in the prompt; everything else downgrades
// exactly as before.
func TestEvidenceCallback_SlowResponseGate(t *testing.T) {
	cases := []struct {
		name          string
		dur           time.Duration
		latencySource string
		thresholdMs   int // 0 = leave default (3000)
		wantTransport bool
		wantLLMCalls  int64
		wantPrompt    string
	}{
		{"slow_wire_pair_withheld", 5 * time.Second, "wire_pair", 0, false, 1, "Observed server processing time: 5000 ms"},
		{"fast_wire_pair_downgrades", 50 * time.Millisecond, "wire_pair", 0, true, 0, ""},
		{"absent_duration_downgrades", 0, "", 0, true, 0, ""},
		{"gate_disabled_downgrades", 5 * time.Second, "wire_pair", -1, true, 0, ""},
		{"non_wire_pair_downgrades", 5 * time.Second, "log_estimate", 0, true, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := reclassEvidence(404, "<html>custom not found</html>", 0, tc.dur, tc.latencySource)
			var mut func(*Config)
			if tc.thresholdMs != 0 {
				mut = func(c *Config) { c.SlowResponseThresholdMs = 0 }
			}
			h := newCallbackHarness(t, ev, verdictEscalation, 0, mut)

			d := h.cb(reclassSnapshot("evt_gate", "malicious"))

			gotTransport := d.Downgraded && strings.Contains(d.Reason, "Transport evidence confirms attack failed")
			if gotTransport != tc.wantTransport {
				t.Errorf("transport downgrade = %v (reason=%q), want %v", gotTransport, d.Reason, tc.wantTransport)
			}
			if got := h.stub.calls.Load(); got != tc.wantLLMCalls {
				t.Errorf("LLM called %d times, want %d", got, tc.wantLLMCalls)
			}
			if tc.wantPrompt != "" && !h.stub.promptContains(tc.wantPrompt) {
				t.Errorf("LLM prompt missing %q", tc.wantPrompt)
			}
		})
	}
}
