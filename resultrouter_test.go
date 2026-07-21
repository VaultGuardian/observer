// resultrouter_test.go
package main

import (
	"context"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
	"github.com/vaultguardian/observer/internal/watcher"
)

// fakeCollector is a minimal EvidenceCollector that records PinVIP calls so
// tests can assert evidence-protection wiring without a live sniffer. Lookup
// returns lookupEv when set (and counts calls) so tests can drive the status
// shortcut's disclosure override.
type fakeCollector struct {
	pinned   []string // eventIDs passed to PinVIP
	lookups  int
	lookupEv *rec.Evidence
}

func (f *fakeCollector) Start(context.Context) error { return nil }
func (f *fakeCollector) Lookup(rec.LookupRequest) *rec.Evidence {
	f.lookups++
	if f.lookupEv != nil {
		return f.lookupEv
	}
	return &rec.Evidence{}
}
func (f *fakeCollector) Enabled() bool { return true }
func (f *fakeCollector) Stats() rec.RECStats                    { return rec.RECStats{} }
func (f *fakeCollector) Coverage() rec.RECCoverage              { return rec.RECCoverage{Mode: "disabled"} }
func (f *fakeCollector) PrePin(string, rec.LookupRequest)       {}
func (f *fakeCollector) SetVIPCallback(func(string))            {}
func (f *fakeCollector) PinVIP(eventID, _ string, _ rec.LookupRequest) {
	f.pinned = append(f.pinned, eventID)
}

// newTestRouter builds a resultRouter wired to a fake collector and a real
// (but inert) coordinator. db/dispatch are nil — the HTTP alert path under test
// does not touch them.
func newTestRouter(t *testing.T) (*resultRouter, *fakeCollector) {
	t.Helper()
	fc := &fakeCollector{}
	coord := coordinator.New(
		context.Background(),
		coordinator.Config{},
		func(coordinator.FinalAlert) {},
		func(*coordinator.PendingAlert) coordinator.EvidenceDecision { return coordinator.EvidenceDecision{} },
		func(coordinator.VerifyRequest) *coordinator.VerifyResult { return nil },
		coordinator.NewSelfSuppressor(),
	)
	return &resultRouter{
		cfg:              Config{},
		collector:        fc,
		alertCoordinator: coord,
	}, fc
}

// httpAlertEvent returns an event whose lines parse to a real HTTP identity on
// a domain vhost with status 200 — so routeAlert reaches the PinVIP block
// rather than any recon/edge short-circuit.
func httpAlertEvent() *event.Event {
	return &event.Event{
		ID:             "evt_test_1",
		SourceType:     "docker",
		SourceName:     "captain-captain",
		NormalizedLine: "example.com GET /api/keys HTTP/1.1 200",
		Line:           `1.2.3.4 - - [t] "GET /api/keys HTTP/1.1" 200 83`,
		Hash:           "deadbeef",
		Timestamp:      time.Now(),
	}
}

// Fix 3: suspicious (VerdictAlert) cache-hits must also pin VIP evidence, not
// just malicious ones. Before the fix, PinVIP fired only on VerdictMalicious,
// so suspicious cache-hits (which skip the LLM PrePin path) got no protected
// evidence.
func TestRouteAlertPinsVIP(t *testing.T) {
	cases := []struct {
		name    string
		verdict patternstore.Verdict
	}{
		{"malicious_still_pins", patternstore.VerdictMalicious},
		{"alert_now_pins", patternstore.VerdictAlert},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, fc := newTestRouter(t)
			evt := httpAlertEvent()
			result := &analyzer.AnalysisResult{
				Verdict: tc.verdict,
				Source:  "pattern", // cache hit (not "llm")
				Reason:  "test",
			}
			r.routeAlert(evt, result, watcher.LogLine{})

			if len(fc.pinned) != 1 || fc.pinned[0] != evt.ID {
				t.Fatalf("verdict %s: PinVIP calls = %v; want exactly [%s]", tc.verdict, fc.pinned, evt.ID)
			}
		})
	}
}

// http404AlertEvent parses to a rejecting status so routeAlert reaches the
// cache-hit status shortcut.
func http404AlertEvent() *event.Event {
	return &event.Event{
		ID:             "evt_test_404",
		SourceType:     "docker",
		SourceName:     "captain-captain",
		NormalizedLine: "example.com GET /backup.env HTTP/1.1 404",
		Line:           `1.2.3.4 - - [t] "GET /backup.env HTTP/1.1" 404 83`,
		Hash:           "deadbeef404",
		Timestamp:      time.Now(),
	}
}

// dotenvDisclosureEvidence is REC evidence whose Disclosure carries a
// deterministically disclosing format — the tier-1 predicate must be true.
func dotenvDisclosureEvidence() *rec.Evidence {
	return &rec.Evidence{
		Status:                rec.EvidenceAvailableHighConfidence,
		CorrelationConfidence: rec.ConfidenceHigh,
		Transport: &rec.TransportEvidence{
			StatusCode:      404,
			ContentType:     "text/plain",
			BodyPreviewHash: "hash404",
		},
		Disclosure: &rec.DisclosureAnalysis{
			Format:              rec.FormatDotenv,
			SensitiveRedactions: 2,
			DisclosureSummary:   "DOTENV/CONFIG STRUCTURE DETECTED",
		},
		SafeBodyPreview: "DB_PASSWORD=[REDACTED]\nAPP_KEY=[REDACTED]",
		CandidateCount:  1,
	}
}

// TestRouteAlertStatusShortcutOverriddenByDisclosure: a cache-hit attack on a
// 404 whose REC lookup shows a deterministically disclosing body must NOT be
// short-circuited to recon — it falls through to the coordinator (PinVIP +
// investigation), and writes no shortcut finding (r.db is nil here: a write
// attempt would panic the test).
func TestRouteAlertStatusShortcutOverriddenByDisclosure(t *testing.T) {
	r, fc := newTestRouter(t)
	fc.lookupEv = dotenvDisclosureEvidence()

	evt := http404AlertEvent()
	result := &analyzer.AnalysisResult{
		Verdict: patternstore.VerdictMalicious,
		Source:  "cache",
		Reason:  "dotenv probe pattern",
	}
	r.routeAlert(evt, result, watcher.LogLine{})

	if fc.lookups != 1 {
		t.Errorf("REC lookups = %d, want 1", fc.lookups)
	}
	if len(fc.pinned) != 1 || fc.pinned[0] != evt.ID {
		t.Errorf("PinVIP calls = %v, want [%s] (event must reach the coordinator path)", fc.pinned, evt.ID)
	}
	if pending, _ := r.alertCoordinator.Stats(); pending != 1 {
		t.Errorf("pending investigations = %d, want 1", pending)
	}
}

// TestRouteAlertStatusShortcutUnchangedWithoutDisclosure: without a
// disclosing body — plain empty evidence, or the disabled-collector shape the
// noOp collector returns — the shortcut behaves exactly as before: recon
// finding, no coordinator, no PinVIP.
func TestRouteAlertStatusShortcutUnchangedWithoutDisclosure(t *testing.T) {
	cases := []struct {
		name string
		ev   *rec.Evidence
	}{
		{"no_evidence", &rec.Evidence{}},
		{"noop_disabled_shape", &rec.Evidence{Status: rec.EvidenceNotAvailableCollectorDisabled, CorrelationConfidence: rec.ConfidenceNone}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, fc := newTestRouter(t)
			db, err := store.Init(t.TempDir())
			if err != nil {
				t.Fatalf("store.Init: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			r.db = db
			fc.lookupEv = tc.ev

			evt := http404AlertEvent()
			result := &analyzer.AnalysisResult{
				Verdict: patternstore.VerdictMalicious,
				Source:  "cache",
				Reason:  "dotenv probe pattern",
			}
			r.routeAlert(evt, result, watcher.LogLine{})

			if fc.lookups != 1 {
				t.Errorf("REC lookups = %d, want 1", fc.lookups)
			}
			if len(fc.pinned) != 0 {
				t.Errorf("PinVIP calls = %v, want none (shortcut must not reach coordinator path)", fc.pinned)
			}
			if pending, _ := r.alertCoordinator.Stats(); pending != 0 {
				t.Errorf("pending investigations = %d, want 0", pending)
			}
		})
	}
}

// TestRouteAlertLLMSourceSkipsStatusLookup: fresh LLM events never enter the
// cache-hit shortcut, so the new REC lookup must not fire for them.
func TestRouteAlertLLMSourceSkipsStatusLookup(t *testing.T) {
	r, fc := newTestRouter(t)

	evt := http404AlertEvent()
	result := &analyzer.AnalysisResult{
		Verdict: patternstore.VerdictMalicious,
		Source:  "llm",
		Reason:  "dotenv probe pattern",
	}
	r.routeAlert(evt, result, watcher.LogLine{})

	if fc.lookups != 0 {
		t.Errorf("REC lookups = %d, want 0 (LLM-sourced events bypass the shortcut)", fc.lookups)
	}
	if len(fc.pinned) != 1 {
		t.Errorf("PinVIP calls = %v, want exactly one (full coordinator path)", fc.pinned)
	}
}
