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
	"github.com/vaultguardian/observer/internal/watcher"
)

// fakeCollector is a minimal EvidenceCollector that records PinVIP calls so
// tests can assert evidence-protection wiring without a live sniffer.
type fakeCollector struct {
	pinned []string // eventIDs passed to PinVIP
}

func (f *fakeCollector) Start(context.Context) error            { return nil }
func (f *fakeCollector) Lookup(rec.LookupRequest) *rec.Evidence { return &rec.Evidence{} }
func (f *fakeCollector) Enabled() bool                          { return true }
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
