// httpoutcomesink_realpath_test.go
//
// Real-path parity coverage (round-4, addressing the review's "remaining
// validation" note). These drive the ACTUAL producing branches — the router's
// recon_failed path and the coordinator dispatch callback's escalated and
// downgraded branches — with a real store and a real notifier dispatcher, and
// assert that store persistence, notification interaction (the Notified column
// gated on a real Dispatch), and sync-insert availability (the row's presence
// for the cursor lane) are IDENTICAL feature-off vs feature-on-with-no-ID.
//
// WHAT THIS GATE PROVES: routing an outcome through the sink adds nothing when
// coalescing is inert, on the real code paths (not labelled generic closures).
// It is refactor-consistency coverage, not a literal pre-refactor binary diff.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/notifier"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/store"
	"github.com/vaultguardian/observer/internal/watcher"
)

// realDispatcher builds a notifier wired to a webhook so Dispatch enqueues a
// real alert; webhookHits counts deliveries the worker actually made.
func realDispatcher(t *testing.T) (*notifier.Dispatcher, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	d, err := notifier.NewDispatcher(&notifier.Config{
		Webhook:  notifier.WebhookConfig{URL: srv.URL},
		Hostname: "test-host",
		Routing:  notifier.RoutingConfig{Malicious: []string{"webhook"}, Suspicious: []string{"webhook"}},
	})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	return d, &hits
}

type realPathResult struct {
	finding      *store.Finding
	webhookHits  int64
	dispatchedOK bool // finding.Notified — the real Dispatch interaction outcome
}

// escalationVia drives the REAL dispatch callback's escalated branch.
func escalationVia(t *testing.T, sink *httpOutcomeSink) realPathResult {
	t.Helper()
	db, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	disp, hits := realDispatcher(t)

	cb := makeDispatchCallback(disp, db, sink)
	cb(coordinator.FinalAlert{
		EventID: "evt_esc", ScopeKey: "docker:captain-nginx", SourceType: "docker", SourceName: "captain-nginx",
		Host: "wp.example.com", HTTPMethod: "GET", HTTPPath: "/?x=1", StatusCode: 200,
		Verdict: "alert", Severity: "suspicious", Escalated: true, EscalateReason: "disclosure", Key: "k", EventCount: 2,
		Line: `1.2.3.4 - - [t] "GET /?x=1 HTTP/1.1" 200 83 "-" "curl"`, // NO vgrid
		BuildAlert: func(interface{}) interface{} {
			return notifier.Alert{EventID: "evt_esc", Severity: notifier.SeverityMalicious, Reason: "disclosure"}
		},
	})
	disp.Stop(context.Background()) // drains the queue → webhook delivered

	f, err := db.GetFindingByEventID(context.Background(), "evt_esc")
	if err != nil {
		t.Fatalf("GetFindingByEventID: %v", err)
	}
	return realPathResult{finding: f, webhookHits: atomic.LoadInt64(hits), dispatchedOK: f.Notified}
}

// downgradeVia drives the REAL dispatch callback's downgraded (REC-evidence) branch.
func downgradeVia(t *testing.T, sink *httpOutcomeSink) realPathResult {
	t.Helper()
	db, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	disp, hits := realDispatcher(t)

	cb := makeDispatchCallback(disp, db, sink)
	cb(coordinator.FinalAlert{
		EventID: "evt_dg", ScopeKey: "docker:captain-nginx", SourceType: "docker", SourceName: "captain-nginx",
		Host: "wp.example.com", HTTPMethod: "GET", HTTPPath: "/?x=1", StatusCode: 404,
		Verdict: "alert", Severity: "suspicious", Downgraded: true, DowngradeReason: "rejected", Key: "k", EventCount: 2,
		Line: `1.2.3.4 - - [t] "GET /?x=1 HTTP/1.1" 404 83 "-" "curl"`,
	})
	disp.Stop(context.Background())

	f, err := db.GetFindingByEventID(context.Background(), "evt_dg")
	if err != nil {
		t.Fatalf("GetFindingByEventID: %v", err)
	}
	return realPathResult{finding: f, webhookHits: atomic.LoadInt64(hits), dispatchedOK: f.Notified}
}

// reconVia drives the REAL router recon_failed branch (resultRouter.routeAlert).
func reconVia(t *testing.T, sink *httpOutcomeSink) realPathResult {
	t.Helper()
	db, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	disp, hits := realDispatcher(t)

	coord := coordinator.New(context.Background(), coordinator.Config{},
		func(coordinator.FinalAlert) {},
		func(*coordinator.PendingAlert) coordinator.EvidenceDecision { return coordinator.EvidenceDecision{} },
		func(coordinator.VerifyRequest) *coordinator.VerifyResult { return nil },
		coordinator.NewSelfSuppressor())
	r := &resultRouter{cfg: Config{}, db: db, collector: &fakeCollector{}, alertCoordinator: coord, dispatch: disp, sink: sink}

	evt := &event.Event{
		ID: "evt_recon", SourceType: "docker", SourceName: "captain-captain",
		NormalizedLine: "example.com GET /api/keys HTTP/1.1 200",
		Line:           `1.2.3.4 - - [t] "GET /api/keys HTTP/1.1" 200 83`,
		Hash:           "deadbeef", Timestamp: time.Now(),
	}
	r.routeAlert(evt, &analyzer.AnalysisResult{
		Verdict: patternstore.VerdictMalicious, Source: "llm",
		LLMClassification: "recon_failed", Reason: "failed probe",
	}, watcher.LogLine{})
	disp.Stop(context.Background())

	f, err := db.GetFindingByEventID(context.Background(), "evt_recon")
	if err != nil {
		t.Fatalf("GetFindingByEventID: %v", err)
	}
	return realPathResult{finding: f, webhookHits: atomic.LoadInt64(hits), dispatchedOK: f.Notified}
}

func TestRealPathParityFeatureOffVsOnNoID(t *testing.T) {
	assertParity := func(t *testing.T, off, on realPathResult) {
		t.Helper()
		if off.finding.Verdict != on.finding.Verdict ||
			off.finding.Classification != on.finding.Classification ||
			off.finding.ResolutionStatus != on.finding.ResolutionStatus ||
			off.finding.Downgraded != on.finding.Downgraded ||
			off.finding.HTTPPath != on.finding.HTTPPath ||
			off.dispatchedOK != on.dispatchedOK {
			t.Errorf("store/notification parity broken:\noff=%+v\non =%+v", off.finding, on.finding)
		}
	}
	offSink := func() *httpOutcomeSink { return newHTTPOutcomeSink(Config{}) }
	onSink := func() *httpOutcomeSink { return newHTTPOutcomeSink(enabledSinkCfg()) }

	t.Run("coordinator_escalation_notifies", func(t *testing.T) {
		off := escalationVia(t, offSink())
		on := escalationVia(t, onSink())
		assertParity(t, off, on)
		if off.finding.Verdict != "malicious" {
			t.Errorf("escalation verdict = %q, want malicious", off.finding.Verdict)
		}
		// Real notification interaction: the dispatch enqueued and the webhook
		// actually delivered, identically on both sinks.
		if !off.dispatchedOK || !on.dispatchedOK {
			t.Errorf("escalation must mark Notified via real Dispatch: off=%v on=%v", off.dispatchedOK, on.dispatchedOK)
		}
		if off.webhookHits < 1 || on.webhookHits < 1 {
			t.Errorf("escalation webhook deliveries: off=%d on=%d, want >=1 each", off.webhookHits, on.webhookHits)
		}
	})

	t.Run("rec_evidence_downgrade_silent", func(t *testing.T) {
		off := downgradeVia(t, offSink())
		on := downgradeVia(t, onSink())
		assertParity(t, off, on)
		if off.finding.Verdict != "downgraded" || off.dispatchedOK {
			t.Errorf("downgrade must persist downgraded and NOT notify: verdict=%q notified=%v", off.finding.Verdict, off.dispatchedOK)
		}
		if off.webhookHits != 0 || on.webhookHits != 0 {
			t.Errorf("downgrade must not deliver any webhook: off=%d on=%d", off.webhookHits, on.webhookHits)
		}
	})

	t.Run("recon_failed_router_silent", func(t *testing.T) {
		off := reconVia(t, offSink())
		on := reconVia(t, onSink())
		assertParity(t, off, on)
		if off.finding.Verdict != "recon" || off.dispatchedOK {
			t.Errorf("recon_failed must persist recon and NOT notify: verdict=%q notified=%v", off.finding.Verdict, off.dispatchedOK)
		}
		if off.webhookHits != 0 || on.webhookHits != 0 {
			t.Errorf("recon_failed must not deliver any webhook: off=%d on=%d", off.webhookHits, on.webhookHits)
		}
	})
}
