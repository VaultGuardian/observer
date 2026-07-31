package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/health"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
)

// newStatsTestServer builds a Server with everything handleStats touches:
// a real store (AsyncWriterStats), real pattern store and analyzer, and a
// disabled (no-op) REC collector.
func newStatsTestServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	patterns, err := patternstore.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("init pattern store: %v", err)
	}
	a := analyzer.New(normalizer.NewRegistry(), patterns, nil, nil)

	return &Server{
		store:     st,
		patterns:  patterns,
		analyzer:  a,
		collector: rec.NewCollector(rec.CollectorConfig{Enabled: false}),
	}
}

func getStats(t *testing.T, srv *Server) map[string]interface{} {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	srv.handleStats(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleStats status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	return body
}

func pipelineHealth(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	ph, ok := body["pipeline_health"].(map[string]interface{})
	if !ok {
		t.Fatalf("pipeline_health missing or wrong type: %T", body["pipeline_health"])
	}
	return ph
}

// TestHandleStats_NoProviderNoPanic: before main installs the telemetry
// sources, the always-available portions render and the runtime portions are
// omitted - no panic, no partial keys.
func TestHandleStats_NoProviderNoPanic(t *testing.T) {
	srv := newStatsTestServer(t)
	ph := pipelineHealth(t, getStats(t, srv))

	for _, key := range []string{"stats_epoch", "started_at", "pipeline", "retry", "llm_scheduler", "coordinator"} {
		if _, present := ph[key]; present {
			t.Errorf("pipeline_health.%s present without an installed provider", key)
		}
	}
	if _, present := ph["snapshot_at"]; !present {
		t.Error("snapshot_at missing")
	}

	writer, ok := ph["writer"].(map[string]interface{})
	if !ok {
		t.Fatalf("writer block missing: %T", ph["writer"])
	}
	if got := writer["dropped"].(float64); got != 0 {
		t.Errorf("writer.dropped = %v, want 0", got)
	}

	// Disabled REC renders zeros, including vip_capacity: 0.
	recBlock, ok := ph["rec"].(map[string]interface{})
	if !ok {
		t.Fatalf("rec block missing: %T", ph["rec"])
	}
	if got := recBlock["vip_capacity"].(float64); got != 0 {
		t.Errorf("rec.vip_capacity = %v with disabled collector, want 0", got)
	}

	norm, ok := ph["normalizer"].(map[string]interface{})
	if !ok {
		t.Fatalf("normalizer block missing: %T", ph["normalizer"])
	}
	if got := norm["tracked_scopes"].(float64); got != 0 {
		t.Errorf("normalizer.tracked_scopes = %v, want 0", got)
	}

	// The top-level rec block stays gated on Enabled() - absent when disabled.
	if _, present := getStats(t, srv)["rec"]; present {
		t.Error("top-level rec block rendered with a disabled collector")
	}
}

// TestHandleStats_WithProvider: once SetHealthTelemetry installs the sources,
// the runtime portions render with capacities from the accessors.
func TestHandleStats_WithProvider(t *testing.T) {
	srv := newStatsTestServer(t)
	hs := health.NewStats(1000, 500)
	hs.ObservePipelineDepth(42)

	srv.SetHealthTelemetry(hs, func() health.RuntimeSnapshot {
		return health.RuntimeSnapshot{
			PipelineDepth:                7,
			RetryDepth:                   3,
			SchedulerInUse:               1,
			SchedulerCapacity:            4,
			SchedulerCalls:               99,
			SchedulerDeferred:            5,
			CoordinatorPending:           11,
			CoordinatorCapacity:          100,
			CoordinatorCapacityEvictions: 2,
		}
	})

	ph := pipelineHealth(t, getStats(t, srv))

	epoch, _ := ph["stats_epoch"].(string)
	if len(epoch) != 16 {
		t.Errorf("stats_epoch = %q, want 16 hex chars", epoch)
	}
	if _, present := ph["started_at"]; !present {
		t.Error("started_at missing")
	}

	pipe := ph["pipeline"].(map[string]interface{})
	if pipe["depth"].(float64) != 7 || pipe["capacity"].(float64) != 1000 || pipe["high_water"].(float64) != 42 || pipe["dropped"].(float64) != 0 {
		t.Errorf("pipeline block = %v, want depth 7, capacity 1000, high_water 42, dropped 0", pipe)
	}

	retry := ph["retry"].(map[string]interface{})
	if retry["depth"].(float64) != 3 || retry["capacity"].(float64) != 500 {
		t.Errorf("retry block = %v, want depth 3, capacity 500", retry)
	}

	sched := ph["llm_scheduler"].(map[string]interface{})
	if sched["in_use"].(float64) != 1 || sched["capacity"].(float64) != 4 ||
		sched["calls"].(float64) != 99 || sched["deferred_flights"].(float64) != 5 {
		t.Errorf("llm_scheduler block = %v, want in_use 1, capacity 4, calls 99, deferred_flights 5", sched)
	}

	coord := ph["coordinator"].(map[string]interface{})
	if coord["pending"].(float64) != 11 || coord["capacity"].(float64) != 100 || coord["capacity_evictions"].(float64) != 2 {
		t.Errorf("coordinator block = %v, want pending 11, capacity 100, capacity_evictions 2", coord)
	}
}

// TestHandleStats_ProviderInstallRace hammers handleStats while the health
// telemetry installs mid-flight. Run under -race this proves the atomic
// pointer install-after-start pattern is race-clean.
func TestHandleStats_ProviderInstallRace(t *testing.T) {
	srv := newStatsTestServer(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
					srv.handleStats(httptest.NewRecorder(), req)
				}
			}
		}()
	}

	hs := health.NewStats(1000, 500)
	for i := 0; i < 50; i++ {
		srv.SetHealthTelemetry(hs, func() health.RuntimeSnapshot {
			return health.RuntimeSnapshot{PipelineDepth: 1}
		})
	}
	close(stop)
	wg.Wait()

	// After install, the runtime portions must be present.
	if _, present := pipelineHealth(t, getStats(t, srv))["pipeline"]; !present {
		t.Error("pipeline block missing after SetHealthTelemetry")
	}
}
