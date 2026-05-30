// internal/rec/reconcile_test.go
package rec

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// pubContainerFull builds a public-facing dockerContainer with an explicit ID
// (so tests can use realistic >12-char IDs that shortID() truncates) and a
// Swarm-style task name that baseName() collapses to its service name.
func pubContainerFull(name, id string, public, private int) dockerContainer {
	return dockerContainer{
		ID:    id,
		Names: []string{"/" + name},
		Ports: []dockerPort{{IP: "0.0.0.0", PublicPort: public, PrivatePort: private, Type: "tcp"}},
	}
}

// =============================================================================
// Pure diff
// =============================================================================

func nc(containerID string, pid int) *namespaceCapture {
	return &namespaceCapture{containerID: containerID, name: containerID, pid: pid}
}

func TestDiffReconcile(t *testing.T) {
	const fullID = "abcdefabcdef0123456789aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64-char
	short := shortID(fullID)

	tests := []struct {
		name    string
		desired map[string]desiredCapture
		actual  map[string]*namespaceCapture
		want    []reconcileAction // kind+id only, in expected order
	}{
		{
			name: "empty/empty → no actions",
		},
		{
			name:    "desired only → open",
			desired: map[string]desiredCapture{"x": {id: "x", name: "x", pid: 10}},
			want:    []reconcileAction{{kind: actionOpen, id: "x"}},
		},
		{
			name:   "actual only → close",
			actual: map[string]*namespaceCapture{"x": nc("x", 10)},
			want:   []reconcileAction{{kind: actionClose, id: "x"}},
		},
		{
			name:    "both, same pid → no-op",
			desired: map[string]desiredCapture{"x": {id: "x", name: "x", pid: 10}},
			actual:  map[string]*namespaceCapture{"x": nc("x", 10)},
		},
		{
			name:    "both, pid differs → repair",
			desired: map[string]desiredCapture{"x": {id: "x", name: "x", pid: 20}},
			actual:  map[string]*namespaceCapture{"x": nc("x", 10)},
			want:    []reconcileAction{{kind: actionRepair, id: "x"}},
		},
		{
			name:    "both, desired pid unknown (0) → no-op",
			desired: map[string]desiredCapture{"x": {id: "x", name: "x", pid: 0}},
			actual:  map[string]*namespaceCapture{"x": nc("x", 10)},
		},
		{
			name: "full-vs-short id → no churn",
			// desired keyed by shortID; actual instance still carries the FULL id
			// (the open-failure / pre-opener state). Must match → no open/close.
			desired: map[string]desiredCapture{short: {id: short, name: "svc", pid: 10}},
			actual:  map[string]*namespaceCapture{"svc": nc(fullID, 10)},
		},
		{
			name: "host instance ignored",
			// containerID=="" must never be a close candidate.
			actual: map[string]*namespaceCapture{"host": nc("", 0)},
		},
		{
			name: "deterministic ordering: close, repair, open by id",
			desired: map[string]desiredCapture{
				"r": {id: "r", name: "r", pid: 99}, // repair (actual pid differs)
				"o": {id: "o", name: "o", pid: 5},  // open
			},
			actual: map[string]*namespaceCapture{
				"r":  nc("r", 1),
				"c2": nc("c2", 1), // close
				"c1": nc("c1", 1), // close
			},
			want: []reconcileAction{
				{kind: actionClose, id: "c1"},
				{kind: actionClose, id: "c2"},
				{kind: actionRepair, id: "r"},
				{kind: actionOpen, id: "o"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := diffReconcile(tc.desired, tc.actual)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d actions, want %d: %+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].kind != tc.want[i].kind || got[i].id != tc.want[i].id {
					t.Fatalf("action[%d] = {kind:%d id:%q}, want {kind:%d id:%q}",
						i, got[i].kind, got[i].id, tc.want[i].kind, tc.want[i].id)
				}
			}
		})
	}
}

// =============================================================================
// reconcileOnce — fakes
// =============================================================================

// fakeDocker is an injectable Docker world for reconcileOnce tests: a set of
// running containers and their current PIDs, both mutable between reconciles.
type fakeDocker struct {
	mu         sync.Mutex
	containers []dockerContainer
	pids       map[string]int // container ID → current PID
	failOpen   map[string]bool
}

func (f *fakeDocker) deps(t *testing.T) autoDetectDeps {
	return autoDetectDeps{
		fetch: func() ([]dockerContainer, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			out := make([]dockerContainer, len(f.containers))
			copy(out, f.containers)
			return out, nil
		},
		pidFor: func(id, name string) (int, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.pids[id], nil
		},
		openerFor: func(pc publicContainer, capture *namespaceCapture) func() (int, error) {
			return func() (int, error) {
				f.mu.Lock()
				fail := f.failOpen[pc.ID]
				pid := f.pids[pc.ID]
				f.mu.Unlock()
				if fail {
					return -1, errors.New("setns denied")
				}
				// Mimic dockerNamespaceOpener: short id + resolved PID.
				capture.containerID = shortID(pc.ID)
				capture.pid = pid
				return dgramFD(t), nil
			}
		},
		hostOpen: func(capture *namespaceCapture) (int, error) { return dgramFD(t), nil },
	}
}

// newReconcileCollector wires a bareCollector for reconcileOnce tests.
func newReconcileCollector(t *testing.T, f *fakeDocker) (*liveCollector, context.Context) {
	t.Helper()
	lc := bareCollector()
	lc.config.Ports = []int{80}
	lc.config.MaxNamespaces = 16
	lc.vxlanPort = DefaultVXLANPort
	lc.deps = f.deps(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { lc.Close(); cancel() })
	return lc, ctx
}

func liveNamespaceCount(lc *liveCollector) int {
	lc.capMu.Lock()
	defer lc.capMu.Unlock()
	n := 0
	for _, c := range lc.captures {
		if c.containerID != "" && c.running.Load() {
			n++
		}
	}
	return n
}

func TestReconcile_PIDChangeRepair(t *testing.T) {
	const id = "captaincaptain01deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0" // >12 chars
	f := &fakeDocker{
		containers: []dockerContainer{pubContainerFull("captain-captain.1.x", id, 3000, 3000)},
		pids:       map[string]int{id: 100},
	}
	lc, ctx := newReconcileCollector(t, f)

	lc.reconcileOnce(ctx) // open at PID 100

	lc.capMu.Lock()
	old := lc.captures["captain-captain"]
	lc.capMu.Unlock()
	if old == nil || old.pid != 100 || !old.running.Load() {
		t.Fatalf("initial open failed: %+v (keys=%v)", old, capKeys(lc))
	}

	// In-place restart: same ID, new PID.
	f.mu.Lock()
	f.pids[id] = 200
	f.mu.Unlock()

	out := captureLogs(func() { lc.reconcileOnce(ctx) })

	lc.capMu.Lock()
	got := lc.captures["captain-captain"]
	n := len(lc.captures)
	lc.capMu.Unlock()

	if n != 1 {
		t.Fatalf("captures = %d, want 1 (no name#shortID duplicate): %v", n, capKeys(lc))
	}
	if got == old {
		t.Fatal("instance was not replaced on repair")
	}
	if got == nil || got.pid != 200 || !got.running.Load() {
		t.Fatalf("repaired instance wrong: %+v", got)
	}
	if old.running.Load() {
		t.Fatal("old instance still running after repair")
	}
	if !strings.Contains(out, "PID changed 100→200") || !strings.Contains(out, "reopening namespace socket") {
		t.Fatalf("missing repair log; got:\n%s", out)
	}
}

func TestReconcile_RepairWithSiblingReplica(t *testing.T) {
	const idA = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	const idB = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222"
	f := &fakeDocker{
		// Two replicas of one Swarm service: same base name "srv-captain--app".
		containers: []dockerContainer{
			pubContainerFull("srv-captain--app.1.aaa", idA, 80, 80),
			pubContainerFull("srv-captain--app.2.bbb", idB, 80, 80),
		},
		pids: map[string]int{idA: 100, idB: 500},
	}
	lc, ctx := newReconcileCollector(t, f)

	lc.reconcileOnce(ctx) // open both replicas

	// Sorted by name then ID: idA < idB, so A keys "srv-captain--app", B collides
	// to "srv-captain--app#<shortB>".
	keyA := "srv-captain--app"
	keyB := "srv-captain--app#" + shortID(idB)
	lc.capMu.Lock()
	a0, b0 := lc.captures[keyA], lc.captures[keyB]
	lc.capMu.Unlock()
	if a0 == nil || b0 == nil {
		t.Fatalf("both replicas not opened: %v", capKeys(lc))
	}

	// Replica A restarts in place (new PID); B unchanged.
	f.mu.Lock()
	f.pids[idA] = 101
	f.mu.Unlock()

	lc.reconcileOnce(ctx)

	lc.capMu.Lock()
	a1, b1 := lc.captures[keyA], lc.captures[keyB]
	n := len(lc.captures)
	lc.capMu.Unlock()

	if n != 2 {
		t.Fatalf("captures = %d, want 2 (no churn/duplicate): %v", n, capKeys(lc))
	}
	// A repaired: new instance under the same key, new PID.
	if a1 == a0 || a1 == nil || a1.pid != 101 || !a1.running.Load() {
		t.Fatalf("replica A not repaired correctly: old=%p new=%+v", a0, a1)
	}
	// B untouched: same instance, same key, still running.
	if b1 != b0 {
		t.Fatal("sibling replica B was replaced — should be untouched")
	}
	if !b1.running.Load() || b1.pid != 500 {
		t.Fatalf("sibling replica B disturbed: running=%v pid=%d", b1.running.Load(), b1.pid)
	}
}

func TestReconcile_SwarmRedeploy_CloseOldOpenNew(t *testing.T) {
	const idA = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	const idB = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222"
	f := &fakeDocker{
		containers: []dockerContainer{pubContainerFull("captain-captain.1.aaa", idA, 3000, 3000)},
		pids:       map[string]int{idA: 100},
	}
	lc, ctx := newReconcileCollector(t, f)

	lc.reconcileOnce(ctx) // open task A
	if lc.captures["captain-captain"] == nil {
		t.Fatalf("task A not opened: %v", capKeys(lc))
	}

	// Swarm redeploy: old task gone, NEW task (new ID), same service name.
	f.mu.Lock()
	f.containers = []dockerContainer{pubContainerFull("captain-captain.2.bbb", idB, 3000, 3000)}
	f.pids = map[string]int{idB: 700}
	f.mu.Unlock()

	out := captureLogs(func() { lc.reconcileOnce(ctx) })

	lc.capMu.Lock()
	got := lc.captures["captain-captain"]
	n := len(lc.captures)
	lc.capMu.Unlock()

	if n != 1 {
		t.Fatalf("captures = %d, want 1: %v", n, capKeys(lc))
	}
	if got == nil || got.containerID != shortID(idB) || got.pid != 700 || !got.running.Load() {
		t.Fatalf("new task not opened correctly: %+v", got)
	}
	// Healed via remove + fresh open, NOT the PID-repair path.
	if !strings.Contains(out, "removed from monitoring") || !strings.Contains(out, "now monitoring") {
		t.Fatalf("expected close-old + open-new logs; got:\n%s", out)
	}
	if strings.Contains(out, "PID changed") {
		t.Fatalf("redeploy must not use the PID-repair path; got:\n%s", out)
	}
}

func TestReconcile_OpenMissing_CloseOrphaned(t *testing.T) {
	const idA = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	const idB = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222"
	f := &fakeDocker{
		containers: []dockerContainer{pubContainerFull("svc-a", idA, 8080, 80)},
		pids:       map[string]int{idA: 100},
	}
	lc, ctx := newReconcileCollector(t, f)

	lc.reconcileOnce(ctx)
	if lc.captures["svc-a"] == nil {
		t.Fatalf("svc-a not opened: %v", capKeys(lc))
	}

	// A removed, B appears.
	f.mu.Lock()
	f.containers = []dockerContainer{pubContainerFull("svc-b", idB, 9090, 3000)}
	f.pids = map[string]int{idB: 200}
	f.mu.Unlock()

	lc.reconcileOnce(ctx)

	lc.capMu.Lock()
	defer lc.capMu.Unlock()
	if lc.captures["svc-a"] != nil {
		t.Fatal("svc-a should be closed+removed")
	}
	b := lc.captures["svc-b"]
	if b == nil || !b.running.Load() || b.containerID != shortID(idB) {
		t.Fatalf("svc-b not opened correctly: %+v", b)
	}
}

func TestReconcile_CapAndExclude_Runtime(t *testing.T) {
	const idEx = "eeeeeeeeeeee0000000000000000000000000000000000000000000000000000"
	f := &fakeDocker{
		containers: []dockerContainer{
			pubContainerFull("svc-c", "cccccccccccc3333333333333333333333333333333333333333333333333333", 80, 80),
			pubContainerFull("svc-a", "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111", 80, 80),
			pubContainerFull("svc-b", "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222", 80, 80),
			pubContainerFull("secret-svc", idEx, 80, 80),
		},
		pids: map[string]int{
			"cccccccccccc3333333333333333333333333333333333333333333333333333": 3,
			"aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111": 1,
			"bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222": 2,
			idEx: 9,
		},
	}
	lc, ctx := newReconcileCollector(t, f)
	lc.config.MaxNamespaces = 1
	lc.config.ExcludeContainers = map[string]bool{"secret-svc": true}

	out := captureLogs(func() { lc.reconcileOnce(ctx) })

	if got := liveNamespaceCount(lc); got != 1 {
		t.Fatalf("live namespace captures = %d, want 1 (cap): %v", got, capKeys(lc))
	}
	// svc-a wins the cap (sorted by name); excluded never appears.
	if lc.captures["svc-a"] == nil {
		t.Fatalf("svc-a should be the one monitored: %v", capKeys(lc))
	}
	if lc.captures["secret-svc"] != nil {
		t.Fatal("excluded container must never be monitored")
	}
	if !strings.Contains(out, "REC_MAX_NAMESPACES=1") {
		t.Fatalf("expected cap-drop log; got:\n%s", out)
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	const idA = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	const idB = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222"
	f := &fakeDocker{
		containers: []dockerContainer{
			pubContainerFull("svc-a", idA, 8080, 80),
			pubContainerFull("svc-b", idB, 9090, 3000),
		},
		pids: map[string]int{idA: 100, idB: 200},
	}
	lc, ctx := newReconcileCollector(t, f)

	lc.reconcileOnce(ctx)
	snap := func() map[string]*namespaceCapture {
		lc.capMu.Lock()
		defer lc.capMu.Unlock()
		m := make(map[string]*namespaceCapture, len(lc.captures))
		for k, v := range lc.captures {
			m[k] = v
		}
		return m
	}
	first := snap()
	if len(first) != 2 {
		t.Fatalf("want 2 captures, got %v", capKeys(lc))
	}

	for i := 0; i < 2; i++ {
		lc.reconcileOnce(ctx)
		again := snap()
		if len(again) != len(first) {
			t.Fatalf("reconcile %d changed capture count: %d → %d", i+2, len(first), len(again))
		}
		for k, v := range first {
			if again[k] != v {
				t.Fatalf("reconcile %d churned key %q (instance pointer changed)", i+2, k)
			}
		}
	}
}

func TestReconcile_PartialOpenFailure(t *testing.T) {
	const idA = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	const idB = "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222"
	f := &fakeDocker{
		containers: []dockerContainer{
			pubContainerFull("svc-a", idA, 8080, 80),
			pubContainerFull("svc-b", idB, 9090, 3000),
		},
		pids:     map[string]int{idA: 100, idB: 200},
		failOpen: map[string]bool{idB: true},
	}
	lc, ctx := newReconcileCollector(t, f)

	lc.reconcileOnce(ctx)

	lc.capMu.Lock()
	a, b := lc.captures["svc-a"], lc.captures["svc-b"]
	lc.capMu.Unlock()

	if a == nil || !a.running.Load() || a.lastError != "" {
		t.Fatalf("healthy svc-a wrong: %+v", a)
	}
	if b == nil || b.running.Load() || b.lastError == "" {
		t.Fatalf("failed svc-b should carry lastError and not run: %+v", b)
	}
	if !lc.Enabled() {
		t.Fatal("collector should stay Enabled off the healthy instance")
	}
}

func TestReconcile_HostInvariant(t *testing.T) {
	const id = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	f := &fakeDocker{
		containers: nil, // start with zero public containers
		pids:       map[string]int{id: 100},
	}
	lc, ctx := newReconcileCollector(t, f)

	// Zero public → host fallback comes up.
	lc.reconcileOnce(ctx)
	host := lc.captures["host"]
	if host == nil || !host.running.Load() {
		t.Fatalf("host fallback should be active with zero namespaces: %v", capKeys(lc))
	}

	// A public container appears → namespace opens AND host is retired (no gap:
	// the namespace is confirmed running before the host is closed).
	f.mu.Lock()
	f.containers = []dockerContainer{pubContainerFull("captain-captain.1.x", id, 3000, 3000)}
	f.mu.Unlock()
	lc.reconcileOnce(ctx)

	if ns := lc.captures["captain-captain"]; ns == nil || !ns.running.Load() {
		t.Fatalf("namespace capture not active: %v", capKeys(lc))
	}
	if h := lc.captures["host"]; h != nil {
		t.Fatalf("host fallback should be retired once namespace coverage is up: %v", capKeys(lc))
	}
	if host.running.Load() {
		t.Fatal("retired host instance should no longer be running")
	}

	// Container removed → last namespace closes → host reopens.
	f.mu.Lock()
	f.containers = nil
	f.mu.Unlock()
	lc.reconcileOnce(ctx)

	if lc.captures["captain-captain"] != nil {
		t.Fatal("namespace capture should be removed")
	}
	if h := lc.captures["host"]; h == nil || !h.running.Load() {
		t.Fatalf("host fallback should be reopened when last namespace closes: %v", capKeys(lc))
	}
}

// =============================================================================
// Events listener / backoff
// =============================================================================

func TestNextBackoff(t *testing.T) {
	max := 30 * time.Second
	if got := nextBackoff(time.Second, max); got != 2*time.Second {
		t.Fatalf("nextBackoff(1s) = %s, want 2s", got)
	}
	if got := nextBackoff(16*time.Second, max); got != max {
		t.Fatalf("nextBackoff(16s) = %s, want 30s (capped)", got)
	}
	if got := nextBackoff(max, max); got != max {
		t.Fatalf("nextBackoff(30s) = %s, want 30s (stays capped)", got)
	}
}

func TestConsumeEventsTriggers(t *testing.T) {
	lc := bareCollector()
	lc.reconcileCh = make(chan struct{}, 10) // wide so we can count, not coalesce
	lc.deps = (&fakeDocker{}).deps(t)

	stream := strings.NewReader(
		`{"Action":"start","Actor":{"ID":"a"}}` + "\n" +
			`{"Action":"die","Actor":{"ID":"b"}}` + "\n")

	got, err := lc.consumeEvents(context.Background(), stream)
	if !got {
		t.Fatal("consumeEvents reported no event decoded")
	}
	if err != io.EOF {
		t.Fatalf("err = %v, want io.EOF at stream end", err)
	}
	if len(lc.reconcileCh) != 2 {
		t.Fatalf("triggers = %d, want 2 (one per event)", len(lc.reconcileCh))
	}
}

func TestConsumeEventsContextCancel(t *testing.T) {
	lc := bareCollector()
	lc.reconcileCh = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	got, err := lc.consumeEvents(ctx, strings.NewReader(`{"Action":"start","Actor":{"ID":"a"}}`))
	if err == nil {
		t.Fatal("want ctx error, got nil")
	}
	if got {
		t.Fatal("no event should be reported on a pre-cancelled context")
	}
}

func TestTriggerCoalesces(t *testing.T) {
	lc := bareCollector()
	lc.reconcileCh = make(chan struct{}, 1)
	for i := 0; i < 5; i++ {
		lc.trigger()
	}
	if len(lc.reconcileCh) != 1 {
		t.Fatalf("coalesced triggers = %d, want 1", len(lc.reconcileCh))
	}
}

// =============================================================================
// Lifecycle
// =============================================================================

// TestClose_StopsAllGoroutines launches the full manager set (reconcile loop,
// rescan ticker, events listener, vipCleanupLoop) exactly as Start() does in
// auto-detect mode, fires triggers concurrently, then asserts Close() cancels
// and JOINS every goroutine. The deterministic leak check is that mgrWG.Wait()
// returns — a leaked/blocked goroutine makes Close() hang and the test fails on
// the timeout. Run under -race for the concurrent-trigger path.
func TestClose_StopsAllGoroutines(t *testing.T) {
	const id = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	f := &fakeDocker{
		containers: []dockerContainer{pubContainerFull("svc-a", id, 8080, 80)},
		pids:       map[string]int{id: 100},
	}
	lc := bareCollector()
	lc.config.Ports = []int{80}
	lc.config.MaxNamespaces = 16
	lc.config.RescanInterval = 20 * time.Millisecond
	lc.config.DockerSocket = "/nonexistent/docker.sock" // events stream fails fast → backoff
	lc.vxlanPort = DefaultVXLANPort
	lc.deps = f.deps(t)

	mgrCtx, cancel := context.WithCancel(context.Background())
	lc.mgrCancel = cancel
	lc.reconcileCh = make(chan struct{}, 1)
	lc.mgrWG.Add(4)
	go func() { defer lc.mgrWG.Done(); lc.reconcileLoop(mgrCtx) }()
	go func() { defer lc.mgrWG.Done(); lc.rescanTicker(mgrCtx) }()
	go func() { defer lc.mgrWG.Done(); lc.eventsListener(mgrCtx) }()
	go func() { defer lc.mgrWG.Done(); lc.vipCleanupLoop(mgrCtx) }()

	// Hammer triggers from several goroutines while the ticker also fires.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				lc.trigger()
			}
		}()
	}
	wg.Wait()
	time.Sleep(40 * time.Millisecond) // let a few reconciles + ticks run

	done := make(chan struct{})
	go func() { lc.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return — manager goroutine leak")
	}
}

// TestLegacyMode_NoManager: with REC_NS_CONTAINER set, Start() must NOT create
// the runtime reconciliation manager (no events listener, ticker, or reconcile
// loop). The capture open may fail in the test env (no CAP_NET_RAW / no Docker);
// that is irrelevant — the assertion is that the manager fields stay nil.
func TestLegacyMode_NoManager(t *testing.T) {
	lc := bareCollector()
	lc.config.Enabled = true
	lc.config.NSContainer = "captain-nginx"
	lc.config.DockerSocket = "/nonexistent/docker.sock"

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { lc.Close(); cancel() })

	_ = lc.Start(ctx) // error is fine in a capability-less test env

	if lc.mgrCancel != nil {
		t.Fatal("legacy mode must not start the reconciliation manager (mgrCancel set)")
	}
	if lc.reconcileCh != nil {
		t.Fatal("legacy mode must not create reconcileCh")
	}
}
