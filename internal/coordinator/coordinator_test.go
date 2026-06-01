package coordinator

import (
	"context"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// P0 regression: a timeout dispatch must never race an in-flight evidence
// check. The check (which can be kicked off by the concurrent TryResolveVIP
// push path) sets c.checking[key] while it runs the LLM outside the lock; the
// finalize deadline must defer to it rather than delete the pending entry and
// dispatch a plain SUSPICIOUS alert, which silently dropped the check's
// verdict in prod.
// =============================================================================

// fakeDispatcher records every FinalAlert the coordinator emits, with the
// wall-clock time it was dispatched (for ordering assertions).
type fakeDispatcher struct {
	mu   sync.Mutex
	sent []FinalAlert
	at   []time.Time
}

func (f *fakeDispatcher) dispatch(a FinalAlert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, a)
	f.at = append(f.at, time.Now())
}

func (f *fakeDispatcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func (f *fakeDispatcher) all() []FinalAlert {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]FinalAlert(nil), f.sent...)
}

// gatedEvidence is an EvidenceCheckFunc whose call can be made to block until
// the test releases it, returning a configured decision. The first call that
// blocks signals `started` so the test knows a check is genuinely in flight.
type gatedEvidence struct {
	block    chan struct{} // if non-nil, the check blocks until this is closed
	decision EvidenceDecision
	started  chan struct{}
	once     sync.Once
}

func (g *gatedEvidence) check(_ *PendingAlert) EvidenceDecision {
	if g.block != nil {
		g.once.Do(func() { close(g.started) })
		<-g.block
	}
	return g.decision
}

func noVerify(VerifyRequest) *VerifyResult { return nil }

// newTestCoordinator builds a coordinator with millisecond windows and a fast
// retry interval so the deferred-dispatch loop is exercised deterministically.
func newTestCoordinator(t *testing.T, ev EvidenceCheckFunc, evWindow, finWindow, maxWait time.Duration) (*Coordinator, *fakeDispatcher, context.CancelFunc) {
	t.Helper()
	fd := &fakeDispatcher{}
	ctx, cancel := context.WithCancel(context.Background())
	c := New(ctx, Config{
		EvidenceWindow:       evWindow,
		FinalizeWindow:       finWindow,
		GraveyardTTL:         5 * time.Second,
		MaxEvidenceCheckWait: maxWait,
		CatchAllThreshold:    DefaultCatchAllThreshold,
	}, fd.dispatch, ev, noVerify, NewSelfSuppressor())
	c.dispatchRetryInterval = 5 * time.Millisecond
	return c, fd, cancel
}

// suspiciousAlert is a minimal pending alert that takes the plain-suspicious
// path: BodyPreviewHash="" skips the Process catch-all, ResponseBytes=0 skips
// the dispatchTimedOut byte-fallback.
func suspiciousAlert() *PendingAlert {
	return &PendingAlert{
		EventID:    "evt_test",
		ScopeKey:   "docker:test",
		SourceType: "nginx",
		Verdict:    "suspicious",
		Severity:   "suspicious",
		Reason:     "scanner path",
		Host:       "app.example",
		HTTPMethod: "GET",
		HTTPPath:   "/api/.env",
		StatusCode: 200,
	}
}

func (c *Coordinator) pendingLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

func (c *Coordinator) graveyardOutcome(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tomb, ok := c.graveyard[key]
	if !ok {
		return "", false
	}
	return tomb.Outcome, true
}

// waitForDispatch polls until the dispatcher has at least n alerts or the
// deadline elapses.
func waitForDispatch(t *testing.T, fd *fakeDispatcher, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if fd.count() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d dispatch(es); got %d", n, fd.count())
}

// TestTimeoutDefersToInFlightDowngrade is the core regression: the finalize
// deadline fires while a VIP-initiated evidence check is in flight; the
// timeout must defer (no suspicious dispatch, pending preserved) and the
// check's downgrade must be the one and only verdict emitted.
func TestTimeoutDefersToInFlightDowngrade(t *testing.T) {
	const key = "app.example|GET|/api/.env|200"
	g := &gatedEvidence{
		block:    make(chan struct{}),
		started:  make(chan struct{}),
		decision: EvidenceDecision{Downgraded: true, Reason: "known benign 404 page"},
	}
	// Windows long enough that the VIP check reliably grabs the singleflight
	// guard before investigationLoop's own finalize check runs.
	c, fd, cancel := newTestCoordinator(t, g.check, 80*time.Millisecond, 80*time.Millisecond, 10*time.Second)
	defer cancel()

	c.Process(key, suspiciousAlert())
	go c.TryResolveVIP(key) // starts the in-flight check
	<-g.started             // check is now running, c.checking[key]==true

	// Let the finalize deadline fire and dispatchTimedOut defer several times.
	time.Sleep(200 * time.Millisecond)
	if got := fd.count(); got != 0 {
		t.Fatalf("timeout dispatched while a check was in flight (got %d alerts) — the race fix did not defer", got)
	}
	if c.pendingLen() != 1 {
		t.Fatalf("pending entry was deleted out from under the in-flight check; pending=%d", c.pendingLen())
	}

	// Release the check: its downgrade now owns the dispatch.
	close(g.block)
	waitForDispatch(t, fd, 1, 2*time.Second)
	time.Sleep(50 * time.Millisecond) // give the retry loop a chance to double-dispatch

	alerts := fd.all()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one dispatch, got %d", len(alerts))
	}
	if !alerts[0].Downgraded {
		t.Fatalf("expected the downgrade verdict to win, got Downgraded=%v Escalated=%v", alerts[0].Downgraded, alerts[0].Escalated)
	}
	if c.pendingLen() != 0 {
		t.Fatalf("pending not cleared after resolution; pending=%d", c.pendingLen())
	}
	if outcome, ok := c.graveyardOutcome(key); !ok || outcome != "downgraded" {
		t.Fatalf("graveyard outcome = %q, ok=%v; want downgraded", outcome, ok)
	}
}

// TestTimeoutFinalizesAfterNoChangeCheck: the in-flight check completes with
// no verdict change. The suspicious finalization must still happen, exactly
// once, only after the check has cleared the singleflight guard.
func TestTimeoutFinalizesAfterNoChangeCheck(t *testing.T) {
	const key = "app.example|GET|/api/.env|200"
	g := &gatedEvidence{
		block:    make(chan struct{}),
		started:  make(chan struct{}),
		decision: EvidenceDecision{}, // no change
	}
	c, fd, cancel := newTestCoordinator(t, g.check, 80*time.Millisecond, 80*time.Millisecond, 10*time.Second)
	defer cancel()

	c.Process(key, suspiciousAlert())
	go c.TryResolveVIP(key)
	<-g.started

	time.Sleep(200 * time.Millisecond)
	if got := fd.count(); got != 0 {
		t.Fatalf("timeout dispatched while check in flight (got %d) — should have deferred", got)
	}

	releaseAt := time.Now()
	close(g.block)
	waitForDispatch(t, fd, 1, 2*time.Second)
	time.Sleep(50 * time.Millisecond)

	alerts := fd.all()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one dispatch, got %d", len(alerts))
	}
	if alerts[0].Downgraded || alerts[0].Escalated {
		t.Fatalf("expected a plain suspicious alert, got Downgraded=%v Escalated=%v", alerts[0].Downgraded, alerts[0].Escalated)
	}
	if fd.at[0].Before(releaseAt) {
		t.Fatalf("suspicious alert dispatched before the check completed — defer was not honored")
	}
	if outcome, ok := c.graveyardOutcome(key); !ok || outcome != "alerted" {
		t.Fatalf("graveyard outcome = %q, ok=%v; want alerted", outcome, ok)
	}
}

// TestTimeoutFinalizesWhenCheckWedged: a check that runs longer than
// MaxEvidenceCheckWait must not hang the investigation — the timeout finalizes
// suspicious once the cap is exceeded, and the late result is dropped without
// a second dispatch.
func TestTimeoutFinalizesWhenCheckWedged(t *testing.T) {
	const key = "app.example|GET|/api/.env|200"
	g := &gatedEvidence{
		block:    make(chan struct{}),
		started:  make(chan struct{}),
		decision: EvidenceDecision{Downgraded: true, Reason: "too late to matter"},
	}
	// Short cap so the wedged check is abandoned quickly.
	c, fd, cancel := newTestCoordinator(t, g.check, 40*time.Millisecond, 40*time.Millisecond, 80*time.Millisecond)
	defer cancel()

	c.Process(key, suspiciousAlert())
	go c.TryResolveVIP(key)
	<-g.started

	// Never released within the cap → timeout must finalize on its own.
	waitForDispatch(t, fd, 1, 2*time.Second)
	alerts := fd.all()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one (suspicious) dispatch, got %d", len(alerts))
	}
	if alerts[0].Downgraded || alerts[0].Escalated {
		t.Fatalf("wedged check should be dropped; expected suspicious, got Downgraded=%v", alerts[0].Downgraded)
	}

	// Release the wedged check now; its late downgrade must NOT double-dispatch.
	close(g.block)
	time.Sleep(80 * time.Millisecond)
	if got := fd.count(); got != 1 {
		t.Fatalf("late check double-dispatched; total alerts=%d", got)
	}
}

// TestTimeoutNoRegressionWhenNoCheckInFlight: the common path. With no check
// in flight at the deadline, the suspicious alert dispatches promptly.
func TestTimeoutNoRegressionWhenNoCheckInFlight(t *testing.T) {
	const key = "app.example|GET|/api/.env|200"
	// Evidence check always returns no change, never blocks.
	g := &gatedEvidence{decision: EvidenceDecision{}}
	c, fd, cancel := newTestCoordinator(t, g.check, 30*time.Millisecond, 30*time.Millisecond, 10*time.Second)
	defer cancel()

	start := time.Now()
	c.Process(key, suspiciousAlert())

	waitForDispatch(t, fd, 1, 2*time.Second)
	elapsed := time.Since(start)

	alerts := fd.all()
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one dispatch, got %d", len(alerts))
	}
	if alerts[0].Downgraded || alerts[0].Escalated {
		t.Fatalf("expected a plain suspicious alert, got Downgraded=%v Escalated=%v", alerts[0].Downgraded, alerts[0].Escalated)
	}
	// No added latency beyond the finalize window + a couple of retry ticks.
	if elapsed > 300*time.Millisecond {
		t.Fatalf("suspicious dispatch took %s — unexpected latency on the common path", elapsed)
	}
	if c.pendingLen() != 0 {
		t.Fatalf("pending not cleared; pending=%d", c.pendingLen())
	}
}

// TestNoDoubleDispatchUnderConcurrentVIP hammers an investigation with
// concurrent VIP pushes while it finalizes. Exactly one alert must be emitted.
func TestNoDoubleDispatchUnderConcurrentVIP(t *testing.T) {
	const key = "app.example|GET|/api/.env|200"
	g := &gatedEvidence{decision: EvidenceDecision{}} // fast no-op checks
	c, fd, cancel := newTestCoordinator(t, g.check, 30*time.Millisecond, 30*time.Millisecond, 10*time.Second)
	defer cancel()

	c.Process(key, suspiciousAlert())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				c.TryResolveVIP(key)
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()

	waitForDispatch(t, fd, 1, 2*time.Second)
	time.Sleep(50 * time.Millisecond)
	if got := fd.count(); got != 1 {
		t.Fatalf("expected exactly one dispatch under concurrent VIP pushes, got %d", got)
	}
}
