package notifier

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubNotifier is a controllable Notifier for tests. It can block indefinitely
// to simulate slow downstreams (filling the queue), or return errors.
type stubNotifier struct {
	name      string
	calls     atomic.Int64
	block     chan struct{} // when non-nil, Send blocks on this until closed
	returnErr error
}

func (s *stubNotifier) Send(ctx context.Context, alert Alert) error {
	s.calls.Add(1)
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
		}
	}
	return s.returnErr
}

func (s *stubNotifier) Name() string { return s.name }

// newTestDispatcher builds a dispatcher with one stub channel wired in.
// Sidesteps NewDispatcher's env-driven channel detection.
func newTestDispatcher(t *testing.T, n *stubNotifier, rateLimit time.Duration) *Dispatcher {
	t.Helper()
	cfg := &Config{
		Routing: RoutingConfig{
			Malicious:  []string{n.Name()},
			Suspicious: []string{n.Name()},
			Alert:      []string{n.Name()},
		},
	}
	if rateLimit > 0 {
		// Webhook is the simplest channel to wire up in tests.
		cfg.RateLimits.Webhook = rateLimit.String()
	}
	d := &Dispatcher{
		channels: []Notifier{n},
		config:   cfg,
		limiters: make(map[string]*rateLimiter),
		queues:   make(map[string]chan Alert),
		stopCh:   make(chan struct{}),
	}
	q := make(chan Alert, defaultQueueSize)
	d.queues[n.Name()] = q
	d.wg.Add(1)
	go d.runWorker(n, q)
	return d
}

// TestRateLimit_TwoPhase verifies the commit-on-success split that fixes
// the "dropped alert silences next real alert" bug. With the old code,
// a check that returned not-limited also stamped lastSent - so if the
// caller went on to drop the alert (queue full), the stamp was still
// committed and silenced the next legitimate alert.
//
// The fix splits the operation: rateLimitCheck is pure, commitRateLimit
// is called only after successful enqueue. This test exercises the unit
// directly rather than going through a worker, which avoids scheduling
// races.
func TestRateLimit_TwoPhase(t *testing.T) {
	cfg := &Config{}
	cfg.RateLimits.Webhook = "200ms"
	d := &Dispatcher{
		config:   cfg,
		limiters: make(map[string]*rateLimiter),
	}

	// First check: nothing stored yet → not limited.
	limited, key := d.rateLimitCheck("webhook", "alpha", SeveritySuspicious)
	if limited {
		t.Fatal("first check should return not-limited (no prior entry)")
	}
	if key == "" {
		t.Fatal("expected non-empty key on not-limited check")
	}

	// Simulate "enqueue failed" - caller does NOT commit. The bug being
	// fixed is precisely that the old code committed here unconditionally.
	// A second check must still return not-limited.
	limited, _ = d.rateLimitCheck("webhook", "alpha", SeveritySuspicious)
	if limited {
		t.Fatal("second check should still be not-limited - no commit happened in between")
	}

	// Commit the rate-limit (this is what a successful enqueue triggers).
	d.commitRateLimit(key)

	// Now within the interval, the next check must be limited.
	limited, _ = d.rateLimitCheck("webhook", "alpha", SeveritySuspicious)
	if !limited {
		t.Fatal("third check should be limited - we just committed")
	}

	// After the interval elapses, the next check is not-limited again.
	time.Sleep(220 * time.Millisecond)
	limited, _ = d.rateLimitCheck("webhook", "alpha", SeveritySuspicious)
	if limited {
		t.Fatal("after interval, check should be not-limited")
	}
}

// TestRateLimit_DistinctContainersIndependent confirms that container
// names share a channel but each has its own rate-limit slot.
func TestRateLimit_DistinctContainersIndependent(t *testing.T) {
	cfg := &Config{}
	cfg.RateLimits.Webhook = "1m"
	d := &Dispatcher{
		config:   cfg,
		limiters: make(map[string]*rateLimiter),
	}

	_, key := d.rateLimitCheck("webhook", "alpha", SeveritySuspicious)
	d.commitRateLimit(key)

	// beta gets its own slot.
	limited, _ := d.rateLimitCheck("webhook", "beta", SeveritySuspicious)
	if limited {
		t.Fatal("beta should be independent of alpha's rate limit")
	}
}

// TestRateLimit_NoIntervalConfigured returns empty key, no limit.
func TestRateLimit_NoIntervalConfigured(t *testing.T) {
	d := &Dispatcher{
		config:   &Config{}, // empty rate limits
		limiters: make(map[string]*rateLimiter),
	}
	limited, key := d.rateLimitCheck("webhook", "alpha", SeveritySuspicious)
	if limited {
		t.Fatal("no configured interval → never limited")
	}
	if key != "" {
		t.Fatalf("expected empty key when no interval, got %q", key)
	}

	// commitRateLimit with empty key is a no-op (safe to call).
	d.commitRateLimit("")
	if len(d.limiters) != 0 {
		t.Fatalf("commitRateLimit('') must not create an entry; map has %d entries", len(d.limiters))
	}
}

// TestDispatch_ReturnsEnqueuedCount verifies the Notified-honesty fix:
// Dispatch returns the number of channels that accepted the alert, so
// the DB's Notified flag can reflect reality instead of always being true.
func TestDispatch_ReturnsEnqueuedCount(t *testing.T) {
	// Fast-draining stub: Send returns immediately.
	n := &stubNotifier{name: "webhook"}
	d := newTestDispatcher(t, n, 0)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		d.Stop(ctx)
	}()

	got := d.Dispatch(context.Background(), Alert{
		Severity:      SeverityAlert,
		ContainerName: "alpha",
		EventID:       "evt-1",
	})
	if got != 1 {
		t.Errorf("Dispatch returned %d, want 1 (single channel accepted)", got)
	}
}

// TestDispatch_AfterStopReturnsZero confirms post-Stop dispatches are
// silent drops that don't get counted as notified.
func TestDispatch_AfterStopReturnsZero(t *testing.T) {
	n := &stubNotifier{name: "webhook"}
	d := newTestDispatcher(t, n, 0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d.Stop(ctx)

	got := d.Dispatch(context.Background(), Alert{
		Severity:      SeverityAlert,
		ContainerName: "alpha",
		EventID:       "post-stop",
	})
	if got != 0 {
		t.Errorf("Dispatch after Stop returned %d, want 0", got)
	}
}

// TestStop_IsIdempotent confirms multiple Stop() calls are safe (no panic,
// no double-close).
func TestStop_IsIdempotent(t *testing.T) {
	n := &stubNotifier{name: "webhook"}
	d := newTestDispatcher(t, n, 0)

	// Call Stop concurrently from a few goroutines to exercise stopOnce.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			d.Stop(ctx)
		}()
	}
	wg.Wait()

	// One more for good measure - should be a no-op.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d.Stop(ctx)
}

// TestRateLimit_MaliciousBypassesPriorSuspicious verifies that a prior
// suspicious alert on a container never suppresses a later malicious
// alert on the same channel and container within the interval. The
// malicious severity bypasses the limiter entirely.
func TestRateLimit_MaliciousBypassesPriorSuspicious(t *testing.T) {
	n := &stubNotifier{name: "webhook"}
	d := newTestDispatcher(t, n, time.Minute)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		d.Stop(ctx)
	}()

	if got := d.Dispatch(context.Background(), Alert{
		Severity:      SeveritySuspicious,
		ContainerName: "alpha",
		EventID:       "evt-suspicious",
	}); got != 1 {
		t.Fatalf("suspicious Dispatch returned %d, want 1", got)
	}

	if got := d.Dispatch(context.Background(), Alert{
		Severity:      SeverityMalicious,
		ContainerName: "alpha",
		EventID:       "evt-malicious",
	}); got != 1 {
		t.Fatalf("malicious Dispatch within interval returned %d, want 1 (bypass)", got)
	}
}

// TestRateLimit_MaliciousBypassIsUnconditional verifies two back-to-back
// malicious alerts on the same container both dispatch: malicious never
// consults or commits limiter state, so it cannot rate-limit itself.
func TestRateLimit_MaliciousBypassIsUnconditional(t *testing.T) {
	n := &stubNotifier{name: "webhook"}
	d := newTestDispatcher(t, n, time.Minute)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		d.Stop(ctx)
	}()

	for i, id := range []string{"evt-mal-1", "evt-mal-2"} {
		if got := d.Dispatch(context.Background(), Alert{
			Severity:      SeverityMalicious,
			ContainerName: "alpha",
			EventID:       id,
		}); got != 1 {
			t.Fatalf("malicious Dispatch #%d returned %d, want 1", i+1, got)
		}
	}
}

// TestRateLimit_SameSeveritySuppressedAndCounted verifies the limiter
// still applies within a severity, and that a suppression is visible:
// the second suspicious alert within the interval is dropped and the
// rateLimited counter increments (exposed via RateLimitedCount, which
// the stats callback in main.go reads).
func TestRateLimit_SameSeveritySuppressedAndCounted(t *testing.T) {
	n := &stubNotifier{name: "webhook"}
	d := newTestDispatcher(t, n, time.Minute)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		d.Stop(ctx)
	}()

	if got := d.RateLimitedCount(); got != 0 {
		t.Fatalf("RateLimitedCount before any dispatch = %d, want 0", got)
	}

	if got := d.Dispatch(context.Background(), Alert{
		Severity:      SeveritySuspicious,
		ContainerName: "alpha",
		EventID:       "evt-1",
	}); got != 1 {
		t.Fatalf("first suspicious Dispatch returned %d, want 1", got)
	}

	if got := d.Dispatch(context.Background(), Alert{
		Severity:      SeveritySuspicious,
		ContainerName: "alpha",
		EventID:       "evt-2",
	}); got != 0 {
		t.Fatalf("second suspicious Dispatch within interval returned %d, want 0 (suppressed)", got)
	}

	if got := d.RateLimitedCount(); got != 1 {
		t.Fatalf("RateLimitedCount after suppression = %d, want 1", got)
	}
}

// Sanity that stubNotifier.returnErr field is at least addressable -
// unused in current tests but kept on the struct for future cases.
var _ = errors.New
