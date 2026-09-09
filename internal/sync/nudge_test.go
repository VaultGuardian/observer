package sync

import (
	"context"
	"testing"
	"time"
)

// =============================================================================
// Lane C -> lanes A/B nudges
// =============================================================================
//
// Executing a hosted command changes local state that the dashboard is waiting
// to see. Without the nudge the operator watches a pending banner for up to a
// full lane A interval (or five minutes for a snapshot-visible change), which
// is why the select arms in lanes A and B exist. These tests drive the real
// goroutines: a select case nothing exercises is a select case that can be
// silently wrong.

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A nudge wakes lane A immediately, well inside its configured interval.
func TestNudgeWakesLaneA(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)

	e := newTestEngine(t, st, ingest)
	e.cfg.Interval = time.Hour // the timer must not be what delivers this

	insertFindings(t, st, 3, "nudge")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runLaneA(ctx)
	}()

	// Nothing should move on its own with an hour-long interval.
	time.Sleep(50 * time.Millisecond)
	if posts := ingest.postsTo(pathFindings); len(posts) != 0 {
		t.Fatalf("findings POSTs before the nudge = %d; want 0", len(posts))
	}

	e.nudgeOutbound()

	waitFor(t, "lane A to push after a nudge", func() bool {
		return len(ingest.postsTo(pathFindings)) > 0
	})

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("lane A did not exit after cancellation")
	}
}

// The same for lane B's snapshot loop, whose clock is five minutes in
// production - far too slow to confirm an operator's click.
func TestNudgeWakesLaneBSnapshot(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	local := newFakeLocalAPI(t)

	e := newLaneBEngine(t, st, ingest, local.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.runSnapshot(ctx)
	}()

	// runSnapshot sends one immediately on start.
	waitFor(t, "the initial snapshot", func() bool {
		return len(ingest.postsTo(pathIngestSnapshot)) >= 1
	})

	e.nudgeOutbound()

	waitFor(t, "a second snapshot after the nudge", func() bool {
		return len(ingest.postsTo(pathIngestSnapshot)) >= 2
	})

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("lane B snapshot did not exit after cancellation")
	}
}

// The channels are hints, not a queue: a nudge that nobody is listening for
// must never block lane C, however many times it fires.
func TestNudgeNeverBlocks(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	e := newTestEngine(t, st, ingest)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			e.nudgeOutbound()
		}
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("nudgeOutbound blocked with nobody reading the channels")
	}

	// Only one of each is queued: the pass a nudge triggers sees every
	// command's effect, so coalescing them is exactly right.
	if dirty, snapshot := drainNudges(e); dirty != 1 || snapshot != 1 {
		t.Errorf("queued nudges = (%d, %d); want one of each", dirty, snapshot)
	}
}

// Shutdown must not race the nudge channels. They are never closed precisely so
// a lane C that stops first cannot panic a lane still selecting on them.
func TestNudgeDuringShutdown(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	e := newTestEngine(t, st, ingest)

	ctx, cancel := context.WithCancel(context.Background())
	e.Start(ctx)

	for i := 0; i < 50; i++ {
		e.nudgeOutbound()
	}
	cancel()
	e.Stop()

	// Still usable afterwards - no closed-channel panic.
	e.nudgeOutbound()
}
