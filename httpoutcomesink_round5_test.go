// httpoutcomesink_round5_test.go
//
// Round-5 lifecycle coverage: the clauses of the one accepted-observation
// lifecycle that the round-4 gates imply but do not themselves drive.
//
//	TestRound5FailedInFlightAttemptRetriesQueuedSibling — the waiter contract's
//	    failure arm: a sibling that queued behind a RUNNING attempt must fire
//	    when that attempt fails, through the directives NotifyResult returns.
//	TestRound5NoIDPathIsJoinedByShutdown — the stated D8 amendment: the
//	    enabled-but-no-ID commit is registry-accounted, so shutdown joins it.
//	TestRound5ConcurrentLifecycleDrainsEverything — ownership audit under real
//	    concurrency (anchor conflicts, failing notifies, waiters): every parked
//	    entry, every attempt record and every registry entry must drain, and no
//	    observation's row may be written twice.
package main

import (
	"sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/requestcorr"
)

// Spec clause 1, failure arm: an eligible sibling that arrives while an attempt
// is InFlight does not get its own directive — but when that attempt FAILS,
// NotifyResult must hand back a fresh Fire for it. Queuing may never become
// silencing.
func TestRound5FailedInFlightAttemptRetriesQueuedSibling(t *testing.T) {
	s, _ := setupReview()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	attempts := 0
	siblingFired := false

	go func() {
		s.Emit(outcome("anchor", "edge", requestcorr.OutcomeEscalated, func() bool {
			mu.Lock()
			attempts++
			mu.Unlock()
			close(entered)
			<-release
			return false // the enqueue FAILS
		}, func(bool) {}))
		close(done)
	}()
	<-entered

	siblingDone := make(chan struct{})
	go func() {
		s.Emit(outcome("backend", "backend", requestcorr.OutcomeEscalated, func() bool {
			mu.Lock()
			attempts++
			siblingFired = true
			mu.Unlock()
			return true
		}, func(bool) {}))
		close(siblingDone)
	}()
	<-siblingDone // the sibling queued and returned WITHOUT notifying

	mu.Lock()
	if attempts != 1 {
		mu.Unlock()
		t.Fatalf("sibling must queue behind the running attempt, not open a second: attempts=%d, want 1", attempts)
	}
	mu.Unlock()

	close(release)
	<-done

	mu.Lock()
	defer mu.Unlock()
	if attempts != 2 || !siblingFired {
		t.Fatalf("failed in-flight attempt must re-fire the queued sibling: attempts=%d siblingFired=%v, want 2/true", attempts, siblingFired)
	}
	if s.tracker.Notified(reviewLineageID) != true {
		t.Fatalf("the retry succeeded; the incident's ledger must record it")
	}
}

// The D8 amendment, asserted rather than assumed: with the feature ON and no
// trusted ID, Emit still commits synchronously — and that commit is registered,
// so Shutdown cannot return while it is still inside the finding write.
func TestRound5NoIDPathIsJoinedByShutdown(t *testing.T) {
	s, _ := setupReview()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		o := outcome("noid", "backend", requestcorr.OutcomeRecon, nil, func(bool) { close(entered); <-release })
		o.rawLine = rawNoVgrid // enabled, but nothing to correlate on
		s.Emit(o)
		close(done)
	}()
	<-entered

	stopped := make(chan struct{})
	go func() { s.Shutdown(); close(stopped) }()
	early := false
	select {
	case <-stopped:
		early = true
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	<-done
	<-stopped
	if early {
		t.Fatal("Shutdown returned while an enabled-but-no-ID commit was still writing its finding")
	}
	if s.missingIDs.Load() != 1 {
		t.Errorf("missing_ids_total = %d, want 1", s.missingIDs.Load())
	}
}

// Ownership audit under real concurrency. Three lineages that anchor exactly
// once (so siblings really do queue behind a running attempt) plus one lineage
// whose repeated anchors poison it; notifies that block and sometimes fail;
// then an ordered shutdown. Afterwards the sink must own NOTHING: no parked
// closure, no attempt record, no registry entry. And no accepted observation
// may have written its row more than once.
func TestRound5ConcurrentLifecycleDrainsEverything(t *testing.T) {
	s, _ := setupReview()
	clk := &manualClock{t: time.Unix(1700000000, 0)}
	s.tracker = requestcorr.New(requestcorr.Config{}, clk)

	anchored := []string{
		"2fb2cf19c82b36ceb7f89d50b381fcf1",
		"d222b0a4b75f01a12a7c1c4d2174cd2c",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	const poisonID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	outcomes := []requestcorr.Outcome{
		requestcorr.OutcomeRecon, requestcorr.OutcomeUnresolved,
		requestcorr.OutcomeEscalated, requestcorr.OutcomeEscalated,
	}

	var mu sync.Mutex
	writes := map[string]int{}

	// Each entry is one accepted observation: (lineage, source). The first three
	// are the single anchor for each anchored lineage; the rest are downstream
	// siblings, except the poison lane, which anchors repeatedly on purpose.
	type obsPlan struct{ id, src string }
	var plan []obsPlan
	for _, id := range anchored {
		plan = append(plan, obsPlan{id, "edge"})
	}
	for i := 0; len(plan) < 150; i++ {
		switch i % 5 {
		case 4:
			plan = append(plan, obsPlan{poisonID, "edge"}) // duplicate anchors ⇒ poison
		default:
			plan = append(plan, obsPlan{anchored[i%len(anchored)], "backend"})
		}
	}

	// A settler running CONCURRENTLY with the producers, exactly as Run drives
	// it: transitions under the lock (registered in the same critical section),
	// callbacks applied outside it. This is what makes terminal dispositions
	// land on observations whose notification is still in flight or queued.
	settlerStop := make(chan struct{})
	settlerDone := make(chan struct{})
	go func() {
		defer close(settlerDone)
		for {
			select {
			case <-settlerStop:
				return
			default:
			}
			clk.advance(4 * time.Second)
			s.mu.Lock()
			ds := s.tracker.Tick()
			s.selectLocked(ds)
			s.mu.Unlock()
			s.apply(ds)
			time.Sleep(200 * time.Microsecond)
		}
	}()

	var wg sync.WaitGroup
	for i, pl := range plan {
		wg.Add(1)
		go func(i int, pl obsPlan) {
			defer wg.Done()
			ev := "ev" + itoa(i)
			o := outcome(ev, pl.src, outcomes[i%len(outcomes)],
				func() bool {
					time.Sleep(time.Millisecond) // hold the attempt open
					return i%3 != 0              // and sometimes fail it
				},
				func(bool) { mu.Lock(); writes[ev]++; mu.Unlock() })
			o.rawLine = "x vgrid=" + pl.id
			s.Emit(o)
		}(i, pl)
	}
	wg.Wait()
	close(settlerStop)
	<-settlerDone
	s.Shutdown()

	s.mu.Lock()
	parked, attempts, work := len(s.parked), len(s.attempts), len(s.work)
	s.mu.Unlock()
	if parked != 0 || attempts != 0 || work != 0 {
		t.Fatalf("sink still owns work after Shutdown: parked=%d attempts=%d registry=%d", parked, attempts, work)
	}

	mu.Lock()
	defer mu.Unlock()
	total := 0
	for ev, c := range writes {
		if c != 1 {
			t.Fatalf("event %s wrote %d finding rows, want exactly 1", ev, c)
		}
		total += c
	}
	if total == 0 || total > len(plan) {
		t.Fatalf("rows written = %d, want 1..%d", total, len(plan))
	}
}
