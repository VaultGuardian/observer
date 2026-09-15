// httpoutcomesink_round5_combo_test.go
//
// Adversarial round-5 review combination tests, adopted verbatim (drivers and
// assertions unchanged) from the reviewer's lineage_round5_combinations_test.go.
// They reuse setupReview/outcome/reviewLineageID from
// httpoutcomesink_review_test.go and manualClock from httpoutcomesink_test.go.
//
// Each drives one lifecycle COMBINATION — two live attempts at once — which the
// round-5 single-slot ledger could not represent, and which the round-6
// per-attempt model exists to fix:
//
//	TestRound5IndependentPendingNotifiesSurviveSettle     — Fix A: a superseded
//	    pre-anchor token must not orphan its closure; both independents notify
//	TestRound5SettledRepresentativeFollowsRetryResult     — Fix B1: a failed
//	    attempt hands its dependent row to the retry, never resolves it early
//	TestRound5DeferredWriteCannotBlockNotificationRetry   — Fix B2: an eligible
//	    retry runs before blocking row persistence in the same drain
//	TestRound5AnchorAdoptionWaitsForOlderIndependentAttempt — Fix B3: incident
//	    truth spans every accepted attempt, not just the last token minted
//
// They are part of the permanent suite and must stay green. The permutation
// suite in httpoutcomesink_permutation_test.go proves the surrounding space.
package main

import (
	"github.com/vaultguardian/observer/internal/requestcorr"
	"sync/atomic"
	"testing"
	"time"
)

// Pause each Emit at its actual post-selection boundary, keeping the registry
// registration that production performs. No coordinator/heuristic changes.
func TestRound5IndependentPendingNotifiesSurviveSettle(t *testing.T) {
	s, c := setupReview()
	var notified, writes int
	var batches [][]requestcorr.Directive
	for _, ev := range []string{"backend1", "backend2"} {
		s.mu.Lock()
		s.parked[ev] = &parkedOutcome{notify: func() bool { notified++; return true }, writeFinding: func(bool) { writes++ }, lineageID: reviewLineageID, sev: requestcorr.SevActionable}
		ds := s.tracker.Observe(requestcorr.Observation{LineageID: reviewLineageID, Source: "backend", EventID: ev, Outcome: requestcorr.OutcomeEscalated})
		s.selectLocked(ds)
		s.mu.Unlock()
		batches = append(batches, ds)
	}
	c.t = c.t.Add(4 * time.Second)
	s.mu.Lock()
	ds := s.tracker.Tick()
	s.selectLocked(ds)
	s.mu.Unlock()
	s.apply(ds)
	for _, b := range batches {
		s.apply(b)
	}
	if notified != 2 || writes != 2 {
		t.Fatalf("unanchored independent observations: notifications=%d writes=%d, want 2/2", notified, writes)
	}
}

func TestRound5SettledRepresentativeFollowsRetryResult(t *testing.T) {
	s, _ := setupReview()
	clk := &manualClock{t: time.Unix(1700000000, 0)}
	s.tracker = requestcorr.New(requestcorr.Config{}, clk)
	enteredA, releaseA, enteredB, releaseB, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var wrote atomic.Int32
	var notified atomic.Bool
	go func() {
		s.Emit(outcome("anchor", "edge", requestcorr.OutcomeEscalated, func() bool { close(enteredA); <-releaseA; return false }, func(n bool) { notified.Store(n); wrote.Add(1) }))
		close(done)
	}()
	<-enteredA
	s.Emit(outcome("backend", "backend", requestcorr.OutcomeEscalated, func() bool { close(enteredB); <-releaseB; return true }, func(bool) {}))
	clk.advance(4 * time.Second)
	s.mu.Lock()
	ds := s.tracker.Tick()
	s.selectLocked(ds)
	s.mu.Unlock()
	s.apply(ds)
	close(releaseA)
	<-enteredB
	early := wrote.Load()
	close(releaseB)
	<-done
	if early != 0 || wrote.Load() != 1 || !notified.Load() {
		t.Fatalf("representative retry: writes before retry result=%d final writes=%d Notified=%v; want 0/1/true", early, wrote.Load(), notified.Load())
	}
}

func TestRound5DeferredWriteCannotBlockNotificationRetry(t *testing.T) {
	s, _ := setupReview()
	clk := &manualClock{t: time.Unix(1700000000, 0)}
	s.tracker = requestcorr.New(requestcorr.Config{}, clk)
	enteredA, releaseA, writing, releaseWrite, retried, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		s.Emit(outcome("anchor", "edge", requestcorr.OutcomeEscalated, func() bool { close(enteredA); <-releaseA; return false }, func(bool) { close(writing); <-releaseWrite }))
		close(done)
	}()
	<-enteredA
	s.Emit(outcome("backend", "backend", requestcorr.OutcomeEscalated, func() bool { close(retried); return true }, func(bool) {}))
	clk.advance(4 * time.Second)
	s.mu.Lock()
	ds := s.tracker.Tick()
	s.selectLocked(ds)
	s.mu.Unlock()
	s.apply(ds)
	close(releaseA)
	select {
	case <-writing:
	case <-retried:
	}
	blocked := false
	select {
	case <-retried:
	case <-time.After(200 * time.Millisecond):
		blocked = true
	}
	close(releaseWrite)
	<-done
	if blocked {
		t.Fatal("retry notification could not execute until the previous attempt's deferred finding write unblocked")
	}
}

// Backend-first traffic can have more than one independent callback running
// before the anchor arrives. Anchoring must not forget an older live success.
func TestRound5AnchorAdoptionWaitsForOlderIndependentAttempt(t *testing.T) {
	s, _ := setupReview()
	clk := &manualClock{t: time.Unix(1700000000, 0)}
	s.tracker = requestcorr.New(requestcorr.Config{}, clk)
	aEntered, aRelease, aDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	bEntered, bRelease, bDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var wrote atomic.Int32
	var notified atomic.Bool
	go func() {
		s.Emit(outcome("backend-a", "backend", requestcorr.OutcomeEscalated, func() bool { close(aEntered); <-aRelease; return true }, func(n bool) { notified.Store(n); wrote.Add(1) }))
		close(aDone)
	}()
	<-aEntered
	go func() {
		s.Emit(outcome("backend-b", "backend", requestcorr.OutcomeEscalated, func() bool { close(bEntered); <-bRelease; return false }, func(bool) {}))
		close(bDone)
	}()
	<-bEntered
	s.Emit(outcome("anchor", "edge", requestcorr.OutcomeRecon, nil, func(bool) {}))
	clk.advance(4 * time.Second)
	s.mu.Lock()
	ds := s.tracker.Tick()
	s.selectLocked(ds)
	s.mu.Unlock()
	s.apply(ds)
	close(bRelease)
	<-bDone
	beforeOlder := wrote.Load()
	close(aRelease)
	<-aDone
	if beforeOlder != 0 || wrote.Load() != 1 || !notified.Load() {
		t.Fatalf("anchor adoption: writes before older result=%d final writes=%d Notified=%v; want 0/1/true", beforeOlder, wrote.Load(), notified.Load())
	}
}
