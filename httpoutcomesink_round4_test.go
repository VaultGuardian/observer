// httpoutcomesink_round4_test.go
//
// Adversarial round-4 review acceptance tests, adopted verbatim (assertions and
// drivers unchanged) from the reviewer's lineage_round4_additional_test.go. They
// reuse setupReview/outcome from httpoutcomesink_review_test.go and manualClock
// from httpoutcomesink_test.go.
//
// Each one is the behavioral gate for one clause of the round-5 lifecycle
// (see the httpoutcomesink.go header and requestcorr's package doc):
//
//	TestRound4PendingNotifySurvivesTick    — a terminal claim TRANSFERS pending
//	                                         notification work, never discards it
//	TestRound4ConcurrentSiblingsNotifyOnce — lineage-scoped attempt reservation:
//	                                         a sibling queues, it does not fire
//	TestRound4NotifiedReflectsInFlightResult — a representative row waits for the
//	                                         in-flight attempt's real outcome
//	TestRound4ShutdownJoinsTickWrites      — the registry covers Tick-owned work
//	                                         and Shutdown joins the Run loop
//
// They are part of the permanent suite and must stay green. The concurrency
// drivers force a legal schedule deliberately; a sequential happy-path
// replacement would not be equivalent coverage.
package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/requestcorr"
)

// This schedules the existing unlock-after-Observe / lock-in-apply boundary.
// A sibling does not get its own fresh three-second settlement interval.
func TestRound4PendingNotifySurvivesTick(t *testing.T) {
	s, c := setupReview()
	var notifications int
	s.Emit(outcome("anchor", "edge", requestcorr.OutcomeRecon, nil, func(bool) {}))
	c.t = c.t.Add(requestcorr.DefaultSettleWindow)
	id := "2fb2cf19c82b36ceb7f89d50b381fcf1"
	s.mu.Lock()
	s.parked["backend"] = &parkedOutcome{notify: func() bool { notifications++; return true }, writeFinding: func(bool) {}, lineageID: id, sev: requestcorr.SevActionable}
	ds := s.tracker.Observe(requestcorr.Observation{LineageID: id, Source: "backend", EventID: "backend", Outcome: requestcorr.OutcomeEscalated})
	s.mu.Unlock()
	s.mu.Lock()
	terminal := s.tracker.Tick()
	s.mu.Unlock()
	s.apply(terminal)
	s.apply(ds)
	if notifications != 1 {
		t.Fatalf("Observe -> Tick/apply -> pending apply: notifications=%d, want 1", notifications)
	}
}

func TestRound4ConcurrentSiblingsNotifyOnce(t *testing.T) {
	s, _ := setupReview()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	go func() {
		s.Emit(outcome("anchor", "edge", requestcorr.OutcomeEscalated, func() bool { attempts.Add(1); close(entered); <-release; return true }, func(bool) {}))
		close(done)
	}()
	<-entered
	siblingDone := make(chan struct{})
	go func() {
		s.Emit(outcome("backend", "backend", requestcorr.OutcomeEscalated, func() bool { attempts.Add(1); return true }, func(bool) {}))
		close(siblingDone)
	}()
	select {
	case <-siblingDone:
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	<-done
	<-siblingDone
	if got := attempts.Load(); got != 1 {
		t.Fatalf("one anchored lineage, overlapping successful notification callbacks: attempts=%d, want 1", got)
	}
}

func TestRound4NotifiedReflectsInFlightResult(t *testing.T) {
	s, _ := setupReview()
	clk := &manualClock{t: time.Unix(1700000000, 0)}
	s.tracker = requestcorr.New(requestcorr.Config{}, clk)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	var persistedNotified atomic.Bool
	go func() {
		s.Emit(outcome("anchor", "edge", requestcorr.OutcomeEscalated, func() bool { close(entered); <-release; return true }, func(n bool) { persistedNotified.Store(n); writes.Add(1) }))
		close(done)
	}()
	<-entered
	clk.advance(4 * time.Second)
	s.mu.Lock()
	ds := s.tracker.Tick()
	s.mu.Unlock()
	tickDone := make(chan struct{})
	go func() { s.apply(ds); close(tickDone) }()
	select {
	case <-tickDone:
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	<-done
	<-tickDone
	if writes.Load() != 1 || !persistedNotified.Load() {
		t.Fatalf("successful notify after concurrent settle: writes=%d Notified=%v, want 1/true", writes.Load(), persistedNotified.Load())
	}
}

func TestRound4ShutdownJoinsTickWrites(t *testing.T) {
	s := newHTTPOutcomeSink(Config{LineageEnabled: true, LineageAnchorSources: map[string]bool{"edge": true}})
	s.tracker = requestcorr.New(requestcorr.Config{SettleWindow: time.Millisecond}, nil)
	s.tickInterval = time.Millisecond
	entered, release, runDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.Emit(outcome("anchor", "edge", requestcorr.OutcomeUnresolved, nil, func(bool) { close(entered); <-release }))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { s.Run(ctx); close(runDone) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("tick did not begin write")
	}
	cancel()
	shutdownDone := make(chan struct{})
	go func() { s.Shutdown(); close(shutdownDone) }()
	early := false
	select {
	case <-shutdownDone:
		early = true
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	<-runDone
	<-shutdownDone
	if early {
		t.Fatal("Shutdown returned while Run/Tick still executed an accepted finding's write callback")
	}
}
