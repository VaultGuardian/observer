package main

import (
	"github.com/vaultguardian/observer/internal/requestcorr"
	"sync/atomic"
	"testing"
)

func TestClosureReviewPoisonPreservesQueuedRetry(t *testing.T) {
	s, _ := setupReview()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var attempts, successes, rows atomic.Int32
	go func() {
		s.Emit(outcome("anchor", "edge", requestcorr.OutcomeEscalated, func() bool {
			attempts.Add(1)
			close(entered)
			<-release
			return false
		}, func(bool) { rows.Add(1) }))
		close(done)
	}()
	<-entered
	s.Emit(outcome("queued", "backend", requestcorr.OutcomeEscalated, func() bool {
		attempts.Add(1)
		successes.Add(1)
		return true
	}, func(bool) { rows.Add(1) }))
	s.Emit(outcome("duplicate-anchor", "edge", requestcorr.OutcomeRecon, nil, func(bool) { rows.Add(1) }))
	close(release)
	<-done
	s.Shutdown()
	if successes.Load() != 1 || attempts.Load() != 2 || rows.Load() != 3 {
		t.Fatalf("duplicate-anchor fail-open: attempts=%d successes=%d rows=%d; want 2/1/3", attempts.Load(), successes.Load(), rows.Load())
	}
}
