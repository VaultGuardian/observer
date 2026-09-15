// httpoutcomesink_round2_test.go
//
// Adversarial round-2 review acceptance tests (R2-1..R2-4), adopted into the
// permanent suite from the reviewer's lineage_round2_additional_test.go. They
// reuse setupReview/outcome/settle from httpoutcomesink_review_test.go.
//
//	R2-1 TestRound2FailedNotifyRetriesAfterSettle    — late notify retry after settle
//	R2-4 TestRound2LateUpgradeAdvancesWatermark      — monotonic high-water baseline
//	R2-2 TestRound2BlockedWriteMustNotBlockUnrelatedNotify — no callback under the lock
//	R2-3 TestRound2ShutdownWaitsForAcceptedLateEmit  — shutdown joins in-flight Emits
//
// Behavioral assertions are preserved verbatim. The R2-2 driver is adapted to
// the round-4 ownership model (locks cover decisions, apply runs callbacks
// lock-free), per the reviewer's explicit license to adapt white-box mechanics.
package main

import (
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/requestcorr"
)

func TestRound2FailedNotifyRetriesAfterSettle(t *testing.T) {
	s, c := setupReview()
	attempts := 0
	s.Emit(outcome("anchor", "edge", requestcorr.OutcomeEscalated, func() bool { attempts++; return false }, func(bool) {}))
	settle(s, c)
	s.Emit(outcome("late", "backend", requestcorr.OutcomeEscalated, func() bool { attempts++; return true }, func(bool) {}))
	if attempts != 2 {
		t.Fatalf("failed first enqueue followed by late actionable sibling: attempts=%d, want 2", attempts)
	}
}

func TestRound2LateUpgradeAdvancesWatermark(t *testing.T) {
	s, c := setupReview()
	malicious, unresolved := 0, 0
	s.Emit(outcome("anchor", "edge", requestcorr.OutcomeRecon, nil, func(bool) {}))
	settle(s, c)
	for _, id := range []string{"late1", "late2", "late3"} {
		s.Emit(outcome(id, "backend", requestcorr.OutcomeEscalated, func() bool { return true }, func(bool) { malicious++ }))
	}
	s.Emit(outcome("late-lower", "backend", requestcorr.OutcomeUnresolved, nil, func(bool) { unresolved++ }))
	if malicious != 1 || unresolved != 0 {
		t.Fatalf("after first durable escalation: malicious rows=%d unresolved rows=%d; want 1 and 0", malicious, unresolved)
	}
}

func TestRound2BlockedWriteMustNotBlockUnrelatedNotify(t *testing.T) {
	s, c := setupReview()
	entered, release, settled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.Emit(outcome("safe-anchor", "edge", requestcorr.OutcomeUnresolved, nil, func(bool) { close(entered); <-release }))
	c.t = c.t.Add(4 * time.Second)
	// Round-4 ownership model: take the tracker transition under the lock, then
	// apply OUTSIDE it (apply runs the blocking writeFinding lock-free).
	go func() {
		s.mu.Lock()
		ds := s.tracker.Tick()
		s.mu.Unlock()
		s.apply(ds)
		close(settled)
	}()
	<-entered
	notified, done := make(chan struct{}), make(chan struct{})
	go func() {
		o := outcome("unrelated", "edge", requestcorr.OutcomeEscalated, func() bool { close(notified); return true }, func(bool) {})
		o.rawLine = "x vgrid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		s.Emit(o)
		close(done)
	}()
	blocked := false
	select {
	case <-notified:
	case <-time.After(300 * time.Millisecond):
		blocked = true
	}
	close(release)
	<-settled
	<-done
	if blocked {
		t.Fatal("unrelated actionable notification was blocked for duration of another group's write callback")
	}
}

func TestRound2ShutdownWaitsForAcceptedLateEmit(t *testing.T) {
	s, _ := setupReview()
	s.finishDrain()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		s.Emit(outcome("late", "edge", requestcorr.OutcomeEscalated, func() bool { close(entered); <-release; return true }, func(bool) {}))
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
		t.Fatal("Shutdown returned while an already-entered late Emit still had its finding write ahead of it")
	}
}
