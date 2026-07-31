package main

import (
	"testing"
)

func TestLLMScheduler_InUseAndCapacity(t *testing.T) {
	s := NewLLMScheduler(3)
	if got := s.Capacity(); got != 3 {
		t.Errorf("Capacity() = %d, want 3", got)
	}
	if got := s.InUse(); got != 0 {
		t.Errorf("InUse() = %d before any acquire, want 0", got)
	}

	release1, ok := s.TryAcquire()
	if !ok {
		t.Fatal("TryAcquire failed on empty scheduler")
	}
	release2, ok := s.TryAcquire()
	if !ok {
		t.Fatal("second TryAcquire failed with capacity 3")
	}
	if got := s.InUse(); got != 2 {
		t.Errorf("InUse() = %d with two slots held, want 2", got)
	}

	release1()
	if got := s.InUse(); got != 1 {
		t.Errorf("InUse() = %d after one release, want 1", got)
	}
	release2()
	if got := s.InUse(); got != 0 {
		t.Errorf("InUse() = %d after all releases, want 0", got)
	}
}

// Capacity() must reflect the constructor clamp, never the raw config value.
func TestLLMScheduler_CapacityClamp(t *testing.T) {
	for _, raw := range []int{0, -1} {
		s := NewLLMScheduler(raw)
		if got := s.Capacity(); got != 2 {
			t.Errorf("NewLLMScheduler(%d).Capacity() = %d, want clamped 2", raw, got)
		}
	}
}

func TestLLMScheduler_StatsCounters(t *testing.T) {
	s := NewLLMScheduler(1)
	release, ok := s.TryAcquire()
	if !ok {
		t.Fatal("TryAcquire failed on empty scheduler")
	}
	// Saturated: the next TryAcquire is a deferred flight.
	if _, ok := s.TryAcquire(); ok {
		t.Fatal("TryAcquire succeeded on full scheduler")
	}
	release()

	total, dropped := s.Stats()
	if total != 1 {
		t.Errorf("Stats() total = %d, want 1 (successful acquisitions only)", total)
	}
	if dropped != 1 {
		t.Errorf("Stats() dropped = %d, want 1", dropped)
	}
}
