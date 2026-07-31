package health

import (
	"sync"
	"testing"
	"time"
)

func TestNewStats_Identity(t *testing.T) {
	s := NewStats(1000, 500)
	snap := s.Snapshot()

	if len(snap.StatsEpoch) != 16 {
		t.Errorf("stats epoch length = %d, want 16 hex chars: %q", len(snap.StatsEpoch), snap.StatsEpoch)
	}
	for _, c := range snap.StatsEpoch {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Errorf("stats epoch contains non-hex char %q: %q", c, snap.StatsEpoch)
		}
	}
	if snap.StartedAt.IsZero() {
		t.Error("started_at is zero")
	}
	if snap.PipelineCapacity != 1000 || snap.RetryCapacity != 500 {
		t.Errorf("capacities = (%d, %d), want (1000, 500)", snap.PipelineCapacity, snap.RetryCapacity)
	}

	// Two process runs must not share an epoch.
	if other := NewStats(1, 1); other.Snapshot().StatsEpoch == snap.StatsEpoch {
		t.Error("two Stats instances share the same epoch")
	}
}

func TestObservePipelineDepth_Monotonic(t *testing.T) {
	s := NewStats(100, 10)
	s.ObservePipelineDepth(7)
	s.ObservePipelineDepth(3)
	if hw := s.Snapshot().PipelineHighWater; hw != 7 {
		t.Errorf("high water = %d after observing 7 then 3, want 7", hw)
	}
	s.ObservePipelineDepth(9)
	if hw := s.Snapshot().PipelineHighWater; hw != 9 {
		t.Errorf("high water = %d after observing 9, want 9", hw)
	}
}

func TestRecordPipelineDrop_SetsHighWaterToCapacity(t *testing.T) {
	s := NewStats(1000, 10)
	s.ObservePipelineDepth(12)
	s.RecordPipelineDrop()
	snap := s.Snapshot()
	if snap.PipelineDropped != 1 {
		t.Errorf("pipeline dropped = %d, want 1", snap.PipelineDropped)
	}
	// A drop proves saturation: high water jumps to capacity even though no
	// depth observation ever reached it.
	if snap.PipelineHighWater != 1000 {
		t.Errorf("high water after drop = %d, want capacity 1000", snap.PipelineHighWater)
	}
	if s.PipelineDrops() != 1 {
		t.Errorf("PipelineDrops() = %d, want 1", s.PipelineDrops())
	}
}

func TestRecordRetryDrop(t *testing.T) {
	s := NewStats(10, 10)
	s.RecordRetryDrop()
	s.RecordRetryDrop()
	if got := s.RetryDrops(); got != 2 {
		t.Errorf("RetryDrops() = %d, want 2", got)
	}
	if got := s.Snapshot().RetryDropped; got != 2 {
		t.Errorf("snapshot retry dropped = %d, want 2", got)
	}
}

func TestRecordRetryWait_LastAndMax(t *testing.T) {
	s := NewStats(10, 10)
	s.RecordRetryWait(250 * time.Millisecond)
	s.RecordRetryWait(100 * time.Millisecond)
	snap := s.Snapshot()
	if snap.RetryLastQueueWaitMs != 100 {
		t.Errorf("last wait = %d ms, want 100 (plain store of most recent)", snap.RetryLastQueueWaitMs)
	}
	if snap.RetryMaxQueueWaitMs != 250 {
		t.Errorf("max wait = %d ms, want 250 (CAS-max)", snap.RetryMaxQueueWaitMs)
	}

	// Negative waits (clock adjustment) clamp to zero rather than corrupting
	// the last value or the max.
	s.RecordRetryWait(-5 * time.Second)
	snap = s.Snapshot()
	if snap.RetryLastQueueWaitMs != 0 {
		t.Errorf("last wait after negative = %d ms, want 0", snap.RetryLastQueueWaitMs)
	}
	if snap.RetryMaxQueueWaitMs != 250 {
		t.Errorf("max wait after negative = %d ms, want 250", snap.RetryMaxQueueWaitMs)
	}
}

// TestCASMax_RaceSafe hammers the CAS-max path from many goroutines and
// asserts the final high water equals the global maximum observed depth.
// Run under -race this also proves the loop is data-race free.
func TestCASMax_RaceSafe(t *testing.T) {
	s := NewStats(1_000_000, 10)
	const goroutines = 16
	const perG = 1000

	var wg sync.WaitGroup
	globalMax := 0
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		base := g * perG
		if base+perG > globalMax {
			globalMax = base + perG
		}
		go func(base int) {
			defer wg.Done()
			for i := 1; i <= perG; i++ {
				s.ObservePipelineDepth(base + i)
			}
		}(base)
	}
	wg.Wait()

	if hw := s.Snapshot().PipelineHighWater; hw != int64(globalMax) {
		t.Errorf("high water = %d, want global max %d", hw, globalMax)
	}
}
