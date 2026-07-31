// Package health holds process-level pipeline capacity and loss telemetry.
// It is read-only observability: nothing in this package influences routing,
// classification, eviction, dispatch, learning, or cap decisions.
//
// The package is stdlib-only so both main and internal/api can import it
// without creating an import cycle.
package health

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"sync/atomic"
	"time"
)

// Stats holds main-owned counters for the ingestion pipeline and retry queue,
// plus a process-run identity (stats epoch and start time) that identifies
// the process run for all pipeline_health telemetry. The dashboard discards
// baselines when the epoch changes.
type Stats struct {
	statsEpoch       string
	startedAt        time.Time
	pipelineCapacity int
	retryCapacity    int

	pipelineHighWater    atomic.Int64
	pipelineDropped      atomic.Int64
	retryDropped         atomic.Int64
	retryLastQueueWaitMs atomic.Int64
	retryMaxQueueWaitMs  atomic.Int64
}

// Snapshot is a plain value copy of Stats suitable for rendering.
type Snapshot struct {
	StatsEpoch           string
	StartedAt            time.Time
	PipelineCapacity     int
	PipelineHighWater    int64
	PipelineDropped      int64
	RetryCapacity        int
	RetryLastQueueWaitMs int64
	RetryMaxQueueWaitMs  int64
	RetryDropped         int64
}

// RuntimeSnapshot carries live values the API server cannot reach directly:
// channel depths sampled at snapshot time plus scheduler and coordinator
// state owned by main.
type RuntimeSnapshot struct {
	PipelineDepth                int
	RetryDepth                   int
	SchedulerInUse               int
	SchedulerCapacity            int
	SchedulerCalls               int64
	SchedulerDeferred            int64
	CoordinatorPending           int
	CoordinatorCapacity          int
	CoordinatorCapacityEvictions int64
}

// NewStats constructs the process-run stats. The epoch is a random ID
// generated once per process; capacities are static and set here so the
// API layer never hard-codes buffer sizes.
func NewStats(pipelineCapacity, retryCapacity int) *Stats {
	return &Stats{
		statsEpoch:       newEpoch(),
		startedAt:        time.Now().UTC(),
		pipelineCapacity: pipelineCapacity,
		retryCapacity:    retryCapacity,
	}
}

func newEpoch() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is effectively unheard of; fall back to a
		// timestamp-derived ID rather than aborting startup.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// ObservePipelineDepth records the observed pipeline channel depth,
// keeping a monotonic high-water mark via a CAS-max loop.
func (s *Stats) ObservePipelineDepth(depth int) {
	casMax(&s.pipelineHighWater, int64(depth))
}

// RecordPipelineDrop counts a failed pipeline enqueue. A drop proves the
// channel was saturated, so the high-water mark is raised to capacity.
func (s *Stats) RecordPipelineDrop() {
	s.pipelineDropped.Add(1)
	s.ObservePipelineDepth(s.pipelineCapacity)
}

// RecordRetryDrop counts a failed retry-queue enqueue.
func (s *Stats) RecordRetryDrop() {
	s.retryDropped.Add(1)
}

// RecordRetryWait records how long an event sat in the retry channel from
// enqueue to worker dequeue. This measures retry-channel residence only;
// it does NOT include the subsequent blocking wait for an LLM slot inside
// AnalyzeRetry. Negative waits (clock adjustments) clamp to zero.
func (s *Stats) RecordRetryWait(wait time.Duration) {
	ms := wait.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	s.retryLastQueueWaitMs.Store(ms)
	casMax(&s.retryMaxQueueWaitMs, ms)
}

// PipelineDrops returns the total failed pipeline enqueues.
func (s *Stats) PipelineDrops() int64 {
	return s.pipelineDropped.Load()
}

// RetryDrops returns the total failed retry-queue enqueues.
func (s *Stats) RetryDrops() int64 {
	return s.retryDropped.Load()
}

// Snapshot returns a plain value copy of the current stats.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		StatsEpoch:           s.statsEpoch,
		StartedAt:            s.startedAt,
		PipelineCapacity:     s.pipelineCapacity,
		PipelineHighWater:    s.pipelineHighWater.Load(),
		PipelineDropped:      s.pipelineDropped.Load(),
		RetryCapacity:        s.retryCapacity,
		RetryLastQueueWaitMs: s.retryLastQueueWaitMs.Load(),
		RetryMaxQueueWaitMs:  s.retryMaxQueueWaitMs.Load(),
		RetryDropped:         s.retryDropped.Load(),
	}
}

// casMax raises v to candidate if candidate is larger, race-safely.
func casMax(v *atomic.Int64, candidate int64) {
	for {
		cur := v.Load()
		if candidate <= cur {
			return
		}
		if v.CompareAndSwap(cur, candidate) {
			return
		}
	}
}
