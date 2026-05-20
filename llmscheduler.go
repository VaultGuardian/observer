package main

import (
	"context"
	"sync/atomic"
)

// =============================================================================
// LLM Scheduler — Global Concurrency Control for All LLM Call Sites
// =============================================================================
//
// PROBLEM:
//   Tier 1 classification had a semaphore. Tier 2 reclassification and
//   catch-all verification did not. Under load, T2 and catch-all calls
//   could run unbounded while T1 was being throttled — defeating the
//   purpose of concurrency control.
//
// SOLUTION:
//   One shared semaphore for ALL LLM calls. Priority is achieved through
//   acquire semantics:
//     - T2 evidence reclassification: BLOCKING acquire (rare, high value)
//     - Catch-all verification: BLOCKING acquire (once per fingerprint lifetime, no retry)
//     - T1 classification: NON-BLOCKING try-acquire (drop if full)
//
//   T2 and catch-all calls are rare (~3-5/week each at current scanner rates)
//   so blocking won't starve T1. T1 drops are safe because the line stays
//   VerdictUnknown and will be re-classified on next occurrence.
//
// DESIGN DECISION (the team, April 2026):
//   All LLM calls must flow through a single scheduler.

// LLMScheduler controls concurrent access to the LLM inference server.
type LLMScheduler struct {
	sem     chan struct{}
	dropped atomic.Int64 // T1 classify calls dropped due to full semaphore
	total   atomic.Int64 // total calls (all tiers)
}

// NewLLMScheduler creates a scheduler with the given concurrency limit.
func NewLLMScheduler(maxConcurrent int) *LLMScheduler {
	if maxConcurrent < 1 {
		maxConcurrent = 2
	}
	return &LLMScheduler{
		sem: make(chan struct{}, maxConcurrent),
	}
}

// AcquireBlocking waits for a slot. Use for Tier 2 evidence reclassification
// where dropping the call would mean missing a confirmed escalation.
// Returns a release function. Respects context cancellation.
func (s *LLMScheduler) AcquireBlocking(ctx context.Context) (release func(), ok bool) {
	select {
	case s.sem <- struct{}{}:
		s.total.Add(1)
		return func() { <-s.sem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// TryAcquire attempts to get a slot without blocking.
// Use for Tier 1 classification where dropping is safe (line stays VerdictUnknown).
// Returns (release, true) on success, (nil, false) if full.
func (s *LLMScheduler) TryAcquire() (release func(), ok bool) {
	select {
	case s.sem <- struct{}{}:
		s.total.Add(1)
		return func() { <-s.sem }, true
	default:
		s.dropped.Add(1)
		return nil, false
	}
}

// Stats returns scheduler metrics.
func (s *LLMScheduler) Stats() (total, dropped int64) {
	return s.total.Load(), s.dropped.Load()
}
