// httpoutcomesink.go
package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vaultguardian/observer/internal/requestcorr"
)

// =============================================================================
// HTTP outcome sink — the single funnel for HTTP finding-producing paths
// (Part 3 / frozen design D8; round-2/4 single-owner serialization).
// =============================================================================
//
// Every HTTP path that used to write a finding directly now hands the sink an
// httpOutcome: the finding-write closure, an optional notify closure, and the
// metadata needed to place the observation on a request lineage. The four
// producing paths are:
//
//	1. recon_failed             (resultRouter.routeAlert)
//	2. status-rejection recon   (resultRouter.shortCircuitStatusRejection)
//	3. bare-IP edge recon       (resultRouter.routeAlert)
//	4. coordinator dispatch     (main.makeDispatchCallback: downgraded/escalated/unresolved)
//
// Non-HTTP findings (SSH/policy/host-state, non-HTTP malicious direct dispatch)
// NEVER call the sink — verifiable by grep.
//
// # D8 pass-through
//
// Emit's first act: with the feature off, it runs the outcome's full original
// behavior (notify-then-write, byte-identical to HEAD) and returns. When on but
// no valid ID is present the same commit runs (registered in-flight so shutdown
// can join it).
//
// # Locks cover DECISIONS, never callback execution (R2-2, round-4 Fix 1)
//
// The sink mutex serializes tracker transitions and parked-map claims ONLY;
// no notify() or writeFinding() runs while it is held. Concretely:
//   - Emit grouped: lock → admit + park + tracker.Observe → unlock → apply(ds).
//   - Run/drain:    lock → tracker.Tick()/FlushAll() → unlock → apply(ds).
//   - apply: a terminal directive CLAIMS its parked entry (delete under the
//     lock) then runs writeFinding OUTSIDE the lock — claim-before-execute is
//     exactly-once. A notify directive check-and-sets `consumed` and reads the
//     entry under the lock, unlocks, runs notify(), then relocks only to record
//     the result and call tracker.NotifyResult.
// A blocked writeFinding (full writer queue) therefore cannot delay an
// unrelated lineage's actionable notification: the blocked call holds no lock.
//
// The tracker stays internally lockless; every tracker call is made under the
// sink lock, so Observe and Tick can never interleave. Because Emit applies its
// notify directive immediately after Observe and a lineage cannot settle for a
// full settle window (default 3s), a Tick can never race ahead of a pending
// notification in production — so there is NO representative-emit notify
// backstop (it would only ever fire on an artificial split-Observe path).
//
// # Notification intent vs. success (F3)
//
// The tracker records notification INTENT (a directive); the sink executes it
// and feeds the enqueue result back via tracker.NotifyResult. The ledger
// advances only on success, so a failed enqueue leaves the next actionable
// sibling free to fire, and a representative row's Notified reflects reality.

// httpOutcome is what a producing path hands the sink.
type httpOutcome struct {
	eventID string
	// rawLine carries the trailing vgrid token (evt.Line / FinalAlert.Line);
	// the sink extracts the lineage ID from it. The token was stripped from
	// the NORMALIZED line, so this must be the raw line.
	rawLine   string
	source    string // bare source/container name, matched against anchor set
	outcome   requestcorr.Outcome
	timestamp time.Time

	// notify runs the path's notification dispatch and returns whether
	// anything was actually enqueued. nil for paths that never notify.
	notify func() bool
	// writeFinding persists the path's finding row. Its argument is the
	// Notified column value. Paths that always write Notified:false ignore it.
	writeFinding func(notified bool)
}

// parkedOutcome holds a grouped observation's closures until the tracker
// decides its fate. lineageID/sev let apply feed NotifyResult back without the
// original observation in hand; notifyConsumed makes firing exactly-once.
type parkedOutcome struct {
	notify         func() bool
	writeFinding   func(bool)
	lineageID      string
	sev            requestcorr.Severity
	notifyConsumed bool
	notified       bool // result of a fired notification, for an independent emit
}

// httpOutcomeSink funnels and (optionally) coalesces HTTP outcomes.
type httpOutcomeSink struct {
	enabled       bool
	anchorSources map[string]bool
	tracker       *requestcorr.Tracker
	tickInterval  time.Duration

	// Lineage-status telemetry (correlation block). Only counted when the
	// feature is on, so they double as an adoption metric.
	trustedIDs                atomic.Int64
	missingIDs                atomic.Int64
	invalidIDs                atomic.Int64
	drainNotificationsSkipped atomic.Int64

	mu        sync.Mutex
	cond      *sync.Cond // signals inflight reaching zero (shutdown join)
	parked    map[string]*parkedOutcome
	closed    bool // set at drain start: new Emits commit synchronously (still counted in-flight)
	drainMode bool // set during drain: apply suppresses fresh notifications
	inflight  int  // Emits currently executing their callbacks (R2-3 completion barrier)

	stopOnce sync.Once
}

func newHTTPOutcomeSink(cfg Config) *httpOutcomeSink {
	s := &httpOutcomeSink{
		enabled:       cfg.LineageEnabled,
		anchorSources: cfg.LineageAnchorSources,
		tickInterval:  500 * time.Millisecond,
		parked:        make(map[string]*parkedOutcome),
	}
	s.cond = sync.NewCond(&s.mu)
	if s.enabled {
		s.tracker = requestcorr.New(requestcorr.Config{}, nil)
	}
	return s
}

// Emit is the single entry point for every HTTP finding-producing path.
func (s *httpOutcomeSink) Emit(o httpOutcome) {
	commit := func() {
		notified := false
		if o.notify != nil {
			notified = o.notify()
		}
		o.writeFinding(notified)
	}

	// D8 pass-through, feature off: no lineage work, no in-flight bookkeeping
	// (Run/Shutdown are no-ops for a disabled sink).
	if !s.enabled {
		commit()
		return
	}

	id, st := extractLineageID(o.rawLine)
	switch st {
	case lineageValid:
		s.trustedIDs.Add(1)
	case lineageInvalid:
		s.invalidIDs.Add(1)
	default:
		s.missingIDs.Add(1)
	}

	sev, _ := requestcorr.SeverityOf(o.outcome)

	// Admission + in-flight registration under the same lock that decides
	// `closed`, so Shutdown can join every accepted Emit (R2-3).
	s.mu.Lock()
	s.inflight++
	if id == "" || s.closed {
		// No coalescable ID, or shutting down: commit synchronously OUTSIDE the
		// lock (it may block on the writer). Still joined via inflight.
		s.mu.Unlock()
		commit()
		s.emitDone()
		return
	}
	s.parked[o.eventID] = &parkedOutcome{
		notify:       o.notify,
		writeFinding: o.writeFinding,
		lineageID:    id,
		sev:          sev,
	}
	ds := s.tracker.Observe(requestcorr.Observation{
		LineageID:      id,
		Source:         o.source,
		IsAnchorSource: s.anchorSources[o.source],
		EventID:        o.eventID,
		Outcome:        o.outcome,
		Timestamp:      o.timestamp,
	})
	s.mu.Unlock()

	s.apply(ds) // callbacks run outside the lock
	s.emitDone()
}

// emitDone marks an in-flight Emit complete and wakes a waiting Shutdown.
func (s *httpOutcomeSink) emitDone() {
	s.mu.Lock()
	s.inflight--
	if s.inflight == 0 {
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

// apply executes tracker directives with the lock held only for decisions and
// claims — never around a callback. Callers pass directives obtained under the
// lock but must NOT hold it here.
func (s *httpOutcomeSink) apply(ds []requestcorr.Directive) {
	for _, d := range ds {
		switch d.Kind {
		case requestcorr.DirNotifyFire, requestcorr.DirNotifyUpgrade:
			s.mu.Lock()
			p := s.parked[d.EventID]
			if p == nil || p.notify == nil || p.notifyConsumed {
				s.mu.Unlock()
				continue
			}
			p.notifyConsumed = true
			if s.drainMode {
				s.drainNotificationsSkipped.Add(1)
				s.mu.Unlock()
				continue
			}
			notifyFn, lineageID, sev := p.notify, p.lineageID, p.sev
			s.mu.Unlock()

			ok := notifyFn() // OUTSIDE the lock

			s.mu.Lock()
			if p2 := s.parked[d.EventID]; p2 != nil {
				p2.notified = ok
			}
			s.tracker.NotifyResult(lineageID, d.EventID, sev, ok)
			s.mu.Unlock()

		case requestcorr.DirNotifySuppressed:
			// Deliberate dedupe; the tracker counts notifications_avoided.

		case requestcorr.DirEmitRepresentative:
			s.mu.Lock()
			p := s.parked[d.EventID]
			delete(s.parked, d.EventID) // CLAIM
			notified := d.Notified
			s.mu.Unlock()
			if p != nil {
				p.writeFinding(notified) // OUTSIDE the lock
			}

		case requestcorr.DirEmitIndependent:
			s.mu.Lock()
			p := s.parked[d.EventID]
			delete(s.parked, d.EventID) // CLAIM
			s.mu.Unlock()
			if p != nil {
				p.writeFinding(p.notified) // p is exclusively owned now
			}

		case requestcorr.DirDrop:
			s.mu.Lock()
			delete(s.parked, d.EventID)
			s.mu.Unlock()
		}
	}
}

// Run drives the settle/tombstone lifecycle until ctx is cancelled, then
// performs the shutdown drain. No-op when the feature is off.
func (s *httpOutcomeSink) Run(ctx context.Context) {
	if !s.enabled {
		return
	}
	ticker := time.NewTicker(s.tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.finishDrain()
			return
		case <-ticker.C:
			s.mu.Lock()
			ds := s.tracker.Tick()
			s.mu.Unlock()
			s.apply(ds)
		}
	}
}

// finishDrain flushes every pending lineage unconditionally, suppressing fresh
// notifications (F6), and executes the deferred write closures synchronously.
// Idempotent.
func (s *httpOutcomeSink) finishDrain() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closed = true    // new Emits now commit synchronously (still counted in-flight)
		s.drainMode = true // apply fires no fresh notifications
		ds := s.tracker.FlushAll()
		s.mu.Unlock()
		s.apply(ds) // deferred writeFinding calls run here, outside the lock
	})
}

// Shutdown drains, executes the drain's deferred writes, and WAITS for every
// accepted in-flight Emit (including late synchronous commits already entered)
// to finish, so all findings are submitted before the store writer closes
// (R2-3). No-op when the feature is off.
func (s *httpOutcomeSink) Shutdown() {
	if !s.enabled {
		return
	}
	s.finishDrain()
	s.mu.Lock()
	for s.inflight > 0 {
		s.cond.Wait()
	}
	s.mu.Unlock()
}

// correlationStats returns the correlation telemetry block for /api/stats. The
// zero value is returned when the feature is off.
func (s *httpOutcomeSink) correlationStats() correlationSnapshot {
	snap := correlationSnapshot{
		Enabled:                   s.enabled,
		TrustedIDs:                s.trustedIDs.Load(),
		MissingIDs:                s.missingIDs.Load(),
		InvalidIDs:                s.invalidIDs.Load(),
		DrainNotificationsSkipped: s.drainNotificationsSkipped.Load(),
	}
	if s.tracker != nil {
		snap.Counters = s.tracker.Snapshot()
	}
	return snap
}

// correlationSnapshot bundles the sink-owned lineage-status counters with the
// tracker's coalescing counters.
type correlationSnapshot struct {
	Enabled                   bool
	TrustedIDs                int64
	MissingIDs                int64
	InvalidIDs                int64
	DrainNotificationsSkipped int64
	Counters                  requestcorr.Counters
}

// statsBlock renders the pipeline_health.correlation block for /api/stats,
// using the design's telemetry names verbatim. Wired into the API server as
// SetCorrelationStatsCallback.
func (s *httpOutcomeSink) statsBlock() map[string]interface{} {
	snap := s.correlationStats()
	c := snap.Counters
	return map[string]interface{}{
		"enabled":                        snap.Enabled,
		"trusted_ids_total":              snap.TrustedIDs,
		"missing_ids_total":              snap.MissingIDs,
		"invalid_ids_total":              snap.InvalidIDs,
		"unanchored_ids_total":           c.UnanchoredIDs,
		"groups_total":                   c.Groups,
		"singleton_groups_total":         c.SingletonGroups,
		"multi_observation_groups_total": c.MultiObservationGroups,
		"groups_3plus_total":             c.Groups3Plus,
		"observations_absorbed_total":    c.ObservationsAbsorbed,
		"anchor_conflicts_total":         c.AnchorConflicts,
		"outcome_conflicts_total":        c.OutcomeConflicts,
		"late_siblings_total":            c.LateSiblings,
		"late_upgrades_persisted_total":  c.LateUpgradesPersisted,
		"notifications_avoided_total":    c.NotificationsAvoided,
		"notification_upgrades_total":    c.NotificationUpgrades,
		"drain_notifications_skipped":    snap.DrainNotificationsSkipped,
		"pending_groups":                 c.PendingGroups,
		"tombstones":                     c.Tombstones,
		"poisoned":                       c.Poisoned,
	}
}
