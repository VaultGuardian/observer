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
// (Part 3 / frozen design D8; round-5 single accepted-observation lifecycle).
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
// # One lifecycle for an accepted observation (round-6: per-attempt ownership)
//
// Round-5 gave the lifecycle one owner per stage but left the tracker with a
// single in-flight slot per lineage. Any schedule with two live attempts — two
// un-anchored independents, or independents started before the anchor arrives —
// overwrote the first token and orphaned its closure, its deferred rows and its
// truth. Every round-5 finding traced back to that. The fix is structural:
//
//	ATTEMPT RECORD (s.attempts, keyed by the tracker's unique token)
//	    {eventID, lineageID, sev, OWNED closure, dependents, chain}
//	    An attempt owns its notify closure and its dependent rows from mint to
//	    result, whatever the lineage ledger does afterwards. Terminal row
//	    selection therefore never has to discard notification work: claiming a
//	    parked entry TRANSFERS the closure into the attempt record (or, if the
//	    attempt has not been armed yet, the entry is retained until it is).
//
//	INDEPENDENT attempts (un-anchored / poisoned) are fully self-contained: own
//	    token, own result, own row flag. Nothing about one can suppress,
//	    serialize or overwrite another.
//
//	INCIDENT CHAIN (notifyChain) is how a representative row learns the truth.
//	    At settle the row is deferred to the SET of attempts still outstanding
//	    on that lineage — still-running pre-anchor independents included, not
//	    just the last token minted. A retry CONTINUES the chain (joining before
//	    its predecessor leaves, so the chain cannot momentarily look exhausted);
//	    a failed attempt hands its dependents on rather than resolving them
//	    early. The chain resolves true the moment ANY member succeeds, false
//	    when every member has failed and no retry remains. Per-EVENT rows keep
//	    per-event results: a sibling's success never turns a failed independent
//	    observation's own flag true.
//
//	COMPLETION REGISTRY (s.work) is unchanged and remains the single completion
//	    authority: one entry per callback execution, registered in the same
//	    critical section that selected it, joined by Shutdown.
//
//	  Emit ─┬─ pass-through (feature off, or on with no trusted ID) ─▶ commit
//	        │
//	        └─ PARK closures ─▶ tracker.Observe ─▶ SELECT + REGISTER + ARM
//	                                                       │   (one critical
//	                                                       ▼    section)
//	              apply(): an ITERATIVE per-goroutine worklist, drained
//	              notifications FIRST, row persistence last (see apply).
//
// # Locks cover DECISIONS, never callback execution (R2-2)
//
// The sink mutex serializes tracker transitions, parked-map claims and registry
// accounting ONLY; no notify() or writeFinding() runs while it is held. A
// blocked writeFinding (full writer queue) therefore cannot delay an unrelated
// lineage's actionable notification: the blocked call holds no lock. The tracker
// stays internally lockless; every tracker call is made under the sink lock, so
// Observe, Tick, FlushAll and NotifyResult can never interleave.
//
// # D8 pass-through (amended, round-5)
//
// Emit's first act: with the feature OFF, it runs the outcome's full original
// behavior (notify-then-write, byte-identical to HEAD) and returns — no lineage
// extraction, no lock, no bookkeeping. That path is unchanged on all of D8's
// terms.
//
// AMENDMENT: when the feature is ON but the log line carries no valid ID, the
// same commit still runs synchronously, in the same order, outside the lock —
// but Emit now takes the sink mutex ONCE, solely for admission/registry
// accounting (read `closed`, register the commit so shutdown can join it). That
// is constant work: no tracker call, no group allocation, no parking. It is a
// deliberate trade for the completion barrier — without it, a finding accepted
// during shutdown can still be in the writer queue when the database closes.
// Do not describe the enabled-but-no-ID path as lock-free; feature-off is.
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

// parkedOutcome holds one observation's closures until the tracker decides its
// fate. It has TWO independent lifetimes, and conflating them is what cost
// rounds 4 and 5:
//
//   - the ROW side, claimed exactly once by a terminal disposition;
//   - the NOTIFICATION side, which is settled when this observation's single
//     notification directive is applied (armed into an attempt, or suppressed).
//
// The entry is deleted only when the row has been claimed AND the notification
// side owes nothing — a purely per-EVENT fact this sink owns, with no per-lineage
// snapshot that could be stale by the time a row is applied.
type parkedOutcome struct {
	notify       func() bool
	writeFinding func(bool)
	lineageID    string
	sev          requestcorr.Severity

	notified      bool           // result of its OWN notification attempt
	notifySettled bool           // its one notification directive has been applied
	notifyArmed   bool           // an attempt record owns its closure
	notifyDone    bool           // that attempt has reported
	attempt       uint64         // the token of the attempt that owns it
	pendingRow    *deferredWrite // its own row, held until its own notification settles
	claimed       bool           // terminal disposition applied (writeFinding taken)
	writeWork     uint64         // registry id of the row write
}

// owesNotify reports whether this observation's notification question is still
// open, so its closure must stay reachable here. Actionable observations are
// the only ones that notify, and the tracker guarantees each of them exactly
// one Fire/Upgrade/Suppressed directive — which is what bounds the retention.
func (p *parkedOutcome) owesNotify() bool {
	return p.notify != nil && p.sev.Actionable() && !p.notifySettled
}

// notifyAttempt is ONE notification execution, keyed by the tracker's unique
// token. It owns its closure and its dependent rows from mint to result, so
// nothing that happens to the lineage ledger afterwards can orphan them.
type notifyAttempt struct {
	token     uint64
	eventID   string
	lineageID string
	sev       requestcorr.Severity

	notify  func() bool // OWNED from arm; survives the parked entry's deletion
	armed   bool        // its directive has been minted and registered here
	claimed bool        // its callback has been taken for execution (exactly-once)
	workID  uint64

	dependents []*deferredWrite // rows whose truth is THIS attempt's own result
	chain      *notifyChain     // the incident chain it belongs to, if any
}

// notifyChain is an incident's notification truth, as seen by a representative
// row selected while notification work was still outstanding.
//
// open is the set of attempts the incident's answer still depends on: every
// attempt outstanding on the lineage when the row was deferred, plus each retry
// that continues the chain. It resolves TRUE as soon as any member succeeds and
// FALSE once every member has failed with no retry left — never early, and
// never from a single token's result (round-6 Fix B1/B3).
type notifyChain struct {
	lineageID  string
	open       map[uint64]bool
	succeeded  bool
	closed     bool
	dependents []*deferredWrite
}

// deferredWrite is a finding row held back until the notification it depends on
// reaches a final state. base is the disposition's own value at selection; own
// marks a per-EVENT row, whose Notified column is that observation's own result
// rather than the incident's.
type deferredWrite struct {
	write  func(bool)
	base   bool
	own    bool
	workID uint64
	result bool
}

// workRef describes one registered detached callback execution. The registry is
// the sink's single completion authority: Shutdown returns only when it is
// empty, which by construction covers Emit-applied, Tick-applied, drain-applied
// and NotifyResult-returned work.
type workRef struct {
	kind    string // workNotify | workWrite | workCommit
	eventID string
}

const (
	workNotify = "notify"
	workWrite  = "write"
	workCommit = "commit"
)

// Run loop lifecycle, so Shutdown can JOIN it rather than assume it exited.
const (
	runIdle = iota
	runRunning
	runExited
)

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
	cond      *sync.Cond // signals registry-empty and Run exit (shutdown join)
	parked    map[string]*parkedOutcome
	attempts  map[uint64]*notifyAttempt // token → the attempt that owns its closure
	work      map[uint64]workRef        // the completion registry
	nextWork  uint64
	closed    bool // set at drain start: new Emits commit synchronously (still registered)
	drainMode bool // set during drain: apply fires no FRESH notifications
	runState  int

	stopOnce sync.Once
}

func newHTTPOutcomeSink(cfg Config) *httpOutcomeSink {
	s := &httpOutcomeSink{
		enabled:       cfg.LineageEnabled,
		anchorSources: cfg.LineageAnchorSources,
		tickInterval:  500 * time.Millisecond,
		parked:        make(map[string]*parkedOutcome),
		attempts:      make(map[uint64]*notifyAttempt),
		work:          make(map[uint64]workRef),
	}
	s.cond = sync.NewCond(&s.mu)
	if s.enabled {
		s.tracker = requestcorr.New(requestcorr.Config{}, nil)
	}
	return s
}

// --- registry (completion authority) ---------------------------------------

// registerLocked claims ownership of one callback execution. It MUST be called
// in the same critical section that selected the work, so there is no window in
// which the work is invisible to both the tracker and the shutdown barrier.
func (s *httpOutcomeSink) registerLocked(kind, eventID string) uint64 {
	s.nextWork++
	s.work[s.nextWork] = workRef{kind: kind, eventID: eventID}
	return s.nextWork
}

func (s *httpOutcomeSink) completeLocked(id uint64) {
	if _, ok := s.work[id]; !ok {
		return
	}
	delete(s.work, id)
	if len(s.work) == 0 {
		s.cond.Broadcast()
	}
}

func (s *httpOutcomeSink) complete(id uint64) {
	s.mu.Lock()
	s.completeLocked(id)
	s.mu.Unlock()
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

	// D8 pass-through, feature off: no lineage work, no lock, no bookkeeping
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

	s.mu.Lock()
	if id == "" || s.closed {
		// D8 amendment: no coalescable ID, or shutting down. The commit runs
		// synchronously OUTSIDE the lock (it may block on the writer); the lock
		// is taken only to read `closed` and register the commit so Shutdown
		// can join it. Constant work — no tracker, no group, no parking.
		w := s.registerLocked(workCommit, o.eventID)
		s.mu.Unlock()
		commit()
		s.complete(w)
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
	s.selectLocked(ds) // ownership claimed in the SAME critical section
	s.mu.Unlock()

	s.apply(ds) // callbacks run outside the lock
}

// selectLocked claims ownership for every callback the given directives will
// execute: it registers the work AND transfers each notification's closure into
// its attempt record. Callers hold the lock and have just produced ds, so
// selection, registration and ownership transfer are simultaneous — Tick can
// remove a group from tracker state knowing its write is already joined by the
// shutdown barrier, and a row claim can never race ahead of a closure hand-off.
func (s *httpOutcomeSink) selectLocked(ds []requestcorr.Directive) {
	for _, d := range ds {
		switch d.Kind {
		case requestcorr.DirNotifyFire, requestcorr.DirNotifyUpgrade:
			s.armAttemptLocked(d)
		case requestcorr.DirEmitRepresentative, requestcorr.DirEmitIndependent:
			if p := s.parked[d.EventID]; p != nil && !p.claimed && p.writeWork == 0 {
				p.writeWork = s.registerLocked(workWrite, d.EventID)
			}
		}
	}
}

// attemptRecordLocked returns (creating if needed) the record for one attempt
// token. A record may be created by the ROW side first — a representative
// selected while an attempt is outstanding seeds its chain before that
// attempt's own directive has been applied.
func (s *httpOutcomeSink) attemptRecordLocked(token uint64) *notifyAttempt {
	a := s.attempts[token]
	if a == nil {
		a = &notifyAttempt{token: token}
		s.attempts[token] = a
	}
	return a
}

// armAttemptLocked records ownership of a minted notification directive and
// TRANSFERS the observation's closure into the attempt.
//
// This is the round-6 root fix: from here the attempt — not the parked map, and
// not the lineage's one in-flight slot — owns the closure. A later attempt on
// the same lineage cannot overwrite it, and a terminal row claim can delete the
// parked entry without taking the notification with it (Fix A).
func (s *httpOutcomeSink) armAttemptLocked(d requestcorr.Directive) *notifyAttempt {
	a := s.attemptRecordLocked(d.Token)
	if a.armed {
		return a
	}
	a.armed = true
	a.eventID, a.lineageID, a.sev = d.EventID, d.LineageID, d.Severity
	a.workID = s.registerLocked(workNotify, d.EventID)
	if p := s.parked[d.EventID]; p != nil && !p.notifySettled {
		a.notify = p.notify
		p.notifySettled = true
		p.notifyArmed = true
		p.attempt = d.Token
		if p.pendingRow != nil {
			// Its own row was waiting for an attempt that had not been armed
			// yet; hand it to the attempt that now owns the notification.
			a.dependents = append(a.dependents, p.pendingRow)
			p.pendingRow = nil
		}
		s.releaseParkedLocked(d.EventID, p)
	}
	return a
}

// incidentChainLocked builds the set of attempts a representative row's truth
// depends on: every attempt still outstanding on this lineage — pre-anchor
// independents included — not merely the last token the ledger recorded
// (round-6 Fix B3). Returns nil when nothing is outstanding.
func (s *httpOutcomeSink) incidentChainLocked(d requestcorr.Directive) *notifyChain {
	open := make(map[uint64]bool)
	for tok, a := range s.attempts {
		if a.lineageID == d.LineageID {
			open[tok] = true
		}
	}
	// A directive minted by a driver that did not register it (white-box tests)
	// has no record here yet; the tracker still knows the reservation is live.
	if d.Token != 0 && s.tracker.AttemptOutstanding(d.LineageID, d.Token) {
		open[d.Token] = true
	}
	if len(open) == 0 {
		return nil
	}
	// An attempt reports its result exactly once, so it can only tell ONE chain.
	// If any of these attempts already belongs to an open chain, JOIN that chain
	// rather than building a second one over the same members — stealing them
	// would leave the first chain's rows waiting for a report that never comes.
	ch := (*notifyChain)(nil)
	for tok := range open {
		if a := s.attempts[tok]; a != nil && a.chain != nil && !a.chain.closed {
			ch = a.chain
			break
		}
	}
	if ch == nil {
		ch = &notifyChain{lineageID: d.LineageID, open: make(map[uint64]bool)}
	}
	for tok := range open {
		ch.open[tok] = true
		a := s.attemptRecordLocked(tok)
		a.lineageID = d.LineageID
		a.chain = ch
	}
	return ch
}

// joinChainLocked adds a retry to the chain its predecessor belonged to. It is
// called BEFORE the predecessor is removed, so the chain can never momentarily
// look exhausted and resolve a representative row early (Fix B1).
func (s *httpOutcomeSink) joinChainLocked(ch *notifyChain, token uint64) {
	if ch == nil || ch.closed || token == 0 {
		return
	}
	ch.open[token] = true
	a := s.attemptRecordLocked(token)
	a.lineageID = ch.lineageID
	a.chain = ch
}

// chainSettledLocked records one member's result. The chain resolves as soon as
// any member SUCCEEDS, or once every member has failed and no retry joined.
func (s *httpOutcomeSink) chainSettledLocked(ch *notifyChain, token uint64, ok bool) []*deferredWrite {
	delete(ch.open, token)
	if ok {
		ch.succeeded = true
	}
	if ch.closed || (!ch.succeeded && len(ch.open) > 0) {
		return nil
	}
	ch.closed = true
	out := ch.dependents
	ch.dependents = nil
	for _, dw := range out {
		dw.result = dw.base || ch.succeeded
	}
	return out
}

// settleAttemptLocked closes an attempt: its own dependent rows take its own
// result, and its incident chain is told. Deleting the record makes settlement
// idempotent.
func (s *httpOutcomeSink) settleAttemptLocked(a *notifyAttempt, ok bool) []*deferredWrite {
	delete(s.attempts, a.token)
	out := a.dependents
	a.dependents = nil
	for _, dw := range out {
		dw.result = ok // a per-event row carries its OWN result, never a sibling's
	}
	if a.chain != nil {
		out = append(out, s.chainSettledLocked(a.chain, a.token, ok)...)
		a.chain = nil
	}
	return out
}

// releaseParkedLocked drops a parked entry once its row has been claimed and its
// notification side owes nothing.
func (s *httpOutcomeSink) releaseParkedLocked(eventID string, p *parkedOutcome) {
	if p.claimed && !p.owesNotify() && p.pendingRow == nil {
		delete(s.parked, eventID)
	}
}

// isNotifyKind reports whether a directive belongs to the notification lane of
// the worklist (it settles an obligation and may unblock an alert).
func isNotifyKind(k requestcorr.DirectiveKind) bool {
	return k == requestcorr.DirNotifyFire || k == requestcorr.DirNotifyUpgrade || k == requestcorr.DirNotifySuppressed
}

// apply drains tracker directives with an ITERATIVE per-goroutine worklist.
//
// Round-6 replaces round-5's apply→runAttempt→apply recursion, for two reasons.
// First, ORDERING (Fix B2): every eligible notification follow-up in a drain —
// including a retry the tracker issued when an attempt failed — executes BEFORE
// any finding row is persisted, so a writeFinding blocked on a full critical
// queue can no longer hold an alert behind it. Second, there is no stack growth
// however long a retry chain becomes. The reviewer confirmed that iteration does
// not inherently create a registration gap: selection, registry ownership and
// closure transfer all still happen in the ONE critical section that produced
// the directives (see selectLocked / armAttemptLocked).
//
// The lock is held only for decisions, claims and accounting — never around a
// callback. Rows are executed from the lowest-priority lane so that the "no row
// persistence while a notification is pending" rule holds for immediate writes
// and for writes released by a settled attempt alike.
func (s *httpOutcomeSink) apply(ds []requestcorr.Directive) {
	var notifyQ, rowQ []requestcorr.Directive
	var writeQ []*deferredWrite

	push := func(list []requestcorr.Directive) {
		for _, d := range list {
			if isNotifyKind(d.Kind) {
				notifyQ = append(notifyQ, d)
			} else {
				rowQ = append(rowQ, d)
			}
		}
	}
	push(ds)

	for {
		switch {
		case len(notifyQ) > 0:
			d := notifyQ[0]
			notifyQ = notifyQ[1:]
			if d.Kind == requestcorr.DirNotifySuppressed {
				writeQ = append(writeQ, s.settleSuppressed(d)...)
				continue
			}
			follow, writes := s.stepNotify(d)
			push(follow)
			writeQ = append(writeQ, writes...)

		case len(rowQ) > 0:
			d := rowQ[0]
			rowQ = rowQ[1:]
			writeQ = append(writeQ, s.stepRow(d)...)

		case len(writeQ) > 0:
			dw := writeQ[0]
			writeQ = writeQ[1:]
			dw.write(dw.result) // OUTSIDE the lock; may block on the store writer
			s.complete(dw.workID)

		default:
			return
		}
	}
}

// stepNotify executes one notification attempt end to end: claim (exactly-once)
// → run the OWNED closure outside the lock → record the result under its token →
// hand any retry the chain and any resolved rows back to the caller's worklist.
// An attempt ALWAYS settles, even with nothing to run, so a reservation is never
// left hanging and no dependent row is stranded.
func (s *httpOutcomeSink) stepNotify(d requestcorr.Directive) ([]requestcorr.Directive, []*deferredWrite) {
	s.mu.Lock()
	a := s.armAttemptLocked(d)
	if a.claimed {
		s.mu.Unlock()
		return nil, nil
	}
	a.claimed = true
	fn := a.notify
	if fn != nil && s.drainMode {
		// F6: the ordered drain starts no FRESH notification. An attempt already
		// running is waited out, never cancelled.
		s.drainNotificationsSkipped.Add(1)
		fn = nil
	}
	s.mu.Unlock()

	ok := false
	if fn != nil {
		ok = fn() // OUTSIDE the lock
	}

	s.mu.Lock()
	if p := s.parked[a.eventID]; p != nil {
		p.notified = ok
		p.notifyDone = true
		s.releaseParkedLocked(a.eventID, p)
	}
	follow := s.tracker.NotifyResult(a.lineageID, a.token, a.sev, ok)
	s.selectLocked(follow) // register the retry BEFORE the registry can empty
	for _, fd := range follow {
		if fd.Kind == requestcorr.DirNotifyFire || fd.Kind == requestcorr.DirNotifyUpgrade {
			s.joinChainLocked(a.chain, fd.Token) // continue the chain, then leave it
		}
	}
	writes := s.settleAttemptLocked(a, ok)
	w := a.workID
	s.mu.Unlock()

	s.complete(w)
	return follow, writes
}

// settleSuppressed closes an observation's notification question without firing:
// a deliberate dedupe, a waiter the incident's success already covered, a waiter
// displaced by a less-safe sibling, or one abandoned with its ledger. Its own
// row, if it was waiting, takes its own (un-notified) result.
func (s *httpOutcomeSink) settleSuppressed(d requestcorr.Directive) []*deferredWrite {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.parked[d.EventID]
	if p == nil {
		return nil
	}
	p.notifySettled = true
	var out []*deferredWrite
	if p.pendingRow != nil {
		p.pendingRow.result = p.notified
		out = append(out, p.pendingRow)
		p.pendingRow = nil
	}
	s.releaseParkedLocked(d.EventID, p)
	return out
}

// stepRow applies one terminal row disposition. It never runs a callback: it
// returns the rows that are ready, so the worklist can keep every notification
// ahead of every write. A row whose Notified column is not yet knowable is
// handed to the work that will know it — the incident chain for a
// representative, the observation's own attempt for an independent row.
func (s *httpOutcomeSink) stepRow(d requestcorr.Directive) []*deferredWrite {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.parked[d.EventID]
	if p == nil || p.claimed {
		return nil // terminal dispositions are exactly-once
	}
	p.claimed = true // CLAIM

	if d.Kind == requestcorr.DirDrop {
		s.releaseParkedLocked(d.EventID, p)
		return nil
	}

	if p.writeWork == 0 {
		p.writeWork = s.registerLocked(workWrite, d.EventID)
	}
	dw := &deferredWrite{write: p.writeFinding, base: d.Notified, workID: p.writeWork}

	if d.Kind == requestcorr.DirEmitRepresentative {
		// The representative carries the INCIDENT's status.
		if ch := s.incidentChainLocked(d); ch != nil {
			ch.dependents = append(ch.dependents, dw)
			s.releaseParkedLocked(d.EventID, p)
			return nil
		}
		dw.result = d.Notified || s.tracker.Notified(d.LineageID)
		s.releaseParkedLocked(d.EventID, p)
		return []*deferredWrite{dw}
	}

	// An independent row carries its OWN notification result.
	dw.own = true
	if p.notifyArmed && !p.notifyDone {
		if a := s.attempts[p.attempt]; a != nil {
			a.dependents = append(a.dependents, dw)
			s.releaseParkedLocked(d.EventID, p)
			return nil
		}
	}
	if p.owesNotify() {
		// Its notification directive exists but has not been armed here yet;
		// armAttemptLocked will hand this row to the attempt that takes it.
		p.pendingRow = dw
		return nil
	}
	dw.result = p.notified
	s.releaseParkedLocked(d.EventID, p)
	return []*deferredWrite{dw}
}

// Run drives the settle/tombstone lifecycle until ctx is cancelled, then
// performs the shutdown drain. No-op when the feature is off. Its exit is
// signalled so Shutdown can JOIN it: a Tick-owned write callback is Run's work,
// and the barrier is not satisfied while Run is still inside one.
func (s *httpOutcomeSink) Run(ctx context.Context) {
	if !s.enabled {
		return
	}
	s.mu.Lock()
	s.runState = runRunning
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.runState = runExited
		s.cond.Broadcast()
		s.mu.Unlock()
	}()

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
			s.selectLocked(ds) // registered before the group leaves tracker state
			s.mu.Unlock()
			s.apply(ds)
		}
	}
}

// finishDrain flushes every pending lineage unconditionally, suppressing fresh
// notifications (F6), and executes the deferred write closures. Idempotent.
func (s *httpOutcomeSink) finishDrain() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closed = true    // new Emits now commit synchronously (still registered)
		s.drainMode = true // apply fires no fresh notifications
		ds := s.tracker.FlushAll()
		s.selectLocked(ds)
		s.mu.Unlock()
		s.apply(ds) // deferred writeFinding calls run here, outside the lock
	})
}

// Shutdown stops admissions, drains the tracker, then waits until the sink owns
// no outstanding work at all and the Run loop has exited.
//
// The registry is the barrier: it covers Emit-applied, Tick-applied,
// drain-applied and NotifyResult-returned callbacks, plus the synchronous
// commits of late Emits already inside the door, plus row writes deferred to an
// in-flight notification. Joining Run as well closes the last gap — a write
// callback selected by Tick belongs to Run, not to any Emit. main.go closes the
// findings writer and the database only after this returns. No-op when off.
func (s *httpOutcomeSink) Shutdown() {
	if !s.enabled {
		return
	}
	s.finishDrain()
	s.mu.Lock()
	for len(s.work) > 0 || s.runState == runRunning {
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
	if s.enabled {
		s.mu.Lock()
		snap.DetachedWork = int64(len(s.work))
		s.mu.Unlock()
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
	DetachedWork              int64 // gauge: registered callbacks not yet complete
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
		"detached_work":                  snap.DetachedWork,
	}
}
