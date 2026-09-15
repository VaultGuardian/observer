// Package requestcorr implements the post-verdict request-lineage coalescer
// (the third safety boundary of the frozen "Request lineage & proxy
// observation coalescing" design).
//
// It is a state machine that returns DIRECTIVES: Observe/Tick/FlushAll/
// NotifyResult take inputs, mutate in-memory state, and describe what the
// caller (the outcome sink) should do — addressed by EventID. It performs no
// I/O and holds no closures; the sink owns findings, notifiers, and stores.
//
// # Single-owner concurrency (round-2 DF-B)
//
// The tracker is NOT internally locked. Its owner — the sink — serializes every
// call to Observe, Tick, FlushAll, and NotifyResult under one mutex, so Observe
// and Tick can never interleave and the "Tick erasing a pending notify" race is
// closed by construction. The one cross-goroutine access is Snapshot (served to
// /api/stats), so every counter and gauge is an atomic.Int64; nothing else is
// read off-owner.
//
// # What it does NOT do (design boundaries)
//
//   - It does not touch the coordinator correlation key, byte partition, or
//     graveyard. Every observation has already run the full per-observation
//     pipeline independently; this layer only controls operator-facing
//     cardinality AFTER a verdict exists. Upstream coordinator huddling may
//     already aggregate identical-shape floods before the sink ever sees an
//     outcome — this layer never *creates* extra findings, it only removes the
//     proxy-topology duplicates it can prove via the trusted ID.
//   - It never pairs on time, shape, hash, or a ± window. The only thing that
//     links two observations is a trusted 32-hex ingress ID (the caller
//     supplies it already validated). No ID → no correlation, ever.
//
// # Anchoring (D1/D2, F5)
//
// A lineage coalesces NOTHING until anchored by exactly one observation from a
// declared trusted-ingress ("anchor") source. Two anchor-role observations for
// one ID is an identity-integrity failure: the ID is poisoned for a full TTL
// (spanning tombstones — F5), everything for it emits independently, and
// anchor_conflicts_total increments.
//
// # Aggregation (D4/D5)
//
// Least-safe child wins. The emitted representative is the highest-severity
// child's OWN finding (evidence linkage intact — no synthetic merged row);
// ties go to the anchor child. Other children emit no row; they are counted.
//
// # Notification lifecycle (D6, F3, round-6)
//
// Correlation may delay the finding ROW but never an actionable NOTIFICATION.
// Every notification directive the tracker hands out mints a UNIQUE ATTEMPT
// TOKEN, and the owner reports back under that token. There are two kinds of
// attempt, and the distinction is structural, not a flag:
//
//	INDEPENDENT (un-anchored or poisoned observations)
//	    No shared state whatsoever. Each actionable observation gets its own
//	    token and notifies for itself. Nothing about one can suppress,
//	    serialize, or OVERWRITE another — the round-5 single-slot ledger could
//	    orphan an older live attempt, which is the root cause all four round-5
//	    findings traced back to. A self-labeled ID therefore cannot silence an
//	    alert, and two backend hops that arrive before the anchor both notify.
//
//	INCIDENT (anchored lineages)
//	    One reservation at a time, plus a queue of eligible siblings:
//
//	      Idle ──issue Fire──▶ InFlight(token,sev,event) ──ok──▶ Succeeded(mark)
//	        ▲                      │        ▲                         │
//	        └──── fail ────────────┘        └──── issue Upgrade ──────┘
//	                                │
//	          eligible sibling ─────┤ queued; ONE TURN AT A TIME. Each is either
//	          arrives mid-attempt   ▼ covered by a success (suppressed, counted)
//	                                  or gets its own attempt — never discarded
//	                                  unnotified while nothing covers it.
//
//	    A Fire is issued only from Idle; from Succeeded only as an Upgrade
//	    strictly above notifiedSev. NotifyResult(token) is the only exit from
//	    InFlight, and only the reserved token releases it — an independent or
//	    superseded result never disturbs a live reservation. On failure the
//	    lineage returns to Idle and NotifyResult RETURNS a fresh Fire/Upgrade
//	    for the next queued sibling, so a failed enqueue never silences an
//	    incident no matter how many siblings queued behind it.
//
// The SUCCESS RECORD (notified/notifiedSev) is shared: ANY attempt's success —
// independent or incident — advances it monotonically, because the fact being
// recorded is "this incident was reported", not "this slot finished". That is
// what lets a pre-anchor backend success dedupe the anchor's own observation.
//
// The tracker holds no closures and no row state; the owner maps each token to
// the closure it owns and to the rows whose Notified column depends on it.
//
// # Timing & durability (D7, DF-A)
//
// A settle window (default 3s) briefly holds a not-yet-emitted finding for a
// sibling. A tombstone (default 300s) makes late observations of an
// anchored-in-lifetime ID TERMINAL: a late child strictly above the tombstone's
// MONOTONIC high-water mark (which starts at the settled aggregate and advances
// as upgrades are accepted) persists its OWN independent finding row (the
// stored representative is never mutated) and advances the mark; a child at or
// below the mark is dropped. Notification eligibility is evaluated separately
// from the row (R2-1): a late actionable child on an incident that never
// successfully notified fires/retries the alert even when its row is dropped.
// The tombstone inherits the lineage's notification ledger WHOLE — in-flight
// attempt and queued siblings included — so settlement never resets the state
// machine mid-attempt. Nothing ever lowers a verdict. The clock is injected.
package requestcorr

import (
	"sync/atomic"
	"time"
)

// Default lifecycle windows (D7). settle mirrors the coordinator finalize
// cadence; tombstone matches DefaultGraveyardTTL (300s).
const (
	DefaultSettleWindow = 3 * time.Second
	DefaultTombstoneTTL = 300 * time.Second
)

// =============================================================================
// Outcome lattice (D4) — Observer's ACTUAL outcome vocabulary, mapped to an
// ordered severity. Derived by grepping the finding-producing paths
// (resultrouter.go, main.go makeDispatchCallback, the reconciler):
//
//	Finding verdict / resolution        →  sink Outcome        →  Severity
//	------------------------------------------------------------------------
//	recon (recon_failed)                →  OutcomeRecon        →  SevSafe
//	recon (recon_failed_status)         →  OutcomeRecon        →  SevSafe
//	recon (edge_inferred, bare-IP)      →  OutcomeRecon        →  SevSafe
//	downgraded (rec_evidence/catch-all) →  OutcomeDowngraded   →  SevSafe
//	alert/suspicious (pending dispatch) →  OutcomeUnresolved   →  SevUnresolved
//	evidence_unavailable (reconciler)   →  OutcomeUnresolved   →  SevUnresolved
//	malicious (escalated dispatch)      →  OutcomeEscalated    →  SevActionable
//
// Every finding-producing HTTP outcome maps cleanly onto exactly one tier.
// Only SevActionable notifies. "Least-safe wins": any non-SevSafe child blocks
// a group downgrade, and any SevActionable child makes the group actionable.
// =============================================================================

// Severity is the ordered outcome lattice. Higher = less safe.
type Severity int

const (
	SevSafe       Severity = iota // recon / downgraded
	SevUnresolved                 // suspicious / unresolved / evidence_unavailable
	SevActionable                 // escalated / malicious
)

// Outcome is the semantic result each finding-producing sink path reports.
type Outcome string

const (
	OutcomeRecon      Outcome = "recon"
	OutcomeDowngraded Outcome = "downgraded"
	OutcomeUnresolved Outcome = "unresolved"
	OutcomeEscalated  Outcome = "escalated"
)

// SeverityOf maps an outcome onto the lattice. ok=false marks an outcome the
// lattice does not recognize — the caller fails open (emit independently),
// never coalescing something it cannot place.
func SeverityOf(o Outcome) (sev Severity, ok bool) {
	switch o {
	case OutcomeRecon, OutcomeDowngraded:
		return SevSafe, true
	case OutcomeUnresolved:
		return SevUnresolved, true
	case OutcomeEscalated:
		return SevActionable, true
	}
	return SevSafe, false
}

// Actionable reports whether a severity notifies immediately (D6).
func (s Severity) Actionable() bool { return s == SevActionable }

// Clock is the injected time source (D7: deterministic tests).
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Observation is one finished, verdict-bearing view of one request.
type Observation struct {
	LineageID      string
	Source         string
	IsAnchorSource bool
	EventID        string
	Outcome        Outcome
	Timestamp      time.Time // source-clock event time; NOT used for lifecycle decisions (D7)
}

// DirectiveKind is what the sink should do with an observation's parked work.
type DirectiveKind int

const (
	// Notification directives (immediate, D6):
	DirNotifyFire       DirectiveKind = iota // run this EventID's notify closure
	DirNotifySuppressed                      // a duplicate — do not notify (counted)
	DirNotifyUpgrade                         // run notify: severity exceeded the recorded one

	// Emission directives (terminal dispositions, D5):
	DirEmitRepresentative // run this EventID's writeFinding as the group representative
	DirEmitIndependent    // run this EventID's writeFinding as its own standalone finding
	DirDrop               // non-representative / sub-threshold sibling: drop its row (counted)
)

// IsTerminal reports whether a directive is a final disposition of a parked
// observation. Every parked EventID receives exactly one such directive.
func (k DirectiveKind) IsTerminal() bool {
	return k == DirEmitRepresentative || k == DirEmitIndependent || k == DirDrop
}

// Directive addresses one EventID's parked work in the sink.
//
// Round-5: a directive DESCRIBES ITS OWN WORK COMPLETELY. The sink never has to
// reconstruct a directive's identity from a parked entry that settlement may
// already have claimed — that reconstruction is exactly what dropped pending
// notifications in earlier rounds.
type Directive struct {
	Kind      DirectiveKind
	EventID   string
	LineageID string   // the lineage this work belongs to ("" for unmappable outcomes)
	Severity  Severity // the observation's severity (notification directives)

	// Notified is authoritative only on DirEmitRepresentative: whether the
	// GROUP actually notified (ledger success), so the representative row's
	// Notified column reflects the incident. Independent emits read the sink's
	// own per-event notify result instead.
	Notified bool

	// Token identifies one notification ATTEMPT, uniquely and for its whole
	// life. Every notification directive carries a fresh non-zero token.
	//
	//   - On DirNotifyFire/DirNotifyUpgrade: the token minted for this attempt.
	//     The owner echoes it back through NotifyResult; only the reserved token
	//     releases an incident reservation, so a stale or independent callback
	//     can never disturb a live attempt.
	//   - On DirEmitRepresentative: the INCIDENT reservation outstanding when
	//     this disposition was selected (0 = none). It seeds the owner's
	//     incident chain for a driver that mints a directive without registering
	//     it; the owner's own per-attempt records are otherwise authoritative.
	//
	// Round-6 removed NotifyPending: retention of an observation's notify
	// closure is now a per-EVENT fact the OWNER holds (armed ⇒ the attempt owns
	// the closure; unsettled ⇒ the parked entry keeps it), never a per-lineage
	// snapshot that could be stale by the time a row was applied.
	Token uint64
}

// Counters is the telemetry surface (pipeline_health.correlation block).
type Counters struct {
	UnanchoredIDs          int64
	Groups                 int64
	SingletonGroups        int64
	MultiObservationGroups int64
	Groups3Plus            int64
	ObservationsAbsorbed   int64
	AnchorConflicts        int64
	OutcomeConflicts       int64
	LateSiblings           int64
	LateUpgradesPersisted  int64
	NotificationsAvoided   int64
	NotificationUpgrades   int64
	PendingGroups          int64 // gauge
	Tombstones             int64 // gauge
	Poisoned               int64 // gauge
}

type lstate int

const (
	stateUnanchored lstate = iota
	stateAnchored
)

type member struct {
	eventID  string
	severity Severity
	isAnchor bool
}

// notifyLedger is one lineage's INCIDENT notification state machine (see the
// package doc). Idle = !inFlight && !notified; InFlight = inFlight;
// Succeeded = !inFlight && notified. An Upgrade attempt is InFlight laid over a
// Succeeded record, which is why the two are tracked as separate fields rather
// than one enum: the success survives a failed upgrade.
//
// Round-6: INDEPENDENT attempts never touch the reservation or the queue —
// they own nothing here beyond their contribution to the shared success record.
// A lineage can therefore have any number of live independent attempts without
// one overwriting another.
type notifyLedger struct {
	// The reserved INCIDENT attempt currently executing in the owner.
	inFlight    bool
	token       uint64
	flightSev   Severity
	flightEvent string

	// The success record (F3): set only by NotifyResult(ok), never by intent.
	notified    bool
	notifiedSev Severity

	// Eligible siblings queued behind the live attempt. ONE TURN AT A TIME:
	// exactly one incident attempt may run, but a sibling is never DISCARDED
	// unnotified while the incident has no success to cover it. (Round-6: a
	// single slot silenced the loser of a same-severity displacement whenever
	// the winner's attempt then failed — three chances to report an incident,
	// none taken. The queue is bounded by the group's own membership.)
	queued []queuedNotify
}

// queuedNotify is one eligible sibling awaiting its turn.
type queuedNotify struct {
	eventID string
	sev     Severity
}

// markNotified advances the success record monotonically. Nothing ever lowers
// it — a failed later attempt cannot un-notify an incident.
func (lg *notifyLedger) markNotified(sev Severity) {
	lg.notified = true
	if sev > lg.notifiedSev {
		lg.notifiedSev = sev
	}
}

// covered reports whether a successful notification already carries this
// severity, so an eligible sibling adds nothing.
func (lg *notifyLedger) covered(sev Severity) bool {
	return lg.notified && sev <= lg.notifiedSev
}

// enqueue records an eligible sibling that arrived while an attempt was running.
// It gets no directive now; releaseQueued decides its fate once the truth about
// the running attempt is known.
func (lg *notifyLedger) enqueue(sev Severity, eventID string) {
	lg.queued = append(lg.queued, queuedNotify{eventID: eventID, sev: sev})
}

// takeBest removes and returns the least-safe queued sibling (stable within a
// severity), so an upgrade is never made to wait behind an equal peer.
func (lg *notifyLedger) takeBest() (queuedNotify, bool) {
	if len(lg.queued) == 0 {
		return queuedNotify{}, false
	}
	best := 0
	for i := 1; i < len(lg.queued); i++ {
		if lg.queued[i].sev > lg.queued[best].sev {
			best = i
		}
	}
	q := lg.queued[best]
	lg.queued = append(lg.queued[:best], lg.queued[best+1:]...)
	return q, true
}

type lineage struct {
	state          lstate
	members        []member
	anchorSeen     bool
	settleDeadline time.Time
	notify         notifyLedger
}

type tombstone struct {
	finalizedAt time.Time
	highWater   Severity // MONOTONIC severity baseline (R2-4): starts at the settled
	// aggregate and advances each time a late upgrade row is
	// accepted, so equal/lower stragglers add no further rows.
	representativeEventID string       // the emitted representative (retained for the record; DF-A)
	notify                notifyLedger // inherited WHOLE from the lineage (round-5)
}

// Tracker is the coalescer state machine. Single-owner: see package doc.
type Tracker struct {
	clock        Clock
	settle       time.Duration
	tombstoneTTL time.Duration

	active     map[string]*lineage   // not-yet-emitted lineages
	tombstones map[string]*tombstone // emitted anchored lineages (late-attach window)
	poisoned   map[string]time.Time  // id → expiry; integrity-failed IDs, fail open after TTL

	nextToken uint64 // attempt tokens; 0 is reserved for "no attempt"

	c counters
}

type counters struct {
	unanchoredIDs         atomic.Int64
	groups                atomic.Int64
	singletonGroups       atomic.Int64
	multiGroups           atomic.Int64
	groups3plus           atomic.Int64
	observationsAbsorbed  atomic.Int64
	anchorConflicts       atomic.Int64
	outcomeConflicts      atomic.Int64
	lateSiblings          atomic.Int64
	lateUpgradesPersisted atomic.Int64
	notifsAvoided         atomic.Int64
	notifUpgrades         atomic.Int64

	gPending atomic.Int64 // gauge: len(active)
	gTomb    atomic.Int64 // gauge: len(tombstones)
	gPoison  atomic.Int64 // gauge: len(poisoned)
}

// Config sets the lifecycle windows. Zero fields fall back to defaults.
type Config struct {
	SettleWindow time.Duration
	TombstoneTTL time.Duration
}

// New builds a Tracker. Clock nil ⇒ real wall clock.
func New(cfg Config, clock Clock) *Tracker {
	if clock == nil {
		clock = realClock{}
	}
	if cfg.SettleWindow <= 0 {
		cfg.SettleWindow = DefaultSettleWindow
	}
	if cfg.TombstoneTTL <= 0 {
		cfg.TombstoneTTL = DefaultTombstoneTTL
	}
	return &Tracker{
		clock:        clock,
		settle:       cfg.SettleWindow,
		tombstoneTTL: cfg.TombstoneTTL,
		active:       make(map[string]*lineage),
		tombstones:   make(map[string]*tombstone),
		poisoned:     make(map[string]time.Time),
	}
}

// --- map mutators that keep the gauges honest (single-owner, no lock) ---

func (t *Tracker) putActive(id string, ln *lineage) { t.active[id] = ln; t.c.gPending.Add(1) }
func (t *Tracker) delActive(id string) {
	if _, ok := t.active[id]; ok {
		delete(t.active, id)
		t.c.gPending.Add(-1)
	}
}
func (t *Tracker) putTombstone(id string, tb *tombstone) {
	if _, ok := t.tombstones[id]; !ok {
		t.c.gTomb.Add(1)
	}
	t.tombstones[id] = tb
}
func (t *Tracker) delTombstone(id string) {
	if _, ok := t.tombstones[id]; ok {
		delete(t.tombstones, id)
		t.c.gTomb.Add(-1)
	}
}
func (t *Tracker) putPoisoned(id string, exp time.Time) {
	if _, ok := t.poisoned[id]; !ok {
		t.c.gPoison.Add(1)
	}
	t.poisoned[id] = exp
}
func (t *Tracker) delPoisoned(id string) {
	if _, ok := t.poisoned[id]; ok {
		delete(t.poisoned, id)
		t.c.gPoison.Add(-1)
	}
}

// ledgerFor returns the notification state machine for an ID, wherever it
// currently lives. A lineage's ledger migrates into its tombstone at settle, so
// an attempt that started before settlement still resolves against the same
// state after it.
func (t *Tracker) ledgerFor(id string) *notifyLedger {
	if ln := t.active[id]; ln != nil {
		return &ln.notify
	}
	if tb := t.tombstones[id]; tb != nil {
		return &tb.notify
	}
	return nil
}

// Observe records one verdict-bearing observation and returns its directives.
// Terminal (emission) directives appear here only for observations that resolve
// immediately — poisoned IDs, late tombstone attaches, unmappable outcomes.
// Observations that join an active lineage return only notification directives;
// their disposition arrives later from Tick/FlushAll.
//
// Precondition: the caller only calls Observe with a validated, non-empty
// LineageID; the D8 pass-through never reaches this layer.
func (t *Tracker) Observe(obs Observation) []Directive {
	sev, ok := SeverityOf(obs.Outcome)
	now := t.clock.Now()

	// Unmappable outcome ⇒ never coalesce; emit independently, terminal.
	if !ok {
		return []Directive{{Kind: DirEmitIndependent, EventID: obs.EventID, LineageID: obs.LineageID, Severity: sev}}
	}

	// --- Poisoned lookup FIRST (F5): spans tombstones ---
	if exp, isP := t.poisoned[obs.LineageID]; isP {
		if now.Before(exp) {
			return t.terminalIndependent(obs, sev)
		}
		t.delPoisoned(obs.LineageID) // TTL elapsed: forget entirely, fail open
	}

	// --- Tombstone (already-emitted anchored lineage) ---
	//
	// pre carries notification work handed BACK to the owner because the ledger
	// holding it is being discarded. Every return below must include it: a
	// dropped sibling is an observation whose notify closure the owner would
	// otherwise keep alive forever.
	var pre []Directive
	if tb, exists := t.tombstones[obs.LineageID]; exists {
		if now.Sub(tb.finalizedAt) > t.tombstoneTTL {
			// post-TTL: fail open to a fresh lineage.
			pre = t.abandonQueued(&tb.notify, obs.LineageID)
			t.delTombstone(obs.LineageID)
		} else {
			return append(pre, t.tombstoneAttach(obs.LineageID, tb, obs, sev, now)...)
		}
	}

	ln := t.active[obs.LineageID]
	if ln == nil {
		ln = &lineage{state: stateUnanchored, settleDeadline: now.Add(t.settle)}
		t.putActive(obs.LineageID, ln)
	}

	// --- Anchor bookkeeping (D1) ---
	if obs.IsAnchorSource && ln.anchorSeen {
		// Duplicate anchor: identity-integrity failure. Poison the ID and
		// flush everything for it independently, terminal — including this
		// arriving observation.
		return append(pre, t.poison(obs.LineageID, ln, obs, sev, now)...)
	}
	if obs.IsAnchorSource {
		ln.anchorSeen = true
		ln.state = stateAnchored
	}

	ln.members = append(ln.members, member{eventID: obs.EventID, severity: sev, isAnchor: obs.IsAnchorSource})

	// --- Notification decision (intent only; success recorded via NotifyResult) ---
	return append(pre, t.notifyDecide(&ln.notify, obs.LineageID, ln.state == stateAnchored, sev, obs.EventID)...)
}

// mint allocates the next attempt token. Every notification directive the
// tracker hands out comes from here, so an attempt always has a unique,
// non-zero identity the owner can key its closure and its dependent rows on.
func (t *Tracker) mint() uint64 {
	t.nextToken++
	return t.nextToken
}

// issueIncident mints an attempt AND takes the lineage's single reservation, so
// no second incident attempt can start until this one reports.
func (t *Tracker) issueIncident(lg *notifyLedger, id string, sev Severity, eventID string, kind DirectiveKind) Directive {
	tok := t.mint()
	lg.inFlight = true
	lg.token = tok
	lg.flightSev = sev
	lg.flightEvent = eventID
	return Directive{Kind: kind, EventID: eventID, LineageID: id, Severity: sev, Token: tok}
}

// issueIndependent mints an attempt that takes NO shared state: an un-anchored
// or poisoned observation notifies entirely for itself. Any number may run at
// once; none can overwrite, suppress, or serialize another (round-6 Fix A).
func (t *Tracker) issueIndependent(id string, sev Severity, eventID string) Directive {
	return Directive{Kind: DirNotifyFire, EventID: eventID, LineageID: id, Severity: sev, Token: t.mint()}
}

// notifyDecide applies the lineage notification state machine to one incoming
// observation. It records INTENT only — the success record advances solely
// through NotifyResult (F3).
//
// The anchored flag is the self-labeling defense (D2): an un-anchored stream is
// exempt from BOTH suppression and the single-attempt reservation, so a forged
// ID can neither silence an alert nor serialize one behind another callback.
func (t *Tracker) notifyDecide(lg *notifyLedger, id string, anchored bool, sev Severity, eventID string) []Directive {
	if !sev.Actionable() {
		return nil
	}
	if !anchored {
		// Fully independent: its own token, its own result, no shared slot.
		return []Directive{t.issueIndependent(id, sev, eventID)}
	}
	if lg.inFlight {
		// An attempt for this incident is already running. Queue, never
		// duplicate: releaseQueued decides whether this sibling still needs to
		// fire once the truth about that attempt is known.
		if lg.covered(sev) {
			t.c.notifsAvoided.Add(1)
			return []Directive{{Kind: DirNotifySuppressed, EventID: eventID, LineageID: id, Severity: sev}}
		}
		lg.enqueue(sev, eventID)
		return nil
	}
	if !lg.notified {
		return []Directive{t.issueIncident(lg, id, sev, eventID, DirNotifyFire)}
	}
	if sev > lg.notifiedSev {
		t.c.notifUpgrades.Add(1)
		return []Directive{t.issueIncident(lg, id, sev, eventID, DirNotifyUpgrade)}
	}
	t.c.notifsAvoided.Add(1)
	return []Directive{{Kind: DirNotifySuppressed, EventID: eventID, LineageID: id, Severity: sev}}
}

// NotifyResult feeds one attempt's result back, addressed by its TOKEN.
//
// Two things happen, and they are deliberately separate:
//
//  1. SUCCESS RECORD — any attempt's success advances the incident's monotonic
//     watermark, independent or incident alike. The fact recorded is "this
//     incident was reported at this severity", not "a particular slot finished",
//     which is what lets a pre-anchor backend success dedupe the later anchor.
//  2. RESERVATION — only the token that HOLDS the reservation releases it. An
//     independent or superseded result therefore cannot free a live incident
//     attempt or steal its queue (round-6 Fix A root cause).
//
// On a released reservation the next queued sibling is issued HERE, as returned
// directives the owner applies like any others: that is what keeps a failed
// enqueue from silencing an incident without ever letting two incident attempts
// run at once.
func (t *Tracker) NotifyResult(lineageID string, token uint64, sev Severity, ok bool) []Directive {
	if token == 0 {
		return nil
	}
	lg := t.ledgerFor(lineageID)
	if lg == nil {
		return nil // the ledger is gone (poisoned, reaped): nothing to record
	}
	if ok {
		lg.markNotified(sev)
	}
	if !lg.inFlight || lg.token != token {
		return nil // independent or superseded: it holds no reservation
	}
	lg.inFlight = false
	return t.releaseQueued(lg, lineageID)
}

// releaseQueued gives the next eligible sibling its turn now that the attempt it
// queued behind has reported. Siblings the incident's success already covers are
// suppressed (counted) and skipped; the first one still eligible gets a FRESH
// attempt, and the rest stay queued behind it. At most one attempt ever runs.
func (t *Tracker) releaseQueued(lg *notifyLedger, id string) []Directive {
	var out []Directive
	for {
		q, ok := lg.takeBest()
		if !ok {
			return out
		}
		if lg.covered(q.sev) {
			t.c.notifsAvoided.Add(1)
			out = append(out, Directive{Kind: DirNotifySuppressed, EventID: q.eventID, LineageID: id, Severity: q.sev})
			continue
		}
		kind := DirNotifyFire
		if lg.notified {
			kind = DirNotifyUpgrade
			t.c.notifUpgrades.Add(1)
		}
		return append(out, t.issueIncident(lg, id, q.sev, q.eventID, kind))
	}
}

// abandonQueued hands every queued sibling back to the owner when the ledger
// holding them is being discarded (poisoned, or a reaped tombstone).
// Suppress only work already covered by a successful notification; otherwise
// give it an independent attempt so discarding the ledger cannot lose a retry.
func (t *Tracker) abandonQueued(lg *notifyLedger, id string) []Directive {
	var out []Directive
	for {
		q, ok := lg.takeBest()
		if !ok {
			return out
		}
		if lg.covered(q.sev) {
			out = append(out, Directive{Kind: DirNotifySuppressed, EventID: q.eventID, LineageID: id, Severity: q.sev})
		} else {
			out = append(out, t.issueIndependent(id, q.sev, q.eventID))
		}
	}
}

// AttemptOutstanding reports whether the given token is STILL this lineage's
// reserved in-flight attempt. The owner asks under its own lock, so the answer
// is authoritative for the decision it is about to make: a terminal row write
// must be handed to the attempt, not guessed against it (round-5 P1-3).
func (t *Tracker) AttemptOutstanding(lineageID string, token uint64) bool {
	if token == 0 {
		return false
	}
	lg := t.ledgerFor(lineageID)
	return lg != nil && lg.inFlight && lg.token == token
}

// Notified reports the incident's notification SUCCESS record — the value a
// representative row's Notified column must carry.
func (t *Tracker) Notified(lineageID string) bool {
	lg := t.ledgerFor(lineageID)
	return lg != nil && lg.notified
}

// tombstoneAttach makes a late observation of an anchored, already-emitted
// lineage terminal (DF-A). A second anchor is an integrity failure ⇒ poison.
//
// Notification eligibility (R2-1) is evaluated SEPARATELY from the row
// disposition (R2-4). The row is monotonic-high-water; the notification runs
// the same state machine the lineage used, so a late actionable child can fire
// (or retry, or queue behind a running attempt) even when its own row is
// dropped.
func (t *Tracker) tombstoneAttach(id string, tb *tombstone, obs Observation, sev Severity, now time.Time) []Directive {
	if obs.IsAnchorSource {
		// Duplicate anchor spanning a tombstone (F5): delete the tombstone,
		// poison the ID, emit this observation independently.
		out := t.abandonQueued(&tb.notify, id)
		t.delTombstone(id)
		t.putPoisoned(id, now.Add(t.tombstoneTTL))
		t.c.anchorConflicts.Add(1)
		return append(out, t.terminalIndependent(obs, sev)...)
	}

	// (1) Notification eligibility — independent of the row (R2-1). Fire/upgrade
	// go FIRST in the slice so the sink registers the attempt before the row
	// disposition claims the parked entry.
	out := t.notifyDecide(&tb.notify, id, true, sev, obs.EventID)

	// (2) Row disposition — monotonic high-water (R2-4). Strictly above the
	// high-water mark ⇒ a durable independent row and the mark ADVANCES; at or
	// below ⇒ dropped (the notification above may still stand).
	if sev > tb.highWater {
		tb.highWater = sev
		t.c.lateUpgradesPersisted.Add(1)
		out = append(out, t.terminalDirective(DirEmitIndependent, id, obs.EventID, sev, &tb.notify, false))
	} else {
		t.c.lateSiblings.Add(1)
		out = append(out, t.terminalDirective(DirDrop, id, obs.EventID, sev, &tb.notify, false))
	}
	return out
}

// poison converts an active lineage into an integrity failure: every parked
// member and the arriving observation emit independently (terminal), and the
// ID is poisoned for a full TTL so subsequent observations also stay separate.
func (t *Tracker) poison(id string, ln *lineage, obs Observation, sev Severity, now time.Time) []Directive {
	t.c.anchorConflicts.Add(1)
	t.putPoisoned(id, now.Add(t.tombstoneTTL))

	out := make([]Directive, 0, len(ln.members)+3)
	out = append(out, t.abandonQueued(&ln.notify, id)...)
	for _, m := range ln.members {
		out = append(out, t.terminalDirective(DirEmitIndependent, id, m.eventID, m.severity, &ln.notify, false))
	}
	t.delActive(id)

	out = append(out, t.terminalIndependent(obs, sev)...)
	return out
}

// terminalIndependent emits one observation as its own finding, with a leading
// independent notification if it is actionable. Poisoned/late paths do not
// dedupe — there is nothing to coalesce with — but the attempt is still tokened
// so the owner can key its closure and its row on it like any other.
func (t *Tracker) terminalIndependent(obs Observation, sev Severity) []Directive {
	if sev.Actionable() {
		return []Directive{
			t.issueIndependent(obs.LineageID, sev, obs.EventID),
			{Kind: DirEmitIndependent, EventID: obs.EventID, LineageID: obs.LineageID, Severity: sev},
		}
	}
	return []Directive{{Kind: DirEmitIndependent, EventID: obs.EventID, LineageID: obs.LineageID, Severity: sev}}
}

// terminalDirective builds a row disposition. Token names the INCIDENT
// reservation outstanding at selection, which seeds the owner's incident chain
// when a driver mints a directive without registering it; the owner's own
// per-attempt records cover every registered attempt, independents included.
func (t *Tracker) terminalDirective(kind DirectiveKind, id, eventID string, sev Severity, lg *notifyLedger, notified bool) Directive {
	d := Directive{Kind: kind, EventID: eventID, LineageID: id, Severity: sev, Notified: notified}
	if lg.inFlight {
		d.Token = lg.token
	}
	return d
}

// Tick emits every lineage whose settle window has closed and reaps expired
// tombstones and poisoned IDs.
func (t *Tracker) Tick() []Directive {
	now := t.clock.Now()
	var out []Directive

	for id, ln := range t.active {
		if now.Before(ln.settleDeadline) {
			continue
		}
		out = append(out, t.emitLineage(id, ln, now)...)
		t.delActive(id)
	}
	for id, tb := range t.tombstones {
		if now.Sub(tb.finalizedAt) > t.tombstoneTTL {
			out = append(out, t.abandonQueued(&tb.notify, id)...)
			t.delTombstone(id)
		}
	}
	for id, exp := range t.poisoned {
		if !now.Before(exp) {
			t.delPoisoned(id)
		}
	}
	return out
}

// FlushAll emits EVERY active lineage unconditionally, ignoring settle
// deadlines. Used by the sink's ordered shutdown drain so no parked finding is
// lost. Tombstones and poisoned IDs hold no parked closures, so they need no
// flush.
func (t *Tracker) FlushAll() []Directive {
	now := t.clock.Now()
	var out []Directive
	for id, ln := range t.active {
		out = append(out, t.emitLineage(id, ln, now)...)
		t.delActive(id)
	}
	return out
}

func (t *Tracker) emitLineage(id string, ln *lineage, now time.Time) []Directive {
	// Unanchored ⇒ every member is its own independent finding.
	if ln.state != stateAnchored {
		t.c.unanchoredIDs.Add(1)
		out := make([]Directive, 0, len(ln.members)+1)
		out = append(out, t.abandonQueued(&ln.notify, id)...)
		for _, m := range ln.members {
			out = append(out, t.terminalDirective(DirEmitIndependent, id, m.eventID, m.severity, &ln.notify, false))
		}
		return out
	}

	// Anchored group: one representative row, siblings dropped.
	t.c.groups.Add(1)
	n := len(ln.members)
	if n == 1 {
		t.c.singletonGroups.Add(1)
	} else {
		t.c.multiGroups.Add(1)
		if n >= 3 {
			t.c.groups3plus.Add(1)
		}
	}

	rep := representative(ln.members)
	aggregate := aggregateSeverity(ln.members)
	if divergentSeverity(ln.members) {
		t.c.outcomeConflicts.Add(1)
	}

	out := make([]Directive, 0, n)
	for _, m := range ln.members {
		if m.eventID == rep.eventID {
			out = append(out, t.terminalDirective(DirEmitRepresentative, id, m.eventID, m.severity, &ln.notify, ln.notify.notified))
		} else {
			t.c.observationsAbsorbed.Add(1)
			out = append(out, t.terminalDirective(DirDrop, id, m.eventID, m.severity, &ln.notify, false))
		}
	}

	// Tombstone so a late in-lifetime sibling can persist a durable upgrade.
	// It INHERITS the notification ledger whole — settlement decides the row,
	// never the state of a notification attempt that is still running.
	t.putTombstone(id, &tombstone{
		finalizedAt:           now,
		highWater:             aggregate, // monotonic baseline; advances on accepted late upgrades
		representativeEventID: rep.eventID,
		notify:                ln.notify,
	})
	return out
}

// representative picks the highest-severity member; ties go to the anchor
// child, else the first-arrived (stable) member (D5).
func representative(ms []member) member {
	best := ms[0]
	for _, m := range ms[1:] {
		if m.severity > best.severity {
			best = m
			continue
		}
		if m.severity == best.severity && m.isAnchor && !best.isAnchor {
			best = m
		}
	}
	return best
}

func aggregateSeverity(ms []member) Severity {
	agg := ms[0].severity
	for _, m := range ms[1:] {
		if m.severity > agg {
			agg = m.severity
		}
	}
	return agg
}

func divergentSeverity(ms []member) bool {
	if len(ms) < 2 {
		return false
	}
	first := ms[0].severity
	for _, m := range ms[1:] {
		if m.severity != first {
			return true
		}
	}
	return false
}

// Snapshot returns the current counters (safe to call off-actor).
func (t *Tracker) Snapshot() Counters {
	return Counters{
		UnanchoredIDs:          t.c.unanchoredIDs.Load(),
		Groups:                 t.c.groups.Load(),
		SingletonGroups:        t.c.singletonGroups.Load(),
		MultiObservationGroups: t.c.multiGroups.Load(),
		Groups3Plus:            t.c.groups3plus.Load(),
		ObservationsAbsorbed:   t.c.observationsAbsorbed.Load(),
		AnchorConflicts:        t.c.anchorConflicts.Load(),
		OutcomeConflicts:       t.c.outcomeConflicts.Load(),
		LateSiblings:           t.c.lateSiblings.Load(),
		LateUpgradesPersisted:  t.c.lateUpgradesPersisted.Load(),
		NotificationsAvoided:   t.c.notifsAvoided.Load(),
		NotificationUpgrades:   t.c.notifUpgrades.Load(),
		PendingGroups:          t.c.gPending.Load(),
		Tombstones:             t.c.gTomb.Load(),
		Poisoned:               t.c.gPoison.Load(),
	}
}
