// Package requestcorr implements the post-verdict request-lineage coalescer
// (the third safety boundary of the frozen "Request lineage & proxy
// observation coalescing" design).
//
// It is a state machine that returns DIRECTIVES: Observe/Tick/FlushAll take
// inputs, mutate in-memory state, and describe what the caller (the outcome
// sink) should do — addressed by EventID. It performs no I/O and holds no
// closures; the sink owns findings, notifiers, and stores.
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
// # Notifications (D6, F3)
//
// Correlation may delay the finding ROW but never an actionable NOTIFICATION.
// The ledger records notification INTENT separately from SUCCESS: a decision to
// fire returns a directive, and only NotifyResult(ok=true) marks the lineage
// notified. A failed enqueue leaves the ledger open so the next actionable
// sibling fires again, and a representative's Notified flag reflects real
// success only.
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
// Nothing ever lowers a verdict. The clock is injected.
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
type Directive struct {
	Kind    DirectiveKind
	EventID string
	// Notified is authoritative only on DirEmitRepresentative: whether the
	// GROUP actually notified (ledger success), so the representative row's
	// Notified column reflects the incident. Independent emits read the sink's
	// own per-event notify result instead.
	Notified bool
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

type lineage struct {
	state          lstate
	members        []member
	anchorSeen     bool
	settleDeadline time.Time
	notified       bool     // ledger: a fire SUCCEEDED (F3), not merely intended
	notifiedSev    Severity // highest severity actually notified
}

type tombstone struct {
	finalizedAt time.Time
	highWater   Severity // MONOTONIC severity baseline (R2-4): starts at the settled
	// aggregate and advances each time a late upgrade row is
	// accepted, so equal/lower stragglers add no further rows.
	representativeEventID string   // the emitted representative (retained for the record; DF-A)
	notified              bool     // ledger: a late/settle fire SUCCEEDED (F3 success state)
	notifiedSev           Severity // highest severity actually notified for this incident
}

// Tracker is the coalescer state machine. Single-owner: see package doc.
type Tracker struct {
	clock        Clock
	settle       time.Duration
	tombstoneTTL time.Duration

	active     map[string]*lineage   // not-yet-emitted lineages
	tombstones map[string]*tombstone // emitted anchored lineages (late-attach window)
	poisoned   map[string]time.Time  // id → expiry; integrity-failed IDs, fail open after TTL

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
		return []Directive{{Kind: DirEmitIndependent, EventID: obs.EventID}}
	}

	// --- Poisoned lookup FIRST (F5): spans tombstones ---
	if exp, isP := t.poisoned[obs.LineageID]; isP {
		if now.Before(exp) {
			return t.terminalIndependent(obs, sev)
		}
		t.delPoisoned(obs.LineageID) // TTL elapsed: forget entirely, fail open
	}

	// --- Tombstone (already-emitted anchored lineage) ---
	if tb, exists := t.tombstones[obs.LineageID]; exists {
		if now.Sub(tb.finalizedAt) > t.tombstoneTTL {
			t.delTombstone(obs.LineageID) // post-TTL: fail open to a fresh lineage
		} else {
			return t.tombstoneAttach(obs.LineageID, tb, obs, sev, now)
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
		return t.poison(obs.LineageID, ln, obs, sev, now)
	}
	if obs.IsAnchorSource {
		ln.anchorSeen = true
		ln.state = stateAnchored
	}

	ln.members = append(ln.members, member{eventID: obs.EventID, severity: sev, isAnchor: obs.IsAnchorSource})

	// --- Notification decision (intent only; success recorded via NotifyResult) ---
	if dir := t.notifyDecision(ln, sev, obs.EventID); dir != nil {
		return []Directive{*dir}
	}
	return nil
}

// notifyDecision applies the ledger and returns a notification directive (or
// nil for a non-actionable observation). It records INTENT only — ln.notified
// is updated by NotifyResult on success (F3).
func (t *Tracker) notifyDecision(ln *lineage, sev Severity, eventID string) *Directive {
	if !sev.Actionable() {
		return nil
	}
	// First actionable child not yet notified ⇒ fire (pre-anchor included).
	if !ln.notified {
		return &Directive{Kind: DirNotifyFire, EventID: eventID}
	}
	// Subsequent actionable child. Dedup applies ONLY when the lineage is
	// anchor-participating (anchored). An un-anchored actionable stream fires
	// every time — the self-labeling defense (nothing to suppress).
	if ln.state != stateAnchored {
		return &Directive{Kind: DirNotifyFire, EventID: eventID}
	}
	if sev > ln.notifiedSev {
		t.c.notifUpgrades.Add(1)
		return &Directive{Kind: DirNotifyUpgrade, EventID: eventID}
	}
	t.c.notifsAvoided.Add(1)
	return &Directive{Kind: DirNotifySuppressed, EventID: eventID}
}

// NotifyResult feeds a fire/upgrade closure's success back into the ledger.
// Called by the actor immediately after executing a notification directive.
// The ledger advances ONLY on ok (F3): a failed enqueue leaves it open so the
// next actionable sibling re-fires, and representative rows reflect real
// success.
func (t *Tracker) NotifyResult(lineageID, eventID string, sev Severity, ok bool) {
	if !ok {
		return
	}
	if ln := t.active[lineageID]; ln != nil {
		ln.notified = true
		if sev > ln.notifiedSev {
			ln.notifiedSev = sev
		}
		return
	}
	if tb := t.tombstones[lineageID]; tb != nil {
		tb.notified = true
		if sev > tb.notifiedSev {
			tb.notifiedSev = sev
		}
	}
}

// tombstoneAttach makes a late observation of an anchored, already-emitted
// lineage terminal (DF-A). A second anchor is an integrity failure ⇒ poison.
//
// Round-4: notification eligibility (R2-1) is evaluated SEPARATELY from the row
// disposition (R2-4). The row is monotonic-high-water; the notification is
// gated only on the incident's SUCCESS record, so a late actionable child can
// fire (or retry) an alert even when its own row is dropped.
func (t *Tracker) tombstoneAttach(id string, tb *tombstone, obs Observation, sev Severity, now time.Time) []Directive {
	if obs.IsAnchorSource {
		// Duplicate anchor spanning a tombstone (F5): delete the tombstone,
		// poison the ID, emit this observation independently.
		t.delTombstone(id)
		t.putPoisoned(id, now.Add(t.tombstoneTTL))
		t.c.anchorConflicts.Add(1)
		return t.terminalIndependent(obs, sev)
	}

	// (1) Notification eligibility — independent of the row (R2-1). Fire/upgrade
	// go FIRST in the slice so the sink records the result (NotifyResult) before
	// any Drop deletes the parked entry.
	out := t.tombstoneNotifyEligibility(tb, sev, obs.EventID)

	// (2) Row disposition — monotonic high-water (R2-4). Strictly above the
	// high-water mark ⇒ a durable independent row and the mark ADVANCES; at or
	// below ⇒ dropped (the notification above may still stand).
	if sev > tb.highWater {
		tb.highWater = sev
		t.c.lateUpgradesPersisted.Add(1)
		out = append(out, Directive{Kind: DirEmitIndependent, EventID: obs.EventID})
	} else {
		t.c.lateSiblings.Add(1)
		out = append(out, Directive{Kind: DirDrop, EventID: obs.EventID})
	}
	return out
}

// tombstoneNotifyEligibility returns a leading notification directive (or none)
// for a late actionable child, gated on the tombstone's SUCCESS record (F3):
// never-notified ⇒ Fire; notified-but-this-is-more-severe ⇒ Upgrade; already
// covered ⇒ suppress. The sink feeds the enqueue result back via NotifyResult,
// so a FAILED attempt leaves eligibility open for the next sibling.
func (t *Tracker) tombstoneNotifyEligibility(tb *tombstone, sev Severity, eventID string) []Directive {
	if !sev.Actionable() {
		return nil
	}
	if !tb.notified {
		return []Directive{{Kind: DirNotifyFire, EventID: eventID}}
	}
	if sev > tb.notifiedSev {
		t.c.notifUpgrades.Add(1)
		return []Directive{{Kind: DirNotifyUpgrade, EventID: eventID}}
	}
	t.c.notifsAvoided.Add(1)
	return nil
}

// poison converts an active lineage into an integrity failure: every parked
// member and the arriving observation emit independently (terminal), and the
// ID is poisoned for a full TTL so subsequent observations also stay separate.
func (t *Tracker) poison(id string, ln *lineage, obs Observation, sev Severity, now time.Time) []Directive {
	t.c.anchorConflicts.Add(1)
	t.putPoisoned(id, now.Add(t.tombstoneTTL))

	out := make([]Directive, 0, len(ln.members)+2)
	for _, m := range ln.members {
		out = append(out, Directive{Kind: DirEmitIndependent, EventID: m.eventID})
	}
	t.delActive(id)

	out = append(out, t.terminalIndependent(obs, sev)...)
	return out
}

// terminalIndependent emits one observation as its own finding, with a leading
// independent notification if it is actionable (poisoned/late paths do not
// dedupe — there is nothing to coalesce with).
func (t *Tracker) terminalIndependent(obs Observation, sev Severity) []Directive {
	if sev.Actionable() {
		return []Directive{
			{Kind: DirNotifyFire, EventID: obs.EventID},
			{Kind: DirEmitIndependent, EventID: obs.EventID},
		}
	}
	return []Directive{{Kind: DirEmitIndependent, EventID: obs.EventID}}
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
		out := make([]Directive, 0, len(ln.members))
		for _, m := range ln.members {
			out = append(out, Directive{Kind: DirEmitIndependent, EventID: m.eventID})
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
			out = append(out, Directive{Kind: DirEmitRepresentative, EventID: m.eventID, Notified: ln.notified})
		} else {
			t.c.observationsAbsorbed.Add(1)
			out = append(out, Directive{Kind: DirDrop, EventID: m.eventID})
		}
	}

	// Tombstone so a late in-lifetime sibling can persist a durable upgrade.
	t.putTombstone(id, &tombstone{
		finalizedAt:           now,
		highWater:             aggregate, // monotonic baseline; advances on accepted late upgrades
		representativeEventID: rep.eventID,
		notified:              ln.notified,
		notifiedSev:           ln.notifiedSev,
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
