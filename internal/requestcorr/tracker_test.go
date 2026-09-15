package requestcorr

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestTracker() (*Tracker, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return New(Config{}, clk), clk
}

const (
	anchorSrc = "captain-nginx"
	backSrc   = "wp"
	idA       = "2fb2cf19c82b36ceb7f89d50b381fcf1"
	idB       = "d222b0a4b75f01a12a7c1c4d2174cd2c"
)

func obs(id, src string, anchor bool, event string, o Outcome) Observation {
	return Observation{LineageID: id, Source: src, IsAnchorSource: anchor, EventID: event, Outcome: o}
}

func countKind(ds []Directive, k DirectiveKind) int {
	n := 0
	for _, d := range ds {
		if d.Kind == k {
			n++
		}
	}
	return n
}

func firstOfKind(ds []Directive, k DirectiveKind) (Directive, bool) {
	for _, d := range ds {
		if d.Kind == k {
			return d, true
		}
	}
	return Directive{}, false
}

// Backend-first is the COMMON case (Apache logs before nginx). Two escalations
// of one request (the 4-emails-for-2-harvests bug): backend notifies, nginx
// suppresses, and after settle ONE representative row (tie → anchor) emits.
func TestBackendFirstEscalationCoalesces(t *testing.T) {
	tr, clk := newTestTracker()

	d1 := tr.Observe(obs(idA, backSrc, false, "ev_back", OutcomeEscalated))
	if countKind(d1, DirNotifyFire) != 1 {
		t.Fatalf("backend escalation should notify immediately, got %+v", d1)
	}
	// F3 (round-2): the ledger records SUCCESS, not intent. The owner feeds the
	// enqueue result back; only then does the next actionable sibling dedupe.
	// Round-5: the result is addressed by the ATTEMPT TOKEN the directive minted,
	// not by EventID — a superseded attempt can no longer disturb a live one.
	fire1, _ := firstOfKind(d1, DirNotifyFire)
	tr.NotifyResult(idA, fire1.Token, SevActionable, true)

	d2 := tr.Observe(obs(idA, anchorSrc, true, "ev_nginx", OutcomeEscalated))
	if countKind(d2, DirNotifySuppressed) != 1 {
		t.Fatalf("anchor escalation should be suppressed (already notified), got %+v", d2)
	}

	clk.advance(DefaultSettleWindow + time.Second)
	em := tr.Tick()
	rep, ok := firstOfKind(em, DirEmitRepresentative)
	if !ok {
		t.Fatalf("expected a representative emit, got %+v", em)
	}
	if rep.EventID != "ev_nginx" {
		t.Errorf("representative should be the anchor child on a severity tie, got %q", rep.EventID)
	}
	if !rep.Notified {
		t.Errorf("representative row must be marked Notified (the group was notified)")
	}
	if countKind(em, DirDrop) != 1 {
		t.Errorf("the backend sibling row must be dropped, got %+v", em)
	}

	c := tr.Snapshot()
	if c.Groups != 1 || c.MultiObservationGroups != 1 || c.ObservationsAbsorbed != 1 || c.NotificationsAvoided != 1 {
		t.Errorf("counters off: %+v", c)
	}
}

// Duplicate anchor (same ID, two ingress-role observations) is an
// identity-integrity failure: poison, count, and keep everything separate.
func TestDuplicateAnchorPoisons(t *testing.T) {
	tr, _ := newTestTracker()
	tr.Observe(obs(idA, anchorSrc, true, "ev1", OutcomeUnresolved))
	// Round-2 (F5): a duplicate anchor poisons the ID and flushes everything
	// for it TERMINALLY at Observe time (no waiting for settle) — the parked
	// first member plus the arriving one both emit independently.
	d := tr.Observe(obs(idA, "other-edge", true, "ev2", OutcomeUnresolved))
	if countKind(d, DirEmitIndependent) != 2 {
		t.Errorf("duplicate anchor must flush both members independently at Observe, got %+v", d)
	}
	if countKind(d, DirEmitRepresentative) != 0 {
		t.Errorf("poisoned lineage must not coalesce")
	}
	if c := tr.Snapshot(); c.AnchorConflicts != 1 {
		t.Fatalf("anchor_conflicts = %d, want 1", c.AnchorConflicts)
	}
	// A further observation of the poisoned ID also emits independently.
	d3 := tr.Observe(obs(idA, backSrc, false, "ev3", OutcomeUnresolved))
	if countKind(d3, DirEmitIndependent) != 1 {
		t.Errorf("poisoned ID keeps everything separate, got %+v", d3)
	}
}

// A downstream-only observation parks, and if no anchor arrives it emits
// independently at settle.
func TestUnanchoredParksThenEmitsSingleton(t *testing.T) {
	tr, clk := newTestTracker()
	tr.Observe(obs(idA, backSrc, false, "ev1", OutcomeRecon))
	if em := tr.Tick(); len(em) != 0 {
		t.Fatalf("nothing should emit before settle, got %+v", em)
	}
	clk.advance(DefaultSettleWindow + time.Millisecond)
	em := tr.Tick()
	if countKind(em, DirEmitIndependent) != 1 {
		t.Fatalf("unanchored singleton must emit independently, got %+v", em)
	}
	if c := tr.Snapshot(); c.UnanchoredIDs != 1 || c.Groups != 0 {
		t.Errorf("counters off: %+v", c)
	}
}

// Least-safe wins (D4): a downgrade + an unresolved sibling must NOT downgrade
// the group — the representative is the unresolved child, and the divergence
// is counted.
func TestDivergentOutcomesGroupNotDowngraded(t *testing.T) {
	tr, clk := newTestTracker()
	tr.Observe(obs(idA, anchorSrc, true, "ev_anchor_down", OutcomeDowngraded))
	tr.Observe(obs(idA, backSrc, false, "ev_back_unres", OutcomeUnresolved))

	clk.advance(DefaultSettleWindow + time.Second)
	em := tr.Tick()
	rep, ok := firstOfKind(em, DirEmitRepresentative)
	if !ok || rep.EventID != "ev_back_unres" {
		t.Errorf("representative must be the least-safe (unresolved) child, got %+v", em)
	}
	if c := tr.Snapshot(); c.OutcomeConflicts != 1 {
		t.Errorf("outcome_conflicts = %d, want 1", c.OutcomeConflicts)
	}
}

// Escalation notifies on Observe, before any Tick (D6 immediacy).
func TestEscalationNotifiesImmediately(t *testing.T) {
	tr, _ := newTestTracker()
	d := tr.Observe(obs(idA, backSrc, false, "ev1", OutcomeEscalated))
	if countKind(d, DirNotifyFire) != 1 {
		t.Fatalf("escalation must notify immediately on Observe, got %+v", d)
	}
}

// Round-4 (R2-1 + R2-4): a late sibling of an anchored, already-emitted group is
// TERMINAL, with the ROW gated on a monotonic high-water mark and the
// NOTIFICATION gated separately on the incident's success record.
func TestTombstoneAttachLateUpgradeIsDurable(t *testing.T) {
	tr, clk := newTestTracker()
	// Anchor DOWNGRADED (safe) and never notified ⇒ high-water = SevSafe,
	// tombstone.notified = false.
	tr.Observe(obs(idA, anchorSrc, true, "ev_anchor", OutcomeDowngraded))
	clk.advance(DefaultSettleWindow + time.Second)
	tr.Tick() // emit + tombstone

	// Late at/below high-water (recon == safe), non-actionable: dropped, no notify.
	clk.advance(time.Second)
	dLow := tr.Observe(obs(idA, backSrc, false, "ev_late_safe", OutcomeRecon))
	if countKind(dLow, DirDrop) != 1 || dLow[0].Kind != DirDrop {
		t.Errorf("a late at/below-high-water sibling must be dropped, got %+v", dLow)
	}

	// Late strictly above high-water (escalation): its OWN durable row PLUS a
	// notification. Because the incident never successfully notified, this is a
	// first FIRE (not an upgrade), and it advances the high-water mark.
	dHigh := tr.Observe(obs(idA, backSrc, false, "ev_late_esc", OutcomeEscalated))
	if countKind(dHigh, DirEmitIndependent) != 1 {
		t.Errorf("a late escalation must persist its own independent row, got %+v", dHigh)
	}
	if countKind(dHigh, DirNotifyFire) != 1 {
		t.Errorf("a late escalation on a never-notified incident must FIRE the alert, got %+v", dHigh)
	}
	// A second, equally-severe late escalation now: high-water no longer below ⇒
	// no new row; and (were the first fire successful) no further notify.
	lateFire, _ := firstOfKind(dHigh, DirNotifyFire)
	tr.NotifyResult(idA, lateFire.Token, SevActionable, true) // record the fire's success
	dHigh2 := tr.Observe(obs(idA, backSrc, false, "ev_late_esc2", OutcomeEscalated))
	if countKind(dHigh2, DirEmitIndependent) != 0 || countKind(dHigh2, DirDrop) != 1 {
		t.Errorf("equal-severity straggler must add no row (monotonic high-water), got %+v", dHigh2)
	}
	c := tr.Snapshot()
	if c.LateSiblings != 2 || c.LateUpgradesPersisted != 1 || c.NotificationUpgrades != 0 {
		t.Errorf("counters off: %+v", c)
	}
}

// Post-TTL, a fresh observation of the same ID fails open to a new finding.
func TestPostTTLFailOpen(t *testing.T) {
	tr, clk := newTestTracker()
	tr.Observe(obs(idA, anchorSrc, true, "ev1", OutcomeUnresolved))
	clk.advance(DefaultSettleWindow + time.Second)
	tr.Tick()

	clk.advance(DefaultTombstoneTTL + time.Second) // tombstone expired
	tr.Observe(obs(idA, backSrc, false, "ev2", OutcomeUnresolved))
	clk.advance(DefaultSettleWindow + time.Second)
	em := tr.Tick()
	if countKind(em, DirEmitIndependent) != 1 {
		t.Errorf("post-TTL downstream-only must fail open to a new independent finding, got %+v", em)
	}
}

// Three-observation group (anchor + two downstream) is counted as 3+.
func TestThreeObservationGroup(t *testing.T) {
	tr, clk := newTestTracker()
	tr.Observe(obs(idA, backSrc, false, "ev1", OutcomeUnresolved))
	tr.Observe(obs(idA, backSrc, false, "ev2", OutcomeUnresolved))
	tr.Observe(obs(idA, anchorSrc, true, "ev_anchor", OutcomeUnresolved))
	clk.advance(DefaultSettleWindow + time.Second)
	em := tr.Tick()
	if countKind(em, DirEmitRepresentative) != 1 || countKind(em, DirDrop) != 2 {
		t.Errorf("3-obs group must emit 1 rep + 2 drops, got %+v", em)
	}
	if c := tr.Snapshot(); c.Groups3Plus != 1 || c.ObservationsAbsorbed != 2 {
		t.Errorf("counters off: %+v", c)
	}
}

// ADVERSARIAL (A2+): given N distinct backend-only observations of one
// self-labeled ID reaching the tracker, none coalesce and none suppress a
// notification — no anchor, "nothing to gain". (This is the tracker-level
// property; end to end, the upstream coordinator may huddle identical-shape
// requests before they ever become N separate outcomes — the sink never
// promises N-in ⇒ N-findings under a flood, only that it merges nothing here.)
func TestSelfLabeledFloodStaysSeparate(t *testing.T) {
	tr, clk := newTestTracker()
	const N = 8
	fires := 0
	for i := 0; i < N; i++ {
		d := tr.Observe(obs(idA, backSrc, false, eventID(i), OutcomeEscalated))
		fires += countKind(d, DirNotifyFire)
	}
	if fires != N {
		t.Fatalf("self-labeled flood must notify %d times, got %d", N, fires)
	}
	clk.advance(DefaultSettleWindow + time.Second)
	em := tr.Tick()
	if countKind(em, DirEmitIndependent) != N {
		t.Errorf("flood must yield %d independent findings, got %d", N, countKind(em, DirEmitIndependent))
	}
	if c := tr.Snapshot(); c.NotificationsAvoided != 0 {
		t.Errorf("no suppression may occur without an anchor, notifs_avoided=%d", c.NotificationsAvoided)
	}
}

// ADVERSARIAL: distinct IDs never cross-contaminate.
func TestDistinctIDsIndependent(t *testing.T) {
	tr, clk := newTestTracker()
	tr.Observe(obs(idA, anchorSrc, true, "a1", OutcomeUnresolved))
	tr.Observe(obs(idB, anchorSrc, true, "b1", OutcomeUnresolved))
	clk.advance(DefaultSettleWindow + time.Second)
	em := tr.Tick()
	if countKind(em, DirEmitRepresentative) != 2 {
		t.Errorf("two distinct anchored singletons expected, got %+v", em)
	}
	if c := tr.Snapshot(); c.SingletonGroups != 2 {
		t.Errorf("singleton_groups = %d, want 2", c.SingletonGroups)
	}
}

func eventID(i int) string {
	return "ev_" + string(rune('a'+i))
}
