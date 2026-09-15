// httpoutcomesink_permutation_test.go
//
// PROOF OF THE COMBINATION SPACE (round-6).
//
// Rounds 2–5 were each closed by a reviewer finding one more schedule the model
// could not represent. Rather than wait for the next one, this enumerates the
// space the per-attempt model is defined over and asserts the model's three
// invariants on every point in it:
//
//	{2 independent observations}
//	  × {anchor: absent / before both / between / after both}
//	  × {anchor severity: safe / actionable}
//	  × {each attempt: ok / fail}                       (3 attempts ⇒ 8)
//	  × {settle: before / between / after the held applies}
//	  × {apply order: forward / reverse}
//	  × {anchor directives: applied at Observe / held}
//
// Every point drives the REAL boundaries — tracker.Observe, selectLocked under
// the sink lock, apply outside it, Tick, the TTL sweep and Shutdown — with the
// manual clock and no sleeps, so the whole suite is deterministic and fast.
//
// The invariants (all three must hold at every point):
//
//	I1 NOTIFICATION CARDINALITY. No observation notifies twice. An observation
//	   made while the lineage was un-anchored ALWAYS notifies for itself
//	   (the self-labeling defense: nothing may suppress an independent). An
//	   anchored actionable observation may skip notifying only if some attempt
//	   for the incident actually SUCCEEDED — being deduped against a sibling
//	   whose attempt then failed is silencing, not coalescing.
//
//	I2 NO STALE ROW. Every finding row is written exactly once, and its Notified
//	   column equals the final truth of the chain that owned it: the incident's
//	   outcome for a representative, the observation's OWN outcome for an
//	   independent row. A sibling's success never turns a failed observation's
//	   own flag true.
//
//	I3 NOTHING LEAKS. After the final settle, the tombstone TTL sweep and
//	   Shutdown, the sink owns nothing: no parked closure, no attempt record,
//	   no registry entry.
package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/requestcorr"
)

// permObs is one observation in a scheduled permutation.
type permObs struct {
	event   string
	source  string // permAnchorSource anchors the lineage
	outcome requestcorr.Outcome
	ok      bool // what its notify closure returns
	hold    bool // hold its directives for later instead of applying at Observe
}

const permAnchorSource = "edge"

// permResult is what a single scheduled run observed.
type permResult struct {
	mu        sync.Mutex
	attempts  map[string]int  // eventID → notify invocations
	succeeded map[string]bool // eventID → its own attempt returned true
	rowFlag   map[string]bool // eventID → the Notified column it persisted
	rowCount  map[string]int  // eventID → finding rows written
	rowKind   map[string]requestcorr.DirectiveKind
	parked    int
	attemptsL int
	work      int

	// repExpected, when set, is the incident truth as of the moment the
	// representative's chain closed. Schedules that add observations AFTER the
	// representative resolved must compare against that, not against every
	// success the incident ever accumulated.
	repExpected *bool
}

func (r *permResult) anySuccess() bool {
	for _, ok := range r.succeeded {
		if ok {
			return true
		}
	}
	return false
}

// runPermutation drives one schedule end to end and returns what it observed.
//
// settleAt is the index in the held-apply sequence at which the settle happens
// (0 = before every held apply, len = after all of them).
func runPermutation(seq []permObs, settleAt int, reverse bool) *permResult {
	r := &permResult{
		attempts:  map[string]int{},
		succeeded: map[string]bool{},
		rowFlag:   map[string]bool{},
		rowCount:  map[string]int{},
		rowKind:   map[string]requestcorr.DirectiveKind{},
	}

	s := newHTTPOutcomeSink(Config{
		LineageEnabled:       true,
		LineageAnchorSources: map[string]bool{permAnchorSource: true},
	})
	clk := &manualClock{t: time.Unix(1_700_000_000, 0)}
	s.tracker = requestcorr.New(requestcorr.Config{}, clk)

	closures := func(o permObs) (func() bool, func(bool)) {
		return func() bool {
				r.mu.Lock()
				r.attempts[o.event]++
				if o.ok {
					r.succeeded[o.event] = true
				}
				r.mu.Unlock()
				return o.ok
			}, func(n bool) {
				r.mu.Lock()
				r.rowFlag[o.event] = n
				r.rowCount[o.event]++
				r.mu.Unlock()
			}
	}

	noteKinds := func(ds []requestcorr.Directive) {
		r.mu.Lock()
		for _, d := range ds {
			if d.Kind.IsTerminal() {
				r.rowKind[d.EventID] = d.Kind
			}
		}
		r.mu.Unlock()
	}

	// Observe: held observations stop at the real post-selection boundary (park,
	// Observe and selectLocked under the lock, apply deferred); the rest go
	// through the production entry point.
	var held [][]requestcorr.Directive
	for _, o := range seq {
		nf, wf := closures(o)
		if !o.hold {
			s.Emit(outcome(o.event, o.source, o.outcome, nf, wf))
			continue
		}
		sev, _ := requestcorr.SeverityOf(o.outcome)
		s.mu.Lock()
		s.parked[o.event] = &parkedOutcome{notify: nf, writeFinding: wf, lineageID: reviewLineageID, sev: sev}
		ds := s.tracker.Observe(requestcorr.Observation{
			LineageID:      reviewLineageID,
			Source:         o.source,
			IsAnchorSource: o.source == permAnchorSource,
			EventID:        o.event,
			Outcome:        o.outcome,
		})
		s.selectLocked(ds)
		s.mu.Unlock()
		noteKinds(ds)
		held = append(held, ds)
	}

	settle := func(advance time.Duration) {
		clk.advance(advance)
		s.mu.Lock()
		ds := s.tracker.Tick()
		s.selectLocked(ds)
		s.mu.Unlock()
		noteKinds(ds)
		s.apply(ds)
	}

	order := make([]int, len(held))
	for i := range order {
		order[i] = i
	}
	if reverse {
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	}
	if settleAt > len(order) {
		settleAt = len(order)
	}

	for i := 0; i <= len(order); i++ {
		if i == settleAt {
			settle(requestcorr.DefaultSettleWindow + time.Second)
		}
		if i < len(order) {
			s.apply(held[order[i]])
		}
	}

	// Final settle, tombstone/poison TTL sweep, ordered shutdown.
	settle(requestcorr.DefaultSettleWindow + time.Second)
	settle(requestcorr.DefaultTombstoneTTL + time.Second)
	s.Shutdown()

	s.mu.Lock()
	r.parked, r.attemptsL, r.work = len(s.parked), len(s.attempts), len(s.work)
	s.mu.Unlock()
	return r
}

func TestPermutationLifecycleSpace(t *testing.T) {
	backendOutcome := requestcorr.OutcomeEscalated // both independents are actionable
	anchorOutcomes := []requestcorr.Outcome{requestcorr.OutcomeRecon, requestcorr.OutcomeEscalated}
	bools := []bool{true, false}

	ran := 0
	for _, anchorPos := range []int{-1, 0, 1, 2} { // absent / before both / between / after both
		for _, anchorOut := range anchorOutcomes {
			for _, holdAnchor := range bools {
				for _, ok1 := range bools {
					for _, ok2 := range bools {
						for _, okA := range bools {
							b1 := permObs{event: "b1", source: "backend", outcome: backendOutcome, ok: ok1, hold: true}
							b2 := permObs{event: "b2", source: "backend2", outcome: backendOutcome, ok: ok2, hold: true}
							an := permObs{event: "anchor", source: permAnchorSource, outcome: anchorOut, ok: okA, hold: holdAnchor}

							var seq []permObs
							switch anchorPos {
							case -1:
								seq = []permObs{b1, b2}
							case 0:
								seq = []permObs{an, b1, b2}
							case 1:
								seq = []permObs{b1, an, b2}
							default:
								seq = []permObs{b1, b2, an}
							}

							// anchored[e]: was the lineage anchored when e was observed?
							anchored := map[string]bool{}
							seen := false
							for _, o := range seq {
								anchored[o.event] = seen
								if o.source == permAnchorSource {
									seen = true
								}
							}

							heldCount := 0
							for _, o := range seq {
								if o.hold {
									heldCount++
								}
							}

							for settleAt := 0; settleAt <= heldCount; settleAt++ {
								if settleAt != 0 && settleAt != 1 && settleAt != heldCount {
									continue // before / between / after
								}
								for _, reverse := range bools {
									name := fmt.Sprintf("anchor%d_%s_hold%v_ok%v%v%v_settle%d_rev%v",
										anchorPos, anchorOut, holdAnchor, ok1, ok2, okA, settleAt, reverse)
									ran++
									t.Run(name, func(t *testing.T) {
										r := runPermutation(seq, settleAt, reverse)
										assertPermutationInvariants(t, seq, anchored, r)
									})
								}
							}
						}
					}
				}
			}
		}
	}
	if ran < 200 {
		t.Fatalf("permutation space too small: %d schedules enumerated", ran)
	}
	t.Logf("enumerated %d schedules", ran)
}

func assertPermutationInvariants(t *testing.T, seq []permObs, anchored map[string]bool, r *permResult) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()

	incidentNotified := r.anySuccess()
	repTruth := incidentNotified
	if r.repExpected != nil {
		repTruth = *r.repExpected
	}

	// --- I1: notification cardinality ---
	for _, o := range seq {
		sev, _ := requestcorr.SeverityOf(o.outcome)
		n := r.attempts[o.event]
		if !sev.Actionable() {
			if n != 0 {
				t.Fatalf("I1: non-actionable %s notified %d times", o.event, n)
			}
			continue
		}
		if n > 1 {
			t.Fatalf("I1: %s notified %d times (duplicate alert for one observation)", o.event, n)
		}
		if !anchored[o.event] {
			if n != 1 {
				t.Fatalf("I1: independent observation %s must notify for itself, got %d", o.event, n)
			}
			continue
		}
		if n == 0 && !incidentNotified {
			t.Fatalf("I1: anchored actionable %s never notified and no attempt for the incident succeeded", o.event)
		}
	}

	// --- I2: no stale row ---
	for _, o := range seq {
		kind, selected := r.rowKind[o.event]
		got := r.rowCount[o.event]
		switch {
		case !selected:
			t.Fatalf("I2: %s never received a terminal disposition", o.event)
		case kind == requestcorr.DirDrop:
			if got != 0 {
				t.Fatalf("I2: dropped %s wrote %d rows", o.event, got)
			}
			continue
		case got != 1:
			t.Fatalf("I2: %s wrote %d rows, want exactly 1", o.event, got)
		}
		want := r.succeeded[o.event] // an independent row carries its OWN result
		if kind == requestcorr.DirEmitRepresentative {
			want = repTruth
		}
		if r.rowFlag[o.event] != want {
			t.Fatalf("I2: %s row (%v) persisted Notified=%v, final truth is %v",
				o.event, kind, r.rowFlag[o.event], want)
		}
	}

	// --- I3: nothing leaks ---
	if r.parked != 0 || r.attemptsL != 0 || r.work != 0 {
		t.Fatalf("I3: sink still owns work after settle+sweep+Shutdown: parked=%d attempts=%d registry=%d",
			r.parked, r.attemptsL, r.work)
	}
}

// TestPermutationPostSettleSpace proves the OTHER half of the space: what
// happens to an incident after it has already settled. Rounds 2–4 each found a
// bug here, so it gets the same enumeration treatment.
//
//	{settled anchored incident: safe / actionable, its attempt ok / fail}
//	  × {late sibling 1: safe / actionable, ok / fail}
//	  × {late sibling 2: from a backend, or a DUPLICATE ANCHOR that poisons}
//	  × {late sibling 2: safe / actionable, ok / fail}
//	  × {apply order: forward / reverse} × {settle between the late applies}
//
// The base phase runs through the real Emit and completes before the settle, so
// the representative's chain closes with the base truth; the late observations
// are held at the real Observe/selectLocked boundary and applied afterwards,
// which is where a tombstone attach, a monotonic high-water drop and a poisoned
// flush all become reachable.
func TestPermutationPostSettleSpace(t *testing.T) {
	outs := []requestcorr.Outcome{requestcorr.OutcomeRecon, requestcorr.OutcomeEscalated}
	bools := []bool{true, false}

	ran := 0
	for _, baseOut := range outs {
		for _, baseOk := range bools {
			for _, late1Out := range outs {
				for _, late1Ok := range bools {
					for _, dupAnchor := range bools {
						for _, late2Out := range outs {
							for _, late2Ok := range bools {
								for _, reverse := range bools {
									for _, settleBetween := range bools {
										base := permObs{event: "anchor", source: permAnchorSource, outcome: baseOut, ok: baseOk}
										late1 := permObs{event: "late1", source: "backend", outcome: late1Out, ok: late1Ok, hold: true}
										src2 := "backend2"
										if dupAnchor {
											src2 = permAnchorSource
										}
										late2 := permObs{event: "late2", source: src2, outcome: late2Out, ok: late2Ok, hold: true}

										name := fmt.Sprintf("base%s%v_l1%s%v_dup%v_l2%s%v_rev%v_mid%v",
											baseOut, baseOk, late1Out, late1Ok, dupAnchor, late2Out, late2Ok, reverse, settleBetween)
										ran++
										t.Run(name, func(t *testing.T) {
											seq := []permObs{base, late1, late2}
											anchored := map[string]bool{"anchor": false, "late1": true, "late2": true}
											r := runPostSettleSchedule(base, []permObs{late1, late2}, reverse, settleBetween)
											assertPermutationInvariants(t, seq, anchored, r)
										})
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if ran < 200 {
		t.Fatalf("post-settle space too small: %d schedules enumerated", ran)
	}
	t.Logf("enumerated %d schedules", ran)
}

func runPostSettleSchedule(base permObs, late []permObs, reverse, settleBetween bool) *permResult {
	r := &permResult{
		attempts:  map[string]int{},
		succeeded: map[string]bool{},
		rowFlag:   map[string]bool{},
		rowCount:  map[string]int{},
		rowKind:   map[string]requestcorr.DirectiveKind{},
	}

	s := newHTTPOutcomeSink(Config{
		LineageEnabled:       true,
		LineageAnchorSources: map[string]bool{permAnchorSource: true},
	})
	clk := &manualClock{t: time.Unix(1_700_000_000, 0)}
	s.tracker = requestcorr.New(requestcorr.Config{}, clk)

	closures := func(o permObs) (func() bool, func(bool)) {
		return func() bool {
				r.mu.Lock()
				r.attempts[o.event]++
				if o.ok {
					r.succeeded[o.event] = true
				}
				r.mu.Unlock()
				return o.ok
			}, func(n bool) {
				r.mu.Lock()
				r.rowFlag[o.event] = n
				r.rowCount[o.event]++
				r.mu.Unlock()
			}
	}
	noteKinds := func(ds []requestcorr.Directive) {
		r.mu.Lock()
		for _, d := range ds {
			if d.Kind.IsTerminal() {
				r.rowKind[d.EventID] = d.Kind
			}
		}
		r.mu.Unlock()
	}
	settle := func(advance time.Duration) {
		clk.advance(advance)
		s.mu.Lock()
		ds := s.tracker.Tick()
		s.selectLocked(ds)
		s.mu.Unlock()
		noteKinds(ds)
		s.apply(ds)
	}

	// Base phase: real Emit, fully resolved before the group settles, so the
	// representative's chain closes with exactly the base truth.
	nf, wf := closures(base)
	s.Emit(outcome(base.event, base.source, base.outcome, nf, wf))
	baseTruth := r.anySuccess()
	r.repExpected = &baseTruth
	settle(requestcorr.DefaultSettleWindow + time.Second) // → tombstone

	// Late phase, held at the real Observe/selectLocked boundary.
	var held [][]requestcorr.Directive
	for _, o := range late {
		lnf, lwf := closures(o)
		sev, _ := requestcorr.SeverityOf(o.outcome)
		s.mu.Lock()
		s.parked[o.event] = &parkedOutcome{notify: lnf, writeFinding: lwf, lineageID: reviewLineageID, sev: sev}
		ds := s.tracker.Observe(requestcorr.Observation{
			LineageID:      reviewLineageID,
			Source:         o.source,
			IsAnchorSource: o.source == permAnchorSource,
			EventID:        o.event,
			Outcome:        o.outcome,
		})
		s.selectLocked(ds)
		s.mu.Unlock()
		noteKinds(ds)
		held = append(held, ds)
	}

	order := []int{0, 1}
	if reverse {
		order = []int{1, 0}
	}
	for i, idx := range order {
		if settleBetween && i == 1 {
			settle(time.Second)
		}
		s.apply(held[idx])
	}

	settle(requestcorr.DefaultSettleWindow + time.Second)
	settle(requestcorr.DefaultTombstoneTTL + time.Second)
	s.Shutdown()

	s.mu.Lock()
	r.parked, r.attemptsL, r.work = len(s.parked), len(s.attempts), len(s.work)
	s.mu.Unlock()
	return r
}

// TestPermutationLedgerDiscardReleasesQueuedSiblings covers the region neither
// family reaches: a ledger DISCARDED while siblings are still queued behind an
// attempt that has been minted but not yet applied.
//
// Queuing needs a live attempt, and a discard needs the incident's record to go
// away — a tombstone reaped at TTL, or an identity-integrity poison. Both drop
// the ledger, and with it every queued sibling's notification obligation, whose
// closure the owner is still holding. Nothing may be left behind.
func TestPermutationLedgerDiscardReleasesQueuedSiblings(t *testing.T) {
	for _, viaPoison := range []bool{false, true} {
		for _, applyAfter := range []bool{false, true} {
			name := fmt.Sprintf("poison%v_applyAfterDiscard%v", viaPoison, applyAfter)
			t.Run(name, func(t *testing.T) {
				r := &permResult{
					attempts:  map[string]int{},
					succeeded: map[string]bool{},
					rowFlag:   map[string]bool{},
					rowCount:  map[string]int{},
					rowKind:   map[string]requestcorr.DirectiveKind{},
				}
				s := newHTTPOutcomeSink(Config{
					LineageEnabled:       true,
					LineageAnchorSources: map[string]bool{permAnchorSource: true},
				})
				clk := &manualClock{t: time.Unix(1_700_000_000, 0)}
				s.tracker = requestcorr.New(requestcorr.Config{}, clk)

				observe := func(o permObs) []requestcorr.Directive {
					sev, _ := requestcorr.SeverityOf(o.outcome)
					nf := func() bool {
						r.mu.Lock()
						r.attempts[o.event]++
						r.mu.Unlock()
						return o.ok
					}
					wf := func(n bool) {
						r.mu.Lock()
						r.rowCount[o.event]++
						r.mu.Unlock()
					}
					s.mu.Lock()
					s.parked[o.event] = &parkedOutcome{notify: nf, writeFinding: wf, lineageID: reviewLineageID, sev: sev}
					ds := s.tracker.Observe(requestcorr.Observation{
						LineageID:      reviewLineageID,
						Source:         o.source,
						IsAnchorSource: o.source == permAnchorSource,
						EventID:        o.event,
						Outcome:        o.outcome,
					})
					s.selectLocked(ds)
					s.mu.Unlock()
					return ds
				}
				drive := func(ds []requestcorr.Directive) {
					s.apply(ds)
				}

				// A minted-but-unapplied anchor attempt, with two siblings queued
				// behind it.
				anchorBatch := observe(permObs{event: "anchor", source: permAnchorSource, outcome: requestcorr.OutcomeEscalated, ok: true})
				observe(permObs{event: "q1", source: "backend", outcome: requestcorr.OutcomeEscalated, ok: true})
				observe(permObs{event: "q2", source: "backend2", outcome: requestcorr.OutcomeEscalated, ok: true})

				if !applyAfter {
					drive(anchorBatch)
					anchorBatch = nil
				}

				if viaPoison {
					drive(observe(permObs{event: "dup", source: permAnchorSource, outcome: requestcorr.OutcomeUnresolved, ok: false}))
				} else {
					clk.advance(requestcorr.DefaultSettleWindow + time.Second)
					s.mu.Lock()
					ds := s.tracker.Tick()
					s.selectLocked(ds)
					s.mu.Unlock()
					drive(ds) // settle → tombstone, which inherits the queue
					clk.advance(requestcorr.DefaultTombstoneTTL + time.Second)
					s.mu.Lock()
					ds = s.tracker.Tick()
					s.selectLocked(ds)
					s.mu.Unlock()
					drive(ds) // reap → every queued sibling must be handed back
				}

				drive(anchorBatch)

				clk.advance(requestcorr.DefaultTombstoneTTL + time.Second)
				s.mu.Lock()
				ds := s.tracker.Tick()
				s.selectLocked(ds)
				s.mu.Unlock()
				drive(ds)
				s.Shutdown()

				r.mu.Lock()
				defer r.mu.Unlock()
				for ev, n := range r.attempts {
					if n > 1 {
						t.Fatalf("%s notified %d times", ev, n)
					}
				}
				for ev, n := range r.rowCount {
					if n > 1 {
						t.Fatalf("%s wrote %d rows", ev, n)
					}
				}
				s.mu.Lock()
				parked, atts, work := len(s.parked), len(s.attempts), len(s.work)
				s.mu.Unlock()
				if parked != 0 || atts != 0 || work != 0 {
					t.Fatalf("discarded ledger left work behind: parked=%d attempts=%d registry=%d", parked, atts, work)
				}
			})
		}
	}
}
