// internal/rec/reacquire_test.go
//
// Fix round v3, FIX 1 + FIX 2a/2d: body-reference ownership races between
// Lookup/Insert returning copies and VIP promotion, budget-first reacquire,
// the post-eviction admission recheck, and the rejected-capture delivery
// guard. All deterministic - the "races" are reproduced by explicitly
// evicting between the copy and the promotion.
package rec

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// promoteLocked drives the VIP promotion step the way PrePin and
// handleCapturedResponse do, under vipMu.
func promoteLocked(lc *liveCollector, eventID string, resp CapturedResponse) bool {
	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()
	return lc.setVIPEvidenceLocked(eventID, resp)
}

func storeHolds(rb *RingBuffer, b *internedBody) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	got, ok := rb.bodies.byKey[b.key]
	return ok && got == b
}

// TestReacquire_EvictedBodySufficientBudget (FIX 1 test a): a Lookup copy
// whose body was evicted+released is promoted with room in the budget - no
// panic, the body is resurrected, VIP holds a correctly charged reference,
// and totals balance after release.
func TestReacquire_EvictedBodySufficientBudget(t *testing.T) {
	lc := bareCollector()
	lc.buffer = mustRing(cfgWithEffective(2, 20000, 2048))
	lc.running.Store(true)
	rb := lc.buffer

	rb.Insert(makeResp("/race", bytes.Repeat([]byte("r"), 1000)))
	candidates := lookupPath(rb, "/race")
	if len(candidates) != 1 || candidates[0].body == nil {
		t.Fatalf("fixture: lookup copy missing body")
	}
	stale := candidates[0]
	bodyCharge := stale.body.byteCharge

	// Capacity-evict /race: its body is fully released (no VIP holder yet).
	rb.Insert(makeResp("/x1", nil))
	rb.Insert(makeResp("/x2", nil))
	if storeHolds(rb, stale.body) {
		t.Fatalf("fixture: body still store-resident after eviction")
	}
	totalBefore := rb.Stats().TotalBytes

	if !promoteLocked(lc, "evt_a", stale) {
		t.Fatalf("promotion rejected despite sufficient budget")
	}
	held, ok := lc.vipEvidence["evt_a"]
	if !ok || held.body == nil {
		t.Fatalf("VIP evidence missing after promotion")
	}
	if held.body.refcount != 1 {
		t.Errorf("resurrected body refcount = %d, want 1 (VIP only)", held.body.refcount)
	}
	if !storeHolds(rb, held.body) {
		t.Errorf("resurrected body not store-resident")
	}
	if got := rb.Stats().TotalBytes; got != totalBefore+bodyCharge {
		t.Errorf("TotalBytes after resurrection = %d, want %d (charged exactly once)", got, totalBefore+bodyCharge)
	}

	// Releasing the VIP reference returns the totals to balance.
	lc.vipMu.Lock()
	lc.deleteVIPEvidenceLocked("evt_a")
	lc.vipMu.Unlock()
	if got := rb.Stats().TotalBytes; got != totalBefore {
		t.Errorf("TotalBytes after VIP release = %d, want %d", got, totalBefore)
	}
	if s := rb.Stats(); s.VIPReacquireRejected != 0 {
		t.Errorf("VIPReacquireRejected = %d, want 0", s.VIPReacquireRejected)
	}
}

// TestReacquire_EvictedBodyInsufficientBudget (FIX 1 test b): with VIP-held
// bodies occupying the effective budget, promoting a released body is
// REJECTED - existing VIP evidence intact, counter incremented, no ring
// eviction performed for it, total never exceeds the effective budget.
func TestReacquire_EvictedBodyInsufficientBudget(t *testing.T) {
	lc := bareCollector()
	lc.buffer = mustRing(cfgWithEffective(2, 6000, 2048))
	lc.running.Store(true)
	rb := lc.buffer

	// /held is promoted to VIP while ring-resident - its charge survives
	// ring eviction.
	rb.Insert(makeResp("/held", bytes.Repeat([]byte("h"), 2000)))
	heldCopy := lookupPath(rb, "/held")[0]
	if !promoteLocked(lc, "evt_held", heldCopy) {
		t.Fatalf("fixture: initial promotion failed")
	}

	// /race is captured, copied via Lookup, then evicted+released under
	// byte pressure from the filler inserts below.
	rb.Insert(makeResp("/race", bytes.Repeat([]byte("r"), 2000)))
	stale := lookupPath(rb, "/race")[0]
	rb.Insert(makeResp("/f1", bytes.Repeat([]byte("1"), 1200)))
	rb.Insert(makeResp("/f2", bytes.Repeat([]byte("2"), 1200)))
	if storeHolds(rb, stale.body) {
		t.Fatalf("fixture: /race body still store-resident (geometry drifted?)")
	}
	evictionsBefore := rb.Stats().EvictionsTotal
	totalBefore := rb.Stats().TotalBytes

	if promoteLocked(lc, "evt_race", stale) {
		t.Fatalf("promotion succeeded despite insufficient budget")
	}

	if _, ok := lc.vipEvidence["evt_race"]; ok {
		t.Errorf("rejected promotion left VIP evidence behind")
	}
	if held, ok := lc.vipEvidence["evt_held"]; !ok || held.body == nil || held.body.refcount < 1 {
		t.Errorf("existing VIP evidence disturbed by the rejected promotion")
	}
	s := rb.Stats()
	if s.VIPReacquireRejected != 1 {
		t.Errorf("VIPReacquireRejected = %d, want 1", s.VIPReacquireRejected)
	}
	if s.EvictionsTotal != evictionsBefore {
		t.Errorf("rejected reacquire evicted ring entries: evictions %d → %d", evictionsBefore, s.EvictionsTotal)
	}
	if s.TotalBytes != totalBefore {
		t.Errorf("rejected reacquire changed TotalBytes: %d → %d", totalBefore, s.TotalBytes)
	}
	if s.TotalBytes > 6000 {
		t.Errorf("TotalBytes %d exceeds the effective budget 6000", s.TotalBytes)
	}
}

// TestReacquire_InsertOnCaptureWindow (FIX 1 test c): the copy returned by
// Insert is evicted+released before onCapture's promotion runs
// (handleCapturedResponse). Both budget outcomes.
func TestReacquire_InsertOnCaptureWindow(t *testing.T) {
	t.Run("sufficient_budget_promotes", func(t *testing.T) {
		lc := bareCollector()
		lc.buffer = mustRing(cfgWithEffective(2, 20000, 2048))
		lc.running.Store(true)

		lc.PinVIP("evt_win", "key|b=1", LookupRequest{
			Method: "GET", Path: "/win", StatusCode: 200,
			Timestamp: time.Now(), Window: time.Hour,
		})
		stored := lc.buffer.Insert(makeResp("/win", bytes.Repeat([]byte("w"), 1000)))

		// The window: eviction lands before the callback runs.
		lc.buffer.Insert(makeResp("/x1", nil))
		lc.buffer.Insert(makeResp("/x2", nil))
		if storeHolds(lc.buffer, stored.body) {
			t.Fatalf("fixture: body still resident")
		}

		lc.handleCapturedResponse(stored) // must not panic
		if held, ok := lc.vipEvidence["evt_win"]; !ok || held.body == nil || held.body.refcount != 1 {
			t.Errorf("VIP promotion after the window failed: present=%v", ok)
		}
		if _, pinned := lc.vipPins["evt_win"]; pinned {
			t.Errorf("pin not consumed by successful promotion")
		}
	})

	t.Run("insufficient_budget_keeps_pin", func(t *testing.T) {
		lc := bareCollector()
		lc.buffer = mustRing(cfgWithEffective(2, 6000, 2048))
		lc.running.Store(true)

		// Occupy the budget with a VIP-held body.
		lc.buffer.Insert(makeResp("/held", bytes.Repeat([]byte("h"), 2000)))
		if !promoteLocked(lc, "evt_held", lookupPath(lc.buffer, "/held")[0]) {
			t.Fatalf("fixture: initial promotion failed")
		}

		lc.PinVIP("evt_win", "key|b=2", LookupRequest{
			Method: "GET", Path: "/win", StatusCode: 200,
			Timestamp: time.Now(), Window: time.Hour,
		})
		stored := lc.buffer.Insert(makeResp("/win", bytes.Repeat([]byte("w"), 2000)))
		lc.buffer.Insert(makeResp("/f1", bytes.Repeat([]byte("1"), 1200)))
		lc.buffer.Insert(makeResp("/f2", bytes.Repeat([]byte("2"), 1200)))
		if storeHolds(lc.buffer, stored.body) {
			t.Fatalf("fixture: body still resident (geometry drifted?)")
		}

		lc.handleCapturedResponse(stored) // must not panic
		if _, ok := lc.vipEvidence["evt_win"]; ok {
			t.Errorf("rejected promotion stored VIP evidence")
		}
		if _, pinned := lc.vipPins["evt_win"]; !pinned {
			t.Errorf("pin was consumed by a REJECTED promotion - it must stay armed")
		}
		if got := lc.buffer.Stats().VIPReacquireRejected; got != 1 {
			t.Errorf("VIPReacquireRejected = %d, want 1", got)
		}
	})
}

// TestReacquire_SameBodyReplacement (FIX 1 test d / Shape B): replacing VIP
// evidence where old and new share the SAME interned body and the ring holds
// no reference - reacquire-first ordering means no last-owner release
// mid-sequence, no panic, refcount and charge stay correct.
func TestReacquire_SameBodyReplacement(t *testing.T) {
	lc := bareCollector()
	lc.buffer = mustRing(cfgWithEffective(2, 20000, 2048))
	lc.running.Store(true)
	rb := lc.buffer

	rb.Insert(makeResp("/same", bytes.Repeat([]byte("s"), 1000)))
	copyA := lookupPath(rb, "/same")[0]
	copyB := lookupPath(rb, "/same")[0]
	if copyA.body == nil || copyA.body != copyB.body {
		t.Fatalf("fixture: copies do not share one interned body")
	}

	if !promoteLocked(lc, "evt_d", copyA) {
		t.Fatalf("fixture: initial promotion failed")
	}
	// Evict the ring entry: VIP now holds the only reference.
	rb.Insert(makeResp("/x1", nil))
	rb.Insert(makeResp("/x2", nil))
	if copyA.body.refcount != 1 {
		t.Fatalf("fixture: refcount = %d, want 1 (VIP only)", copyA.body.refcount)
	}
	totalBefore := rb.Stats().TotalBytes

	if !promoteLocked(lc, "evt_d", copyB) { // replacement, same body
		t.Fatalf("same-body replacement rejected")
	}
	held := lc.vipEvidence["evt_d"]
	if held.body != copyA.body {
		t.Errorf("replacement changed the body object")
	}
	if held.body.refcount != 1 {
		t.Errorf("refcount after same-body replacement = %d, want 1", held.body.refcount)
	}
	if !storeHolds(rb, held.body) {
		t.Errorf("body left the store during same-body replacement")
	}
	if got := rb.Stats().TotalBytes; got != totalBefore {
		t.Errorf("TotalBytes changed across same-body replacement: %d → %d", totalBefore, got)
	}
}

// TestInsertRejectedBudget (FIX 2a): VIP-held charges leave insufficient
// room even after the ring is fully evicted - the insert is rejected with
// rejectedBudget (not rejectedOversized), the intern reference is rolled
// back, and total never exceeds the effective budget.
func TestInsertRejectedBudget(t *testing.T) {
	lc := bareCollector()
	lc.buffer = mustRing(cfgWithEffective(2, 6000, 2048))
	lc.running.Store(true)
	rb := lc.buffer

	// Two VIP-held bodies occupy ~4512 of the 6000-byte effective budget.
	rb.Insert(makeResp("/a", bytes.Repeat([]byte("a"), 2000)))
	if !promoteLocked(lc, "evt_a", lookupPath(rb, "/a")[0]) {
		t.Fatalf("fixture: promotion a failed")
	}
	rb.Insert(makeResp("/b", bytes.Repeat([]byte("b"), 2000)))
	if !promoteLocked(lc, "evt_b", lookupPath(rb, "/b")[0]) {
		t.Fatalf("fixture: promotion b failed")
	}

	// A third distinct body passes the per-entry worst-case check but has
	// no room even once the whole ring is evicted.
	stored := rb.Insert(makeResp("/c", bytes.Repeat([]byte("c"), 2000)))

	if stored.CaptureID != 0 {
		t.Fatalf("budget-rejected insert returned CaptureID %d, want 0", stored.CaptureID)
	}
	if stored.body != nil {
		t.Errorf("budget-rejected insert kept a body reference")
	}
	s := rb.Stats()
	if s.RejectedBudget != 1 {
		t.Errorf("RejectedBudget = %d, want 1", s.RejectedBudget)
	}
	if s.RejectedOversized != 0 {
		t.Errorf("RejectedOversized = %d, want 0 (this entry could fit an empty budget)", s.RejectedOversized)
	}
	if s.TotalBytes > 6000 {
		t.Errorf("TotalBytes %d exceeds the effective budget 6000", s.TotalBytes)
	}
	// The /c body must not linger in the store.
	rb.mu.Lock()
	storeLen := len(rb.bodies.byKey)
	rb.mu.Unlock()
	if storeLen != 2 {
		t.Errorf("store holds %d bodies, want 2 (rejected body rolled back)", storeLen)
	}
}

// TestRejectedCaptureNeverReachesVIP (FIX 2d): a rejected insert with a
// matching VIP pin is never delivered - vipEvidence stays empty and the pin
// stays armed.
func TestRejectedCaptureNeverReachesVIP(t *testing.T) {
	lc := bareCollector()
	// Fix round v4: tiny budgets are invalid configurations (FIX C), so the
	// rejection is driven by an attacker-length Path pushing the worst-case
	// admission estimate past a VALID 5000-byte effective budget.
	rb := mustRing(cfgWithEffective(3, 5000, 2048))
	lc.buffer = rb
	lc.running.Store(true)
	s := newSniffer(rb, "", []int{80}, 64, 2048, DefaultVXLANPort, false, DefaultReassemblyConfig(), DefaultFlowConfig())
	s.onCapture = lc.handleCapturedResponse

	hugePath := "/reject?" + strings.Repeat("A", 3000)
	lc.PinVIP("evt_pin", "key|b=3", LookupRequest{
		Method: "GET", Path: hugePath, StatusCode: 200,
		Timestamp: time.Now(), Window: time.Hour,
	})

	stored := rb.Insert(makeResp(hugePath, bytes.Repeat([]byte("z"), 100)))
	if stored.CaptureID != 0 {
		t.Fatalf("fixture: insert not rejected (CaptureID %d)", stored.CaptureID)
	}
	s.deliverCapture(stored)

	if len(lc.vipEvidence) != 0 {
		t.Errorf("rejected capture reached vipEvidence")
	}
	if _, ok := lc.vipPins["evt_pin"]; !ok {
		t.Errorf("pin consumed by a rejected capture")
	}

	// Positive control: an accepted capture through the same delivery point
	// does promote (its own pin, short path).
	lc.PinVIP("evt_pin_ok", "key|b=4", LookupRequest{
		Method: "GET", Path: "/ok", StatusCode: 200,
		Timestamp: time.Now(), Window: time.Hour,
	})
	accepted := rb.Insert(makeResp("/ok", []byte("tiny")))
	if accepted.CaptureID == 0 {
		t.Fatalf("fixture: small insert unexpectedly rejected")
	}
	s.deliverCapture(accepted)
	if _, ok := lc.vipEvidence["evt_pin_ok"]; !ok {
		t.Errorf("accepted capture was not delivered/promoted")
	}
}
