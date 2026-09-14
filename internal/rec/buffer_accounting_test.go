// internal/rec/buffer_accounting_test.go
//
// Part 2 tests: oversized-insert rejection, the budget-derived MaxEntries
// clamp, per-reason loss counters, observed-demand loss tracking, and stable
// capture identity across slot reuse.
package rec

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestNewRingBufferRejectsUnusableBudget (FIX C, fix round v4): a budget
// that cannot fit one worst-case entry after array charging even at
// MaxEntries == 1 is refused at construction; the smallest workable budget
// constructs, with the geometry logged.
func TestNewRingBufferRejectsUnusableBudget(t *testing.T) {
	if _, err := NewRingBuffer(BufferConfig{
		MaxEntries: 1, MaxTotalBytes: 3000, MaxAge: time.Hour, MaxBodyBytes: 2048,
	}); err == nil {
		t.Fatalf("absurdly small budget accepted - the buffer would limp on an unusable effective budget")
	}

	// Smallest workable budget: exactly the one-slot array plus one
	// worst-case entry.
	min := int64(entryStructSize()) + worstCaseEntryBytes(2048)
	rb, err := NewRingBuffer(BufferConfig{
		MaxEntries: 1, MaxTotalBytes: min, MaxAge: time.Hour, MaxBodyBytes: 2048,
	})
	if err != nil {
		t.Fatalf("smallest workable budget (%d) rejected: %v", min, err)
	}
	if rb.effectiveMaxTotalBytes != worstCaseEntryBytes(2048) {
		t.Errorf("effective budget = %d, want %d (one worst-case entry)",
			rb.effectiveMaxTotalBytes, worstCaseEntryBytes(2048))
	}

	// One byte less is unusable.
	if _, err := NewRingBuffer(BufferConfig{
		MaxEntries: 1, MaxTotalBytes: min - 1, MaxAge: time.Hour, MaxBodyBytes: 2048,
	}); err == nil {
		t.Errorf("budget one byte below the workable minimum accepted")
	}
}

// cfgWithEffective builds a BufferConfig whose EFFECTIVE budget - what
// remains after the FIX 2b entry-array charge - is effectiveWant. Keeps the
// byte-geometry tests independent of entryStructSize() drift. Callers pick
// effectiveWant above worstCaseEntryBytes(maxBody) when the tiny-budget
// guard must stay quiet.
func cfgWithEffective(maxEntries int, effectiveWant int64, maxBody int) BufferConfig {
	return BufferConfig{
		MaxEntries:    maxEntries,
		MaxTotalBytes: effectiveWant + int64(maxEntries)*int64(entryStructSize()),
		MaxAge:        time.Hour,
		MaxBodyBytes:  maxBody,
	}
}

// mustRing constructs a ring buffer from a config that is valid by test
// construction; a FIX C rejection here is a test bug, not a behavior under
// test.
func mustRing(cfg BufferConfig) *RingBuffer {
	rb, err := NewRingBuffer(cfg)
	if err != nil {
		panic(err)
	}
	return rb
}

func TestOversizedInsertRejected(t *testing.T) {
	// Fix round v4: tiny budgets are now invalid configurations (FIX C), so
	// the oversized rejection is driven by the per-insert worst-case
	// ESTIMATE instead - an attacker-length Path string pushes the estimate
	// (entry record + raw preview + redactorMaxOutputBytes + store
	// overhead) past a valid 5000-byte effective budget.
	rb := mustRing(cfgWithEffective(3, 5000, 2048))
	rb.Insert(makeResp("/keep", make([]byte, 100)))

	stored := rb.Insert(makeResp("/huge?"+strings.Repeat("A", 3000), make([]byte, 100)))

	if stored.CaptureID != 0 {
		t.Errorf("oversized insert returned CaptureID %d, want 0 (rejected)", stored.CaptureID)
	}
	s := rb.Stats()
	if s.RejectedOversized != 1 {
		t.Errorf("RejectedOversized = %d, want 1", s.RejectedOversized)
	}
	if s.Entries != 1 {
		t.Errorf("Entries = %d, want 1 (ring untouched by the rejection)", s.Entries)
	}
	if got := lookupPath(rb, "/keep"); len(got) != 1 {
		t.Errorf("/keep lookup returned %d candidates, want 1 (nothing may be evicted for a rejected insert)", len(got))
	}
	if s.EvictionsTotal != 0 {
		t.Errorf("EvictionsTotal = %d, want 0 (rejection must not evict)", s.EvictionsTotal)
	}
}

func TestMaxEntriesClampedToByteBudget(t *testing.T) {
	// An absurd MaxEntries must not preallocate outside the byte budget: the
	// empty entry array is capped at 1/4 of MaxTotalBytes.
	const budget = 1 << 20 // 1MB
	rb := mustRing(BufferConfig{
		MaxEntries:    10_000_000,
		MaxTotalBytes: budget,
		MaxAge:        time.Hour,
		MaxBodyBytes:  2048,
	})

	entrySize := int64(len(rb.entries)) * int64(entryStructSize())
	if entrySize > budget/maxEntryArrayBudgetDivisor {
		t.Errorf("empty entry array = %d bytes, exceeds 1/%d of the %d-byte budget",
			entrySize, maxEntryArrayBudgetDivisor, budget)
	}
	if rb.config.MaxEntries == 10_000_000 {
		t.Errorf("MaxEntries not clamped")
	}
	// The clamped buffer still works.
	rb.Insert(makeResp("/x", nil))
	if got := lookupPath(rb, "/x"); len(got) != 1 {
		t.Errorf("clamped buffer lost an insert")
	}
}

func TestEvictionReasonCountersMoveIndependently(t *testing.T) {
	assertOnly := func(t *testing.T, s BufferStats, age, capacity, bytes int64) {
		t.Helper()
		if s.EvictionsAge != age || s.EvictionsCapacity != capacity || s.EvictionsBytes != bytes {
			t.Errorf("eviction counters = age:%d capacity:%d bytes:%d, want age:%d capacity:%d bytes:%d",
				s.EvictionsAge, s.EvictionsCapacity, s.EvictionsBytes, age, capacity, bytes)
		}
	}

	t.Run("age_only", func(t *testing.T) {
		rb := mustRing(BufferConfig{MaxEntries: 10, MaxTotalBytes: 1 << 20, MaxAge: 30 * time.Millisecond, MaxBodyBytes: 2048})
		rb.Insert(makeResp("/old", nil))
		time.Sleep(50 * time.Millisecond)
		rb.Insert(makeResp("/new", nil))
		assertOnly(t, rb.Stats(), 1, 0, 0)
	})

	t.Run("capacity_only", func(t *testing.T) {
		rb := mustRing(BufferConfig{MaxEntries: 2, MaxTotalBytes: 1 << 20, MaxAge: time.Hour, MaxBodyBytes: 2048})
		rb.Insert(makeResp("/a", nil))
		rb.Insert(makeResp("/b", nil))
		rb.Insert(makeResp("/c", nil))
		assertOnly(t, rb.Stats(), 0, 1, 0)
	})

	t.Run("bytes_only", func(t *testing.T) {
		// Distinct bodies (Part 3: identical bodies intern to one shared
		// charge and would never build byte pressure). Effective-budget
		// geometry per fix round v3: two ~2514-byte entries fit a 6000-byte
		// effective budget, the third evicts.
		rb := mustRing(cfgWithEffective(3, 6000, 2048))
		rb.Insert(makeResp("/a", bytes.Repeat([]byte("a"), 2000)))
		rb.Insert(makeResp("/b", bytes.Repeat([]byte("b"), 2000)))
		rb.Insert(makeResp("/c", bytes.Repeat([]byte("c"), 2000)))
		assertOnly(t, rb.Stats(), 0, 0, 1)
	})

	t.Run("oversized_only", func(t *testing.T) {
		// v4: oversized via a long-path worst-case estimate on a VALID
		// budget (tiny budgets are rejected at construction, FIX C).
		rb := mustRing(cfgWithEffective(3, 5000, 2048))
		rb.Insert(makeResp("/x?"+strings.Repeat("A", 3000), nil))
		s := rb.Stats()
		if s.RejectedOversized != 1 {
			t.Errorf("RejectedOversized = %d, want 1", s.RejectedOversized)
		}
		assertOnly(t, s, 0, 0, 0)
	})
}

// TestDemandedEvidenceEvicted drives the honest-loss counter through the real
// PrePin path: an entry a PrePin/VIP request matched (known demand OBSERVED)
// is later evicted under byte pressure, and only then does the counter move.
func TestDemandedEvidenceEvicted(t *testing.T) {
	lc := bareCollector()
	// Distinct 2000-byte bodies charge ~2525 each (entry record + unique
	// body + store overhead): an 8500-byte EFFECTIVE budget (fix round v3
	// geometry) holds three, so the fourth insert forces byte-pressure
	// eviction past the demanded entry.
	lc.buffer = mustRing(cfgWithEffective(8, 8500, 2048))
	lc.running.Store(true) // white-box Enabled() gate so PrePin proceeds

	flood := func(path string, fill byte) CapturedResponse {
		return makeResp(path, bytes.Repeat([]byte{fill}, 2000))
	}
	lc.buffer.Insert(flood("/wp-login.php", 'w'))

	// PrePin finds the entry in the ring and promotes it to VIP - observed
	// demand is recorded on the ring entry.
	lc.PrePin("evt_demand", LookupRequest{
		Method:     "GET",
		Path:       "/wp-login.php",
		StatusCode: 200,
		Timestamp:  time.Now(),
		Window:     time.Hour,
	})

	if got := lc.buffer.Stats().DemandedEvidenceEvicted; got != 0 {
		t.Fatalf("DemandedEvidenceEvicted = %d before any eviction, want 0", got)
	}

	// Two more fit alongside; the fourth triggers byte pressure that
	// evicts the demanded entry (oldest first).
	lc.buffer.Insert(flood("/f1", '1'))
	lc.buffer.Insert(flood("/f2", '2'))
	if got := lc.buffer.Stats().DemandedEvidenceEvicted; got != 0 {
		t.Fatalf("DemandedEvidenceEvicted = %d before pressure, want 0", got)
	}
	lc.buffer.Insert(flood("/f3", '3'))

	if got := lc.buffer.Stats().DemandedEvidenceEvicted; got != 1 {
		t.Errorf("DemandedEvidenceEvicted = %d, want 1", got)
	}

	// Undemanded losses do not move the counter further.
	lc.buffer.Insert(flood("/f4", '4'))
	if got := lc.buffer.Stats().DemandedEvidenceEvicted; got != 1 {
		t.Errorf("DemandedEvidenceEvicted = %d after undemanded eviction, want still 1", got)
	}
}

// TestEvictionSelectedSplit (FIX 5a): evictions split by whether the entry
// was ever returned in a Lookup candidate set, at every eviction site.
func TestEvictionSelectedSplit(t *testing.T) {
	rb := mustRing(BufferConfig{MaxEntries: 2, MaxTotalBytes: 1 << 20, MaxAge: time.Hour, MaxBodyBytes: 2048})

	// /seen is looked up (everSelected stamped), /unseen never is.
	rb.Insert(makeResp("/seen", nil))
	rb.Insert(makeResp("/unseen", nil))
	if got := lookupPath(rb, "/seen"); len(got) != 1 {
		t.Fatalf("fixture: /seen lookup failed")
	}

	// Capacity-evict both.
	rb.Insert(makeResp("/x1", nil))
	rb.Insert(makeResp("/x2", nil))

	s := rb.Stats()
	if s.EvictedEverSelected != 1 || s.EvictedNeverSelected != 1 {
		t.Errorf("eviction split = ever:%d never:%d, want 1/1", s.EvictedEverSelected, s.EvictedNeverSelected)
	}
	if s.EvictedEverSelected+s.EvictedNeverSelected != s.EvictionsTotal {
		t.Errorf("split (%d+%d) != EvictionsTotal (%d)", s.EvictedEverSelected, s.EvictedNeverSelected, s.EvictionsTotal)
	}
}

func TestCaptureIDMonotonicAcrossSlotReuse(t *testing.T) {
	rb := mustRing(BufferConfig{MaxEntries: 2, MaxTotalBytes: 1 << 20, MaxAge: time.Hour, MaxBodyBytes: 2048})

	var ids []uint64
	for i := 0; i < 7; i++ {
		stored := rb.Insert(makeResp(fmt.Sprintf("/id/%d", i), nil))
		if stored.CaptureID == 0 {
			t.Fatalf("insert %d rejected unexpectedly", i)
		}
		ids = append(ids, stored.CaptureID)
	}
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("CaptureID not monotonic across slot reuse: ids=%v", ids)
		}
	}

	// The live entries carry the LAST two IDs even though every slot index
	// has been reused - identity keys off CaptureID, never slot.
	for i := 5; i < 7; i++ {
		got := lookupPath(rb, fmt.Sprintf("/id/%d", i))
		if len(got) != 1 || got[0].CaptureID != ids[i] {
			t.Errorf("entry /id/%d: got %d candidates (CaptureID %v), want 1 with CaptureID %d",
				i, len(got), captureIDsOf(got), ids[i])
		}
	}
}

func captureIDsOf(entries []CapturedResponse) []uint64 {
	out := make([]uint64, len(entries))
	for i, e := range entries {
		out[i] = e.CaptureID
	}
	return out
}
