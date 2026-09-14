package rec

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// makeResp builds a CapturedResponse with enough request identity for Lookup
// to match it by Method+Path+StatusCode. Timestamp is set to now so the
// default-ish correlation window in lookupPath covers it.
func makeResp(path string, body []byte) CapturedResponse {
	return CapturedResponse{
		Timestamp:   time.Now(),
		Method:      "GET",
		Path:        path,
		StatusCode:  200,
		BodyPreview: body,
	}
}

// lookupPath queries the buffer for a single path with a wide time window,
// so the only thing that can hide an entry is eviction (not the window).
func lookupPath(rb *RingBuffer, path string) []CapturedResponse {
	return rb.Lookup(LookupRequest{
		Method:     "GET",
		Path:       path,
		StatusCode: 200,
		Timestamp:  time.Now(),
		Window:     time.Hour,
	})
}

func TestInsertBelowAllCaps(t *testing.T) {
	rb := mustRing(BufferConfig{
		MaxEntries:    100,
		MaxTotalBytes: 1 << 20,
		MaxAge:        time.Hour,
		MaxBodyBytes:  2048,
	})

	const body = 100
	for i := 0; i < 3; i++ {
		rb.Insert(makeResp(fmt.Sprintf("/p/%d", i), make([]byte, body)))
	}

	s := rb.Stats()
	if s.Entries != 3 {
		t.Fatalf("Entries = %d, want 3", s.Entries)
	}
	// Part 2: accounting also charges the owned variable strings
	// (Path/Host/UserAgent/ContentType) - here just the 4-byte "/p/N" path.
	// Part 3: the three IDENTICAL 100-byte bodies intern to ONE shared body,
	// charged once (bytes + store overhead); entries charge only their own
	// records.
	wantBytes := int64(3*(len("/p/0")+approxEntryOverheadBytes) + (body + bodyStoreOverheadBytes))
	if s.TotalBytes != wantBytes {
		t.Fatalf("TotalBytes = %d, want %d", s.TotalBytes, wantBytes)
	}
	if s.EvictionsTotal != 0 {
		t.Fatalf("EvictionsTotal = %d, want 0 (nothing should evict below caps)", s.EvictionsTotal)
	}
	for i := 0; i < 3; i++ {
		if got := lookupPath(rb, fmt.Sprintf("/p/%d", i)); len(got) != 1 {
			t.Fatalf("lookup /p/%d returned %d candidates, want 1", i, len(got))
		}
	}
}

func TestMemoryPressureEvictsOldestFirst(t *testing.T) {
	// Part 3: bodies must be DISTINCT (identical bodies intern to one shared
	// charge and never build pressure). Each insert costs ~258 (entry record)
	// + ~2256 (unique 2000-byte body + store overhead) ≈ 2514 bytes: a
	// 6000-byte EFFECTIVE ceiling (fix round v3: geometry is expressed as an
	// effective budget, above the tiny-budget guard's worst-case-entry
	// threshold) holds two; the third forces an oldest-first eviction.
	rb := mustRing(cfgWithEffective(3, 6000, 2048))

	rb.Insert(makeResp("/a", bytes.Repeat([]byte("a"), 2000)))
	rb.Insert(makeResp("/b", bytes.Repeat([]byte("b"), 2000)))
	rb.Insert(makeResp("/c", bytes.Repeat([]byte("c"), 2000)))

	if got := lookupPath(rb, "/a"); len(got) != 0 {
		t.Fatalf("oldest entry /a should have been evicted under byte pressure, found %d", len(got))
	}
	if got := lookupPath(rb, "/b"); len(got) != 1 {
		t.Fatalf("/b should still be present, found %d", len(got))
	}
	if got := lookupPath(rb, "/c"); len(got) != 1 {
		t.Fatalf("/c (newest) should be present, found %d", len(got))
	}

	s := rb.Stats()
	if s.EvictionsBytes == 0 {
		t.Fatalf("EvictionsBytes = 0, want >0 (byte cap should have bound)")
	}
	if s.EvictionsCapacity != 0 || s.EvictionsAge != 0 {
		t.Fatalf("only the byte cap should bind: age=%d capacity=%d", s.EvictionsAge, s.EvictionsCapacity)
	}
}

func TestAgeBackstopEvictsExpiredEntries(t *testing.T) {
	rb := mustRing(BufferConfig{
		MaxEntries:    100,
		MaxTotalBytes: 1 << 20,
		MaxAge:        50 * time.Millisecond,
		MaxBodyBytes:  2048,
	})

	rb.Insert(makeResp("/old", nil))
	time.Sleep(80 * time.Millisecond) // age /old past the 50ms backstop

	// The age sweep happens lazily on the next Insert.
	rb.Insert(makeResp("/new", nil))

	if got := lookupPath(rb, "/old"); len(got) != 0 {
		t.Fatalf("expired entry /old should have been swept, found %d", len(got))
	}
	if got := lookupPath(rb, "/new"); len(got) != 1 {
		t.Fatalf("/new should be present, found %d", len(got))
	}

	s := rb.Stats()
	if s.EvictionsAge == 0 {
		t.Fatalf("EvictionsAge = 0, want >0 (age backstop should have fired)")
	}
}

func TestCapacityWrapEvictsOnFullEntryArray(t *testing.T) {
	// Byte and age caps are effectively disabled, so the circular entry
	// array is the only constraint that can bind.
	rb := mustRing(BufferConfig{
		MaxEntries:    2,
		MaxTotalBytes: 1 << 30,
		MaxAge:        time.Hour,
		MaxBodyBytes:  2048,
	})

	rb.Insert(makeResp("/a", nil))
	rb.Insert(makeResp("/b", nil))
	rb.Insert(makeResp("/c", nil)) // wraps over the oldest (/a)

	if s := rb.Stats(); s.Entries != 2 {
		t.Fatalf("Entries = %d, want 2 (entry array is full)", s.Entries)
	}
	if got := lookupPath(rb, "/a"); len(got) != 0 {
		t.Fatalf("oldest entry /a should have been overwritten on wrap, found %d", len(got))
	}
	if got := lookupPath(rb, "/b"); len(got) != 1 {
		t.Fatalf("/b should still be present, found %d", len(got))
	}
	if got := lookupPath(rb, "/c"); len(got) != 1 {
		t.Fatalf("/c (newest) should be present, found %d", len(got))
	}

	s := rb.Stats()
	if s.EvictionsCapacity == 0 {
		t.Fatalf("EvictionsCapacity = 0, want >0 (entry cap should have bound)")
	}
}

func TestBodyPreviewTruncatedToMaxBodyBytes(t *testing.T) {
	const maxBody = 10
	rb := mustRing(BufferConfig{
		MaxEntries:    100,
		MaxTotalBytes: 1 << 20,
		MaxAge:        time.Hour,
		MaxBodyBytes:  maxBody,
	})

	longBody := bytes.Repeat([]byte("x"), 100)
	rb.Insert(makeResp("/big-body", longBody))

	got := lookupPath(rb, "/big-body")
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(got))
	}
	// Part 3: stored entries hold the preview through the interned body
	// store - read it via the accessor.
	if len(got[0].BodyPreviewBytes()) != maxBody {
		t.Fatalf("BodyPreviewBytes length = %d, want %d (should be truncated to MaxBodyBytes)",
			len(got[0].BodyPreviewBytes()), maxBody)
	}
}

func TestEvictionsTotalEqualsSumOfReasons(t *testing.T) {
	// Fix round v3 geometry: a 6000-byte EFFECTIVE budget (above the
	// tiny-budget guard's worst-case-entry threshold, so the 3-slot array
	// survives construction) with 2000-byte DISTINCT bodies - two large
	// entries fit, the third forces byte-pressure eviction without any
	// single entry's worst case exceeding the budget (which would be an
	// oversized rejection, not an eviction).
	cfg := cfgWithEffective(3, 6000, 2048)
	cfg.MaxAge = 40 * time.Millisecond
	rb := mustRing(cfg)

	// Capacity pressure: five small entries into a 3-slot array.
	for i := 0; i < 5; i++ {
		rb.Insert(makeResp(fmt.Sprintf("/cap/%d", i), nil))
	}

	// Age pressure: let the survivors expire, then insert to trigger the sweep.
	time.Sleep(60 * time.Millisecond)
	rb.Insert(makeResp("/age", nil))

	// Byte pressure: two large distinct bodies fit alongside /age; the third
	// exceeds the effective budget and forces oldest-first byte eviction.
	rb.Insert(makeResp("/big1", bytes.Repeat([]byte("1"), 2000)))
	rb.Insert(makeResp("/big2", bytes.Repeat([]byte("2"), 2000)))
	rb.Insert(makeResp("/big3", bytes.Repeat([]byte("3"), 2000)))

	s := rb.Stats()
	if s.EvictionsTotal != s.EvictionsAge+s.EvictionsBytes+s.EvictionsCapacity {
		t.Fatalf("invariant broken: total=%d != age=%d + bytes=%d + capacity=%d",
			s.EvictionsTotal, s.EvictionsAge, s.EvictionsBytes, s.EvictionsCapacity)
	}
	if s.EvictionsAge == 0 || s.EvictionsBytes == 0 || s.EvictionsCapacity == 0 {
		t.Fatalf("expected all three eviction reasons to fire: age=%d bytes=%d capacity=%d",
			s.EvictionsAge, s.EvictionsBytes, s.EvictionsCapacity)
	}
}
