// internal/rec/bodystore_test.go
//
// Part 3 tests: interning identity, refcount lifecycle across ring/VIP
// ownership, clone-check independence from storage sharing (Invariant 6),
// disclosure immutability, and the 32k-ring benchmarks.
package rec

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"
	"time"
)

func ringBodyPtr(t *testing.T, rb *RingBuffer, path string) *internedBody {
	t.Helper()
	got := lookupPath(rb, path)
	if len(got) != 1 {
		t.Fatalf("lookup %s returned %d candidates, want 1", path, len(got))
	}
	return got[0].body
}

func TestInterning_IdentityRules(t *testing.T) {
	rb := mustRing(DefaultBufferConfig())
	body := []byte(wpFaultBody)

	// Identical raw bytes + content type + completeness → ONE shared body.
	a := makeResp("/a", append([]byte(nil), body...))
	a.ContentType = "text/xml"
	a.BodyComplete = true
	b := makeResp("/b", append([]byte(nil), body...))
	b.ContentType = "text/xml"
	b.BodyComplete = true
	rb.Insert(a)
	rb.Insert(b)

	pa, pb := ringBodyPtr(t, rb, "/a"), ringBodyPtr(t, rb, "/b")
	if pa == nil || pa != pb {
		t.Fatalf("identical bodies not shared: %p vs %p", pa, pb)
	}
	if pa.refcount != 2 {
		t.Errorf("shared body refcount = %d, want 2", pa.refcount)
	}
	if len(rb.bodies.byKey) != 1 {
		t.Errorf("store holds %d bodies, want 1", len(rb.bodies.byKey))
	}

	// Different bytes → different body.
	c := makeResp("/c", []byte("something else entirely"))
	c.ContentType = "text/xml"
	rb.Insert(c)
	if pc := ringBodyPtr(t, rb, "/c"); pc == pa {
		t.Errorf("different bytes share a body object")
	}

	// Same bytes, different content type → different body.
	d := makeResp("/d", append([]byte(nil), body...))
	d.ContentType = "text/html"
	d.BodyComplete = true
	rb.Insert(d)
	if pd := ringBodyPtr(t, rb, "/d"); pd == pa {
		t.Errorf("different content types share a body object")
	}

	// Same bytes, different completeness → different body.
	e := makeResp("/e", append([]byte(nil), body...))
	e.ContentType = "text/xml"
	e.BodyComplete = false
	rb.Insert(e)
	if pe := ringBodyPtr(t, rb, "/e"); pe == pa {
		t.Errorf("different completeness flags share a body object")
	}
}

func TestBodyStoreKey_RedactorVersionSplits(t *testing.T) {
	body := []byte("same bytes")
	k1 := bodyStoreKey(body, "text/xml", true, 1)
	k2 := bodyStoreKey(body, "text/xml", true, 2)
	if k1 == k2 {
		t.Errorf("redactor-version bump did not split the storage key - stale analyses could survive a rules change")
	}
}

func TestRefcountLifecycle_VIPOutlivesRing(t *testing.T) {
	lc := bareCollector()
	lc.buffer = mustRing(BufferConfig{MaxEntries: 2, MaxTotalBytes: 1 << 20, MaxAge: time.Hour, MaxBodyBytes: 2048})
	lc.running.Store(true)
	rb := lc.buffer

	resp := makeResp("/held", []byte("evidence body held by vip"))
	rb.Insert(resp)
	held := ringBodyPtr(t, rb, "/held")
	bodyCharge := held.byteCharge

	// Promote to VIP (PrePin) - VIP now holds its own reference.
	lc.PrePin("evt_vip", LookupRequest{
		Method: "GET", Path: "/held", StatusCode: 200,
		Timestamp: time.Now(), Window: time.Hour,
	})
	if held.refcount != 2 {
		t.Fatalf("refcount after VIP promotion = %d, want 2 (ring + VIP)", held.refcount)
	}

	// Capacity-evict the ring entry: the body must stay alive AND charged
	// (ring eviction never frees a body still held by VIP storage).
	rb.Insert(makeResp("/x1", nil))
	rb.Insert(makeResp("/x2", nil))
	if got := lookupPath(rb, "/held"); len(got) != 0 {
		t.Fatalf("/held still in the ring - eviction did not happen")
	}
	if held.refcount != 1 {
		t.Errorf("refcount after ring eviction = %d, want 1 (VIP still holds)", held.refcount)
	}
	if _, ok := rb.bodies.byKey[held.key]; !ok {
		t.Errorf("VIP-held body removed from the store by ring eviction")
	}
	totalBefore := rb.Stats().TotalBytes

	// VIP expiry frees the last reference and uncharges the body.
	lc.cleanupExpiredVIP(time.Now().Add(vipTTL + time.Minute))
	if held.refcount != 0 {
		t.Errorf("refcount after VIP expiry = %d, want 0", held.refcount)
	}
	if _, ok := rb.bodies.byKey[held.key]; ok {
		t.Errorf("expired body still in the store")
	}
	if got := rb.Stats().TotalBytes; got != totalBefore-bodyCharge {
		t.Errorf("TotalBytes after last release = %d, want %d (body charge returned)", got, totalBefore-bodyCharge)
	}
}

func TestRefcount_DoubleReleasePanics(t *testing.T) {
	bs := newBodyStore()
	b, _ := bs.intern([]byte("x"), "", true)
	if freed := bs.release(b); freed == 0 {
		t.Fatalf("last release returned 0 freed bytes")
	}
	defer func() {
		if recover() == nil {
			t.Errorf("double release did not panic - a silent budget corruption path")
		}
	}()
	bs.release(b)
}

// TestCloneCheck_SharedStorageIsNotCloneEquality pins Invariant 6 in both
// directions: (a) two entries sharing one body object still compare via
// BodyPreviewHash in the clone check; (b) if the hashes differ, sharing a
// body reference must NOT make them clones - reference equality is never
// consulted, because identical storage never implies transaction equality.
func TestCloneCheck_SharedStorageIsNotCloneEquality(t *testing.T) {
	mk := func(path, hash string, body []byte) CapturedResponse {
		r := makeResp(path, body)
		r.BodyPreviewHash = hash
		r.ContentLength = int64(len(body))
		r.ContentType = "text/html"
		return r
	}
	body := []byte("<html>shared body</html>")

	t.Run("same_hash_same_body_high_confidence", func(t *testing.T) {
		lc := bareCollector()
		lc.running.Store(true)
		lc.buffer.Insert(mk("/p", "hash-equal", append([]byte(nil), body...)))
		lc.buffer.Insert(mk("/p", "hash-equal", append([]byte(nil), body...)))

		ev := lc.Lookup(LookupRequest{Method: "GET", Path: "/p", StatusCode: 200, Timestamp: time.Now(), Window: time.Hour})
		if ev.CandidateCount != 2 {
			t.Fatalf("candidates = %d, want 2", ev.CandidateCount)
		}
		if ev.CorrelationConfidence != ConfidenceHigh {
			t.Errorf("clone check broke: identical hashes gave %q, want high", ev.CorrelationConfidence)
		}
	})

	t.Run("different_hash_shared_reference_not_clones", func(t *testing.T) {
		lc := bareCollector()
		lc.running.Store(true)
		// Mocked divergence: identical raw bytes (one shared body object)
		// but hand-set DIFFERENT BodyPreviewHash values.
		lc.buffer.Insert(mk("/p", "hash-one", append([]byte(nil), body...)))
		lc.buffer.Insert(mk("/p", "hash-two", append([]byte(nil), body...)))

		// Prove storage IS shared - then prove the clone check ignores it.
		got := lookupPath(lc.buffer, "/p")
		if len(got) != 2 || got[0].body == nil || got[0].body != got[1].body {
			t.Fatalf("fixture broken: bodies not shared (%d candidates)", len(got))
		}

		ev := lc.Lookup(LookupRequest{Method: "GET", Path: "/p", StatusCode: 200, Timestamp: time.Now(), Window: time.Hour})
		if ev.CorrelationConfidence != ConfidenceLow {
			t.Errorf("clone check consulted storage sharing: confidence %q, want low (hashes differ)", ev.CorrelationConfidence)
		}
		if ev.SafeBodyPreview != "" {
			t.Errorf("ambiguous candidates leaked a preview")
		}
	})
}

func TestDisclosureImmutableAcrossLookups(t *testing.T) {
	lc := bareCollector()
	lc.running.Store(true)
	rb := lc.buffer

	resp := makeResp("/xmlrpc.php", []byte(wpFaultBody))
	resp.ContentType = "text/html"
	resp.BodyComplete = true
	resp.BodyPreviewHash = HashBody([]byte(wpFaultBody))
	rb.Insert(resp)

	rb.mu.Lock()
	runsAfterIntern := rb.bodies.redactionsRun
	rb.mu.Unlock()
	if runsAfterIntern != 1 {
		t.Fatalf("redactionsRun after intern = %d, want 1", runsAfterIntern)
	}

	req := LookupRequest{Method: "GET", Path: "/xmlrpc.php", StatusCode: 200, Timestamp: time.Now(), Window: time.Hour}
	ev1 := lc.Lookup(req)
	ev2 := lc.Lookup(req)

	// No second classifyAndRedact for the same interned body.
	rb.mu.Lock()
	runsAfterLookups := rb.bodies.redactionsRun
	rb.mu.Unlock()
	if runsAfterLookups != runsAfterIntern {
		t.Errorf("redactionsRun grew from %d to %d across Lookups - redaction re-ran on captured input", runsAfterIntern, runsAfterLookups)
	}

	// Identical analysis on every Lookup.
	if ev1.Disclosure == nil || ev2.Disclosure == nil {
		t.Fatalf("missing disclosure: ev1=%v ev2=%v", ev1.Disclosure, ev2.Disclosure)
	}
	if *ev1.Disclosure != *ev2.Disclosure {
		t.Errorf("interned analysis differs across Lookups:\n  ev1=%+v\n  ev2=%+v", *ev1.Disclosure, *ev2.Disclosure)
	}
	if ev1.SafeBodyPreview != wpFaultRedacted || ev2.SafeBodyPreview != wpFaultRedacted {
		t.Errorf("interned redacted preview not served: ev1=%q ev2=%q", ev1.SafeBodyPreview, ev2.SafeBodyPreview)
	}

	// Evidence must carry a COPY, not the interned pointer.
	best := ringBodyPtr(t, rb, "/xmlrpc.php")
	if ev1.Disclosure == best.disclosure || ev2.Disclosure == best.disclosure {
		t.Errorf("Evidence.Disclosure aliases the interned analysis - outside callers must never hold store references")
	}
}

// TestEntryStructSize records the measured ring-entry struct size (Part 3
// hand-back item) and pins it under a sanity ceiling so accidental growth is
// visible in review.
func TestEntryStructSize(t *testing.T) {
	size := entryStructSize()
	t.Logf("CapturedResponse struct size: %d bytes (32768 entries preallocate %d bytes empty)",
		size, int64(size)*32768)
	if size > 512 {
		t.Errorf("entry struct grew to %d bytes - re-check the 32k preallocation budget", size)
	}
}

// =============================================================================
// Benchmarks - full 32,768-entry ring, worst case: EVERY entry matches
// host+path+status, so the scan, scoring, and clone check run over all of
// them. Do NOT "optimize" these paths by early-exiting at the first match -
// that would delete the ambiguity/clone check.
// =============================================================================

func benchRing(n int) (*liveCollector, LookupRequest) {
	lc := bareCollector()
	lc.buffer = mustRing(BufferConfig{
		MaxEntries:    n,
		MaxTotalBytes: DefaultMaxTotalBytes,
		MaxAge:        time.Hour,
		MaxBodyBytes:  2048,
	})
	lc.running.Store(true)

	base := time.Now()
	body := []byte(wpFaultBody) // one interned body - the flood shape
	hash := HashBody(body)
	for i := 0; i < n; i++ {
		r := CapturedResponse{
			Timestamp:       base,
			Method:          "GET",
			Path:            "/xmlrpc.php",
			Host:            "blog.example.com",
			UserAgent:       "Mozilla/5.0",
			StatusCode:      200,
			ContentType:     "text/html",
			ContentLength:   int64(len(body)),
			BodyPreview:     append([]byte(nil), body...),
			BodyPreviewHash: hash,
			BodyComplete:    true,
		}
		lc.buffer.Insert(r)
	}
	req := LookupRequest{
		Method: "GET", Path: "/xmlrpc.php", Host: "blog.example.com",
		StatusCode: 200, Timestamp: base, Window: time.Hour,
	}
	return lc, req
}

func BenchmarkLookupFullRing32768(b *testing.B) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	lc, req := benchRing(32768)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ev := lc.Lookup(req)
		if ev.CandidateCount != 32768 {
			b.Fatalf("candidates = %d, want 32768 (worst case must scan everything)", ev.CandidateCount)
		}
	}
}

func BenchmarkPrePinFullRing32768(b *testing.B) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	lc, _ := benchRing(32768)
	base := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lc.PrePin(fmt.Sprintf("evt_%d", i), LookupRequest{
			Method: "GET", Path: "/xmlrpc.php", Host: "blog.example.com",
			StatusCode: 200, Timestamp: base, Window: time.Hour,
		})
	}
}
