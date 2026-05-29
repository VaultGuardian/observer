// internal/rec/capture_test.go
package rec

import (
	"context"
	"errors"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// bareCollector builds a liveCollector with the shared machinery wired up but
// no captures started — the same white-box shape the existing collector tests
// use, plus the captures map.
func bareCollector() *liveCollector {
	return &liveCollector{
		buffer:      NewRingBuffer(DefaultBufferConfig()),
		captures:    make(map[string]*namespaceCapture),
		vipPins:     make(map[string]*vipPin),
		vipEvidence: make(map[string]CapturedResponse),
	}
}

// testCapture builds a namespaceCapture whose sniffer feeds the collector's
// SHARED buffer and SHARED VIP handler — exactly how Start() wires a real one.
func testCapture(lc *liveCollector, name string) *namespaceCapture {
	s := newSniffer(lc.buffer, "", []int{80}, 64, DefaultMaxBodyBytes, DefaultVXLANPort,
		false, DefaultReassemblyConfig(), DefaultFlowConfig())
	s.onCapture = lc.handleCapturedResponse
	return &namespaceCapture{name: name, sniffer: s}
}

// dgramFD returns one end of an AF_UNIX datagram socketpair with a short
// receive timeout, so the real readLoop polls ctx.Done() and exits cleanly —
// no CAP_NET_RAW or AF_PACKET socket needed. readLoop owns and closes the
// returned fd; the peer end is closed on test cleanup.
func dgramFD(t *testing.T) int {
	t.Helper()
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { syscall.Close(pair[1]) })
	tv := syscall.Timeval{Sec: 0, Usec: 100_000} // 100ms — readLoop polls ctx between recvs
	if err := syscall.SetsockoptTimeval(pair[0], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
		t.Fatalf("set SO_RCVTIMEO: %v", err)
	}
	return pair[0]
}

// TestSharedBufferAcrossInstances proves that responses captured by two
// separate instances land in the ONE shared ring buffer and are both findable
// via the existing Lookup path — the unified-evidence guarantee.
func TestSharedBufferAcrossInstances(t *testing.T) {
	lc := bareCollector()

	a := testCapture(lc, "alpha")
	b := testCapture(lc, "beta")
	lc.captures["alpha"] = a
	lc.captures["beta"] = b

	// Manual gate so Lookup runs without a started read loop.
	lc.running.Store(true)

	// Sanity: both instances' sniffers point at the collector's one buffer.
	if a.sniffer.buffer != lc.buffer || b.sniffer.buffer != lc.buffer {
		t.Fatal("instances do not share the collector's buffer")
	}

	// Push a distinct response THROUGH each instance (the path runResponse
	// uses): the per-instance sniffer buffer pointer is the shared buffer.
	a.sniffer.buffer.Insert(makeResp("/from-alpha", []byte("aaa")))
	b.sniffer.buffer.Insert(makeResp("/from-beta", []byte("bbb")))

	for _, path := range []string{"/from-alpha", "/from-beta"} {
		ev := lc.Lookup(LookupRequest{
			Method:     "GET",
			Path:       path,
			StatusCode: 200,
			Timestamp:  time.Now(),
			Window:     time.Hour,
		})
		if ev == nil || ev.Transport == nil {
			t.Fatalf("Lookup(%s): no evidence (status=%v)", path, ev.Status)
		}
		if ev.Transport.StatusCode != 200 {
			t.Fatalf("Lookup(%s): status=%d, want 200", path, ev.Transport.StatusCode)
		}
	}
}

// TestConcurrentInstancesShareBufferRaceSafe drives two instances writing the
// shared ring buffer and VIP handler concurrently while Lookups run, so `go
// test -race` exercises the shared-writer paths (RingBuffer.Insert under
// rb.mu.Lock, handleCapturedResponse under vipMu.Lock). The buffer/VIP store are
// shared by pointer across instances; per-instance flow state is not shared.
func TestConcurrentInstancesShareBufferRaceSafe(t *testing.T) {
	lc := bareCollector()
	a := testCapture(lc, "alpha")
	b := testCapture(lc, "beta")
	lc.captures["alpha"] = a
	lc.captures["beta"] = b
	lc.running.Store(true)

	const n = 200
	done := make(chan struct{})

	writer := func(nc *namespaceCapture, tag string) {
		for i := 0; i < n; i++ {
			resp := makeResp("/"+tag, []byte(tag))
			nc.sniffer.buffer.Insert(resp)    // shared buffer
			lc.handleCapturedResponse(resp)   // shared VIP handler
		}
		done <- struct{}{}
	}

	go writer(a, "alpha")
	go writer(b, "beta")
	go func() {
		for i := 0; i < n; i++ {
			lc.Lookup(LookupRequest{Method: "GET", Path: "/alpha", StatusCode: 200, Timestamp: time.Now(), Window: time.Hour})
		}
		done <- struct{}{}
	}()

	for i := 0; i < 3; i++ {
		<-done
	}
}

// TestPartialFailureIsolation: when one instance fails to start, the collector
// stays Enabled (the healthy instance keeps capturing) and the failed instance
// carries a lastError. This is the seam later sessions rely on.
func TestPartialFailureIsolation(t *testing.T) {
	lc := bareCollector()

	healthy := testCapture(lc, "healthy")
	failed := testCapture(lc, "failed")
	lc.captures["healthy"] = healthy
	lc.captures["failed"] = failed

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := lc.startCapture(ctx, healthy, func() (int, error) { return dgramFD(t), nil }); err != nil {
		t.Fatalf("healthy startCapture returned error: %v", err)
	}
	errFailed := lc.startCapture(ctx, failed, func() (int, error) {
		return -1, errors.New("boom: cannot open socket")
	})
	if errFailed == nil {
		t.Fatal("failed instance: expected startCapture error, got nil")
	}

	// Collector stays enabled off the back of the healthy instance alone.
	if !lc.Enabled() {
		t.Fatal("Enabled() = false; want true (one healthy instance is active)")
	}
	if !healthy.running.Load() {
		t.Fatal("healthy instance not running")
	}
	if healthy.lastError != "" {
		t.Fatalf("healthy instance carries lastError = %q, want empty", healthy.lastError)
	}
	if failed.running.Load() {
		t.Fatal("failed instance reports running, want not running")
	}
	if failed.lastError == "" {
		t.Fatal("failed instance has empty lastError, want the open error recorded")
	}

	// Close stops the healthy instance cleanly.
	lc.Close()
	if healthy.running.Load() {
		t.Fatal("healthy instance still running after Close()")
	}
	if lc.Enabled() {
		t.Fatal("Enabled() = true after Close(); want false (no instances active)")
	}
}

// TestCloseJoinsCaptureGoroutines: Close() cancels and joins every capture's
// goroutines (readLoop/cleanup/flush) with no leak. Close() calling wg.Wait()
// would hang on a stuck goroutine, so a clean return already proves the join;
// the goroutine-count delta is an extra backstop.
func TestCloseJoinsCaptureGoroutines(t *testing.T) {
	base := runtime.NumGoroutine()

	lc := bareCollector()
	nc := testCapture(lc, "host")
	lc.captures["host"] = nc

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := lc.startCapture(ctx, nc, func() (int, error) { return dgramFD(t), nil }); err != nil {
		t.Fatalf("startCapture: %v", err)
	}

	lc.Close() // cancels instance ctx, joins the 3 goroutines

	// After wg.Wait() the goroutine functions have returned; allow a brief
	// settle for the runtime to reflect it, then assert no residual leak.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base+1 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if got := runtime.NumGoroutine(); got > base+1 {
		t.Fatalf("goroutine leak after Close(): base=%d got=%d", base, got)
	}
}
