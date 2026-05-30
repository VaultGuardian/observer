// internal/rec/capture.go
package rec

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================
// Per-namespace capture instance
// =============================================================================
//
// namespaceCapture is one capture source: a single network-namespace socket
// (or the host). It owns its socket, capture goroutines, cancel func, and
// (later) its own container-side port registry. It does NOT own the ring
// buffer, VIP store, or request↔response pairing state — those live on the
// liveCollector and are shared by pointer across all instances, so the
// coordinator's Lookup path stays unified regardless of which namespace
// captured a given response.
//
// Today the collector holds exactly one of these; later sessions add more with
// auto-discovery. The partial-failure isolation in startCapture is the seam
// those sessions rely on: one capture failing must not disable the others.
type namespaceCapture struct {
	containerID string
	name        string
	pid         int
	ports       []int // seeded later with container-side ports (e.g. 80, 3000), not host-published
	sniffer     *sniffer
	cancel      context.CancelFunc
	running     atomic.Bool
	lastError   string
	startedAt   time.Time

	// wg joins this instance's capture goroutines so Close() can shut down
	// without leaking goroutines or file descriptors.
	wg sync.WaitGroup
}

// startCapture opens one capture instance's socket and launches its goroutines.
//
// The opener is injected so callers (and tests) control how the fd is obtained:
// production passes a closure doing the namespace→host fallback; tests pass a
// stub that forces success or failure without CAP_NET_RAW or a real AF_PACKET
// socket.
//
// Partial-failure isolation: if the opener fails, the instance records its
// lastError and stays running=false, but the error is returned for the CALLER
// to decide what to do. It never flips a global flag, so sibling instances are
// unaffected — this is the whole reason for the refactor.
func (lc *liveCollector) startCapture(parent context.Context, nc *namespaceCapture, open func() (int, error)) error {
	ctx, cancel := context.WithCancel(parent)
	nc.cancel = cancel

	fd, err := open()
	if err != nil {
		nc.lastError = err.Error()
		nc.running.Store(false)
		cancel()
		return err
	}

	nc.startedAt = time.Now()
	nc.lastError = ""
	nc.running.Store(true)

	nc.wg.Add(3)
	// The read loop owns the fd (readLoop defers syscall.Close(fd)). When it
	// returns (parent ctx or this instance's ctx cancelled), the instance is no
	// longer running.
	go func() {
		defer nc.wg.Done()
		defer nc.running.Store(false)
		nc.sniffer.readLoop(ctx, fd)
	}()
	go func() {
		defer nc.wg.Done()
		nc.sniffer.cleanupLoop(ctx)
	}()
	go func() {
		defer nc.wg.Done()
		nc.sniffer.flushLoop(ctx)
	}()

	return nil
}

// Close stops every capture instance and joins their goroutines. It is a
// concrete method, NOT part of EvidenceCollector: production shutdown happens
// via parent-ctx cancellation (unchanged by this refactor), and this method
// exists for deterministic teardown in tests.
//
// Session 7: in auto-detect mode Close() FIRST stops the runtime reconciliation
// manager (events listener, rescan ticker, reconcile loop, and vipCleanupLoop —
// all owned by mgrCancel/mgrWG) and joins them, THEN tears down the captures.
// Stopping the manager first guarantees no in-flight reconcile is mutating the
// captures map while we snapshot and cancel it below. In legacy NSContainer mode
// mgrCancel is nil (no manager runs); vipCleanupLoop there is still bound to the
// parent ctx and stops only on parent cancel — unchanged from prior behavior.
func (lc *liveCollector) Close() {
	if lc.mgrCancel != nil {
		lc.mgrCancel()
		lc.mgrWG.Wait()
	}

	lc.capMu.Lock()
	caps := make([]*namespaceCapture, 0, len(lc.captures))
	for _, c := range lc.captures {
		caps = append(caps, c)
	}
	lc.capMu.Unlock()

	for _, c := range caps {
		if c.cancel != nil {
			c.cancel()
		}
	}
	for _, c := range caps {
		c.wg.Wait()
	}
}
