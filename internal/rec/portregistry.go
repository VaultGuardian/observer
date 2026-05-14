// internal/rec/portregistry.go
//
// Port registry for the AF_PACKET sniffer.
//
// Background:
//   v0.47-rc2 and earlier hardcoded the HTTP-aware port set to {80, 8080}.
//   Any backend listening on a different port (e.g. CapRover's captain-captain
//   on 3000) was invisible to REC — packets dropped, no evidence captured,
//   findings parked at SUSPICIOUS forever waiting for a body that never came.
//
// Three sources feed this registry, in priority order:
//   1. Static defaults from CollectorConfig.Ports (80, 8080).
//   2. Operator override via REC_PORTS env var (set in main.go before Start).
//   3. Payload-based learning at runtime: if a packet on an unknown port
//      starts with an HTTP method token or "HTTP/1.x", that port is learned
//      and used for subsequent traffic.
//
// Hot-path design:
//   has() must be lock-free. Reads happen for every TCP packet processed.
//   We use atomic.Pointer to a snapshot map and copy-on-write for learns.
//   Writes are rare (one per first-seen port) and serialized by a mutex.
//
// Bounding:
//   Learned ports are capped (default 64) to prevent unbounded growth from
//   pathological traffic patterns. Once full, new learns are silently
//   refused — the configured/learned set is sticky for the process lifetime.
//   This is safe: REC is namespace-scoped, so the universe of legitimate
//   ports is small and finite.

package rec

import (
	"sync"
	"sync/atomic"
)

// portRegistry holds the set of TCP ports REC treats as HTTP-bearing.
// Reads are lock-free (atomic snapshot). Writes (learns) are serialized
// and use copy-on-write to avoid ever mutating a map while readers hold it.
type portRegistry struct {
	// snapshot is the read-side view. Replaced wholesale on every learn.
	// Treat the map under the pointer as immutable.
	snapshot atomic.Pointer[map[int]bool]

	// mu serializes learn() calls. Read paths never take this lock.
	mu sync.Mutex

	// learned tracks ports added via payload detection (vs configured).
	// Bounded by cap.
	learned map[int]struct{}

	// configured is the immutable set of ports seeded at construction.
	// Used by Stats() to distinguish learned from configured counts.
	configured map[int]struct{}

	// cap is the maximum number of ports we'll learn at runtime.
	// 0 disables learning entirely (configured-only behavior).
	cap int

	// learnedAttempts counts every time learn() was called, regardless of
	// whether it added a new port. learnedAdded counts successful additions.
	// learnedRefused counts caps hits. All atomic for stats().
	learnedAttempts atomic.Int64
	learnedAdded    atomic.Int64
	learnedRefused  atomic.Int64
}

// newPortRegistry builds a registry seeded with the given configured ports.
// learnCap bounds runtime port learning; pass 0 to disable learning.
func newPortRegistry(configured []int, learnCap int) *portRegistry {
	if learnCap < 0 {
		learnCap = 0
	}
	pr := &portRegistry{
		learned:    make(map[int]struct{}),
		configured: make(map[int]struct{}, len(configured)),
		cap:        learnCap,
	}
	initial := make(map[int]bool, len(configured))
	for _, p := range configured {
		if p <= 0 || p > 65535 {
			continue
		}
		initial[p] = true
		pr.configured[p] = struct{}{}
	}
	pr.snapshot.Store(&initial)
	return pr
}

// has reports whether the given port is currently in the registry.
// Lock-free. Safe to call from any goroutine.
func (pr *portRegistry) has(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	m := pr.snapshot.Load()
	if m == nil {
		return false
	}
	return (*m)[port]
}

// learn adds the given port to the registry if not already present and the
// learned-port cap has not been hit. Returns true if the port was newly
// added (caller can use this signal to log once per port).
//
// Bounded — once the learned cap is hit, additional learns are refused.
// Configured ports are not counted against the cap; only learned ones are.
func (pr *portRegistry) learn(port int) bool {
	pr.learnedAttempts.Add(1)
	if pr.cap == 0 {
		pr.learnedRefused.Add(1)
		return false
	}
	if port <= 0 || port > 65535 {
		pr.learnedRefused.Add(1)
		return false
	}
	// Fast-path early exit without taking the lock.
	if pr.has(port) {
		return false
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Re-check under the lock — another goroutine may have learned it.
	if cur := pr.snapshot.Load(); cur != nil && (*cur)[port] {
		return false
	}
	// Configured ports are seeded at construction and never re-learned.
	if _, isConfigured := pr.configured[port]; isConfigured {
		return false
	}
	if len(pr.learned) >= pr.cap {
		pr.learnedRefused.Add(1)
		return false
	}

	pr.learned[port] = struct{}{}

	// Copy-on-write: build a new snapshot map and atomically swap it in.
	// Readers holding the old snapshot continue to use it safely; the
	// pointer flip is atomic.
	old := *pr.snapshot.Load()
	next := make(map[int]bool, len(old)+1)
	for k, v := range old {
		next[k] = v
	}
	next[port] = true
	pr.snapshot.Store(&next)

	pr.learnedAdded.Add(1)
	return true
}

// stats returns a snapshot of registry telemetry for logging / dashboards.
// configuredCount + learnedCount = total entries currently in the registry.
type portRegistryStats struct {
	ConfiguredCount int
	LearnedCount    int
	LearnedAttempts int64
	LearnedAdded    int64
	LearnedRefused  int64
	LearnCap        int
}

func (pr *portRegistry) stats() portRegistryStats {
	pr.mu.Lock()
	learnedCount := len(pr.learned)
	pr.mu.Unlock()
	return portRegistryStats{
		ConfiguredCount: len(pr.configured),
		LearnedCount:    learnedCount,
		LearnedAttempts: pr.learnedAttempts.Load(),
		LearnedAdded:    pr.learnedAdded.Load(),
		LearnedRefused:  pr.learnedRefused.Load(),
		LearnCap:        pr.cap,
	}
}
