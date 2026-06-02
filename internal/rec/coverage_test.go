// internal/rec/coverage_test.go
package rec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// covCapture builds a fully-populated namespaceCapture for coverage tests and
// registers it under the given map key, mirroring the post-publish state a real
// capture reaches once startCapture has run.
func covCapture(lc *liveCollector, key, name, id string, pid int, ports []int, running bool, lastErr string) *namespaceCapture {
	nc := &namespaceCapture{
		name:        name,
		containerID: id,
		pid:         pid,
		ports:       ports,
		lastError:   lastErr,
		startedAt:   time.Unix(1700000000, 0),
	}
	nc.running.Store(running)
	lc.captures[key] = nc
	return nc
}

func findActive(cov RECCoverage, name string) (CoverageCapture, bool) {
	for _, c := range cov.Active {
		if c.Name == name {
			return c, true
		}
	}
	return CoverageCapture{}, false
}

// TestCoverageActiveReflectsCaptures: auto-detect mode reports every live
// namespace capture (name, ports, pid, running, lastError, startedAt, shortID),
// and excludes the "host" fallback entry from Active.
func TestCoverageActiveReflectsCaptures(t *testing.T) {
	lc := bareCollector()
	covCapture(lc, "host", "host", "", 0, nil, true, "")
	covCapture(lc, "alpha", "alpha", "alpha123456789abc", 4242, []int{80, 3000}, true, "")
	covCapture(lc, "beta", "beta", "beta00000000ffff", 7, []int{8080}, true, "")

	cov := lc.Coverage()

	if cov.Mode != "auto-detect" {
		t.Fatalf("Mode = %q, want auto-detect", cov.Mode)
	}
	if cov.HostFallbackActive {
		t.Fatal("HostFallbackActive = true, want false (namespaces live)")
	}
	if len(cov.Active) != 2 {
		t.Fatalf("len(Active) = %d, want 2 (host excluded)", len(cov.Active))
	}
	if _, ok := findActive(cov, "host"); ok {
		t.Fatal("host entry must not appear in Active in auto-detect mode")
	}

	a, ok := findActive(cov, "alpha")
	if !ok {
		t.Fatal("alpha missing from Active")
	}
	if a.ContainerID != "alpha1234567" { // shortID = first 12 chars
		t.Errorf("alpha ContainerID = %q, want shortID alpha1234567", a.ContainerID)
	}
	if a.PID != 4242 || !a.Running {
		t.Errorf("alpha PID/Running = %d/%v, want 4242/true", a.PID, a.Running)
	}
	if len(a.Ports) != 2 || a.Ports[0] != 80 || a.Ports[1] != 3000 {
		t.Errorf("alpha Ports = %v, want [80 3000]", a.Ports)
	}
	if a.StartedAt != time.Unix(1700000000, 0) {
		t.Errorf("alpha StartedAt = %v, want 1700000000", a.StartedAt)
	}
}

// TestCoverageDiscoverySets: Skipped/Excluded/DroppedByCap come from the retained
// inventory, and a real REC_MAX_NAMESPACES cap populates DroppedByCap.
func TestCoverageDiscoverySets(t *testing.T) {
	lc := bareCollector()
	lc.config.MaxNamespaces = 1 // cap so applyNamespaceCap drops the excess

	public := []publicContainer{
		{ID: "id-web", Name: "web", Ports: []tcpPublish{{PublicPort: 8080, PrivatePort: 80}}},
		{ID: "id-api", Name: "api", Ports: []tcpPublish{{PublicPort: 9090, PrivatePort: 3000}}},
		{ID: "id-db", Name: "db", Ports: []tcpPublish{{PublicPort: 5432, PrivatePort: 5432}}},
	}
	inv := discoveryInventory{
		Public: public,
		Skipped: []skippedContainer{
			{Name: "redis", Reason: "no published TCP ports"},
			{Name: "worker", Reason: "loopback-only publish"},
		},
		Excluded: []publicContainer{
			{Name: "vault-itself", Ports: []tcpPublish{{PublicPort: 443, PrivatePort: 8443}}},
		},
	}
	// Mirror the real classify+cap+retain step.
	_, dropped := lc.applyNamespaceCap(inv.Public)
	lc.retainCoverage(inv, dropped)

	cov := lc.Coverage()

	if len(cov.Skipped) != 2 {
		t.Fatalf("len(Skipped) = %d, want 2", len(cov.Skipped))
	}
	if cov.Skipped[0].Name != "redis" || cov.Skipped[0].Reason != "no published TCP ports" {
		t.Errorf("Skipped[0] = %+v", cov.Skipped[0])
	}
	if len(cov.Excluded) != 1 || cov.Excluded[0].Name != "vault-itself" {
		t.Fatalf("Excluded = %+v, want one vault-itself", cov.Excluded)
	}
	if len(cov.Excluded[0].Ports) != 1 || cov.Excluded[0].Ports[0] != 8443 {
		t.Errorf("Excluded[0].Ports = %v, want [8443] (private)", cov.Excluded[0].Ports)
	}

	// MaxNamespaces=1 keeps "api" (sorted first by name) and drops api/db... actually
	// sort is by name: api, db, web → keep api, drop db + web.
	if len(cov.DroppedByCap) != 2 {
		t.Fatalf("len(DroppedByCap) = %d, want 2 (cap=1 over 3 public)", len(cov.DroppedByCap))
	}
	got := map[string]bool{}
	for _, d := range cov.DroppedByCap {
		got[d.Name] = true
	}
	if !got["db"] || !got["web"] {
		t.Errorf("DroppedByCap = %+v, want db+web (api kept)", cov.DroppedByCap)
	}
}

// TestCoverageHostFallbackActive: true when only the host capture exists, false
// once a namespace instance is live.
func TestCoverageHostFallbackActive(t *testing.T) {
	lc := bareCollector()
	covCapture(lc, "host", "host", "", 0, nil, true, "")

	cov := lc.Coverage()
	if !cov.HostFallbackActive {
		t.Fatal("HostFallbackActive = false, want true (only host)")
	}
	if cov.Mode != "host-fallback" {
		t.Errorf("Mode = %q, want host-fallback", cov.Mode)
	}
	if len(cov.Active) != 0 {
		t.Errorf("len(Active) = %d, want 0 (host excluded)", len(cov.Active))
	}

	// Add a live namespace → fallback no longer active.
	covCapture(lc, "alpha", "alpha", "alpha123456789", 10, []int{80}, true, "")
	cov = lc.Coverage()
	if cov.HostFallbackActive {
		t.Fatal("HostFallbackActive = true, want false (namespace live)")
	}
	if cov.Mode != "auto-detect" {
		t.Errorf("Mode = %q, want auto-detect", cov.Mode)
	}
}

// TestCoverageReflectsReconcile: opening/closing captures and rewriting the
// retained inventory both change the next snapshot.
func TestCoverageReflectsReconcile(t *testing.T) {
	lc := bareCollector()
	covCapture(lc, "alpha", "alpha", "alpha123456789", 10, []int{80}, true, "")
	lc.retainCoverage(discoveryInventory{
		Skipped: []skippedContainer{{Name: "redis", Reason: "no published TCP ports"}},
	}, nil)

	cov := lc.Coverage()
	if _, ok := findActive(cov, "alpha"); !ok || len(cov.Active) != 1 {
		t.Fatalf("pre-reconcile Active = %+v, want [alpha]", cov.Active)
	}
	if len(cov.Skipped) != 1 {
		t.Fatalf("pre-reconcile Skipped = %+v", cov.Skipped)
	}

	// Simulated reconcile: close alpha, open beta, refresh inventory (redis now
	// public, so it leaves Skipped).
	delete(lc.captures, "alpha")
	covCapture(lc, "beta", "beta", "beta000000000000", 20, []int{8080}, true, "")
	lc.retainCoverage(discoveryInventory{}, nil)

	cov = lc.Coverage()
	if _, ok := findActive(cov, "alpha"); ok {
		t.Error("alpha still present after close")
	}
	if _, ok := findActive(cov, "beta"); !ok || len(cov.Active) != 1 {
		t.Errorf("post-reconcile Active = %+v, want [beta]", cov.Active)
	}
	if len(cov.Skipped) != 0 {
		t.Errorf("post-reconcile Skipped = %+v, want empty", cov.Skipped)
	}
}

// TestCoverageDegradedCaptureStillListed: a capture with running=false + a
// lastError must still appear (dashboard shows "degraded", not vanished).
func TestCoverageDegradedCaptureStillListed(t *testing.T) {
	lc := bareCollector()
	covCapture(lc, "alpha", "alpha", "alpha123456789", 10, []int{80}, false, "setns: permission denied")

	cov := lc.Coverage()
	a, ok := findActive(cov, "alpha")
	if !ok {
		t.Fatal("degraded capture missing from Active")
	}
	if a.Running {
		t.Error("Running = true, want false")
	}
	if a.LastError != "setns: permission denied" {
		t.Errorf("LastError = %q", a.LastError)
	}
}

// TestCoverageLegacyMode: Mode "legacy", the single pinned capture in Active,
// empty discovery sets (legacy never runs discovery).
func TestCoverageLegacyMode(t *testing.T) {
	lc := bareCollector()
	lc.config.NSContainer = "captain-nginx"
	covCapture(lc, "captain-nginx", "captain-nginx", "ngx123456789abc", 55, []int{80}, true, "")
	// Even if some inventory were retained, legacy must not surface it.
	lc.retainCoverage(discoveryInventory{
		Skipped: []skippedContainer{{Name: "x", Reason: "y"}},
	}, []publicContainer{{Name: "z"}})

	cov := lc.Coverage()
	if cov.Mode != "legacy" {
		t.Fatalf("Mode = %q, want legacy", cov.Mode)
	}
	if len(cov.Active) != 1 || cov.Active[0].Name != "captain-nginx" {
		t.Fatalf("Active = %+v, want single captain-nginx", cov.Active)
	}
	if len(cov.Skipped) != 0 || len(cov.Excluded) != 0 || len(cov.DroppedByCap) != 0 {
		t.Errorf("legacy discovery sets non-empty: %+v", cov)
	}
	if cov.HostFallbackActive {
		t.Error("HostFallbackActive = true in legacy mode")
	}
}

// TestCoverageLegacyHostFallbackStillListed: in legacy mode the lone capture may
// itself be a host fallback (keyed "host"); it must still appear in Active.
func TestCoverageLegacyHostFallbackStillListed(t *testing.T) {
	lc := bareCollector()
	lc.config.NSContainer = "captain-nginx"
	covCapture(lc, "host", "host", "", 0, nil, true, "")

	cov := lc.Coverage()
	if cov.Mode != "legacy" {
		t.Fatalf("Mode = %q, want legacy", cov.Mode)
	}
	if len(cov.Active) != 1 {
		t.Fatalf("Active = %+v, want the single (host-fallback) capture", cov.Active)
	}
}

// TestNoOpCollectorCoverage: the disabled collector reports a "disabled" snapshot.
func TestNoOpCollectorCoverage(t *testing.T) {
	var c EvidenceCollector = &noOpCollector{reason: EvidenceNotAvailableCollectorDisabled}
	cov := c.Coverage()
	if cov.Mode != "disabled" {
		t.Fatalf("Mode = %q, want disabled", cov.Mode)
	}
	if len(cov.Active) != 0 || cov.HostFallbackActive {
		t.Errorf("expected empty disabled snapshot, got %+v", cov)
	}
}

// TestCoverageConcurrentWithReconcile drives Coverage() concurrently with a
// simulated reconcile (capMu-guarded open/close on captures + inventory rewrite)
// AND the real startCapture failure path (which writes lastError + identity under
// capMu). Run under `go test -race` to assert no data race and no deadlock.
func TestCoverageConcurrentWithReconcile(t *testing.T) {
	lc := bareCollector()
	ctx := context.Background()
	const iters = 300

	var wg sync.WaitGroup

	// Writer 1: simulated reconcile — open/close map entries under capMu and
	// rewrite the retained inventory.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			nc := &namespaceCapture{name: "sim", containerID: "sim0123456789", pid: i, ports: []int{80}}
			nc.running.Store(true)
			lc.capMu.Lock()
			lc.captures["sim"] = nc
			lc.capMu.Unlock()

			lc.retainCoverage(discoveryInventory{
				Skipped:  []skippedContainer{{Name: "redis", Reason: "no published TCP ports"}},
				Excluded: []publicContainer{{Name: "vault", Ports: []tcpPublish{{PrivatePort: 8443}}}},
			}, []publicContainer{{Name: "dropped"}})

			lc.capMu.Lock()
			delete(lc.captures, "sim")
			lc.capMu.Unlock()
		}
	}()

	// Writer 2: real open path failure — buildNamespaceCapture publishes, the
	// opener sets identity (capMu), startCapture records lastError (capMu).
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			nc := lc.buildNamespaceCapture("real", "real0123456789", []int{80}, []int{80}, "", DefaultVXLANPort)
			_ = lc.startCapture(ctx, nc, func() (int, error) {
				lc.setCaptureIdentity(nc, "real0123456789", 99)
				return -1, errors.New("boom")
			})
			lc.teardownInstance(nc, "real")
		}
	}()

	// Readers: snapshot coverage repeatedly.
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				cov := lc.Coverage()
				_ = cov.Mode
				for _, c := range cov.Active {
					_ = c.LastError
					_ = c.PID
					_ = c.Ports
				}
			}
		}()
	}

	wg.Wait()
}
