// internal/rec/reconcile.go
package rec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"time"
)

// =============================================================================
// Session 7: Runtime namespace reconciliation
// =============================================================================
//
// REC's monitored namespace set is established once at startup (Session 3). It
// goes stale when Docker state changes: a Swarm redeploy spawns a new task with
// a NEW container ID (heal via close-old + open-new), an in-place restart keeps
// the SAME container ID but a NEW PID so the startup socket points at a dead
// netns (heal via the PID-repair path), a new public container appears, or a
// container is removed.
//
// This file makes the monitored set track live Docker state continuously, so
// coverage self-heals without an Observer restart. Two triggers — a Docker
// /events listener and a periodic rescan ticker — both feed ONE serialized,
// idempotent reconcile that opens/closes/repairs per-namespace captures through
// the exact Session 2 discovery + Session 3 open path. Auto-detect mode only;
// legacy NSContainer mode starts none of this machinery.
//
// IDENTITY HAZARD: discovery yields the FULL 64-char container ID, but a started
// capture's nc.containerID is the SHORT 12-char ID (set by dockerNamespaceOpener
// via inspectContainerPID). Every identity comparison below normalizes BOTH
// sides through shortID() (idempotent on already-short IDs) or reconcile would
// see every container as simultaneously orphaned + missing and churn each cycle.

// =============================================================================
// Pure diff
// =============================================================================

type actionKind int

const (
	actionClose  actionKind = iota // instance whose container is gone
	actionRepair                   // same container ID, PID changed → reopen
	actionOpen                     // public container with no instance
)

// desiredCapture is one container discovery says SHOULD be monitored, post
// cap+exclude. id is shortID(pc.ID). pid is the freshly-resolved host PID, or 0
// when unknown (pidFor failed) — 0 never triggers a repair, it is retried next
// cycle.
type desiredCapture struct {
	id   string
	name string
	pid  int
	pc   publicContainer
}

// reconcileAction is one operation the executor must apply. mapKey + nc are the
// collector map-key and instance for close/repair; desired carries the
// publicContainer for open/repair.
type reconcileAction struct {
	kind    actionKind
	id      string // shortID — the identity key
	name    string
	mapKey  string
	nc      *namespaceCapture
	desired desiredCapture
	oldPID  int
	newPID  int
}

// diffReconcile compares the desired set (keyed by shortID) against a snapshot
// of the collector's captures map and returns the actions that converge actual
// to desired. PURE: no Docker, no sockets, no locks.
//
// The actual map is keyed by the collector's MAP KEY (name / name#shortID /
// "host"); internally it is re-keyed by shortID(nc.containerID) for matching,
// SKIPPING host/empty-ID instances (the host fallback is driven explicitly by
// reconcileOnce, never by this diff). Returns deterministically ordered:
// closes, then repairs, then opens; each group sorted by id.
func diffReconcile(desired map[string]desiredCapture, actual map[string]*namespaceCapture) []reconcileAction {
	type actualEntry struct {
		mapKey string
		nc     *namespaceCapture
	}
	actualByShort := make(map[string]actualEntry, len(actual))
	for k, nc := range actual {
		if nc.containerID == "" {
			continue // host instance — never a diff candidate
		}
		actualByShort[shortID(nc.containerID)] = actualEntry{mapKey: k, nc: nc}
	}

	var actions []reconcileAction
	for sid, d := range desired {
		ae, ok := actualByShort[sid]
		if !ok {
			actions = append(actions, reconcileAction{kind: actionOpen, id: sid, name: d.name, desired: d})
			continue
		}
		// Present on both sides. A PID change (both PIDs known and different) is
		// an in-place restart → repair. Same/unknown PID is the steady-state
		// no-op that makes reconcile idempotent.
		if d.pid != 0 && ae.nc.pid != 0 && d.pid != ae.nc.pid {
			actions = append(actions, reconcileAction{
				kind: actionRepair, id: sid, name: d.name,
				mapKey: ae.mapKey, nc: ae.nc, desired: d,
				oldPID: ae.nc.pid, newPID: d.pid,
			})
		}
		delete(actualByShort, sid) // consumed
	}
	// Anything still in actualByShort has no desired entry → orphaned, close it.
	for sid, ae := range actualByShort {
		actions = append(actions, reconcileAction{
			kind: actionClose, id: sid, name: ae.nc.name, mapKey: ae.mapKey, nc: ae.nc,
		})
	}

	sort.Slice(actions, func(i, j int) bool {
		if actions[i].kind != actions[j].kind {
			return actions[i].kind < actions[j].kind
		}
		return actions[i].id < actions[j].id
	})
	return actions
}

// =============================================================================
// Reconcile executor
// =============================================================================

// reconcileOnce runs one full idempotent reconcile: re-discover, diff, apply,
// then enforce the host-fallback invariant. Safe to call repeatedly; unchanged
// Docker state is a no-op beyond the diff. Never aborts on a per-container open
// failure (partial-failure isolation) and never tears anything down on a
// transient Docker query failure.
func (lc *liveCollector) reconcileOnce(ctx context.Context) {
	containers, err := lc.deps.fetch()
	if err != nil {
		// Transient daemon hiccup — keep current captures; next tick retries.
		log.Printf("[rec] Reconcile: Docker query failed: %v — keeping current captures", err)
		return
	}

	inv := classifyContainers(containers, lc.config.ExcludeContainers)
	capped := lc.applyNamespaceCap(inv.Public) // shared sort+cap+dropped-logging

	desired := make(map[string]desiredCapture, len(capped))
	for _, pc := range capped {
		pid, perr := lc.deps.pidFor(pc.ID, pc.Name)
		if perr != nil {
			pid = 0 // unknown → no repair decision this cycle
		}
		sid := shortID(pc.ID)
		desired[sid] = desiredCapture{id: sid, name: pc.Name, pid: pid, pc: pc}
	}

	lc.capMu.Lock()
	snapshot := make(map[string]*namespaceCapture, len(lc.captures))
	for k, v := range lc.captures {
		snapshot[k] = v
	}
	lc.capMu.Unlock()

	for _, a := range diffReconcile(desired, snapshot) {
		switch a.kind {
		case actionClose:
			lc.applyClose(a)
		case actionRepair:
			lc.applyRepair(ctx, a)
		case actionOpen:
			lc.applyOpen(ctx, a)
		}
	}

	lc.enforceHostInvariant(ctx)
}

// applyOpen opens a namespace capture for a newly-discovered container, reusing
// the exact startup open path. A failure is isolated to this instance.
func (lc *liveCollector) applyOpen(ctx context.Context, a reconcileAction) {
	pc := a.desired.pc
	snifferPorts := unionPorts(lc.config.Ports, privatePorts(pc.Ports))
	nc := lc.buildNamespaceCapture(pc.Name, pc.ID, snifferPorts, lc.config.Interface, lc.vxlanPort)
	nc.ports = privatePorts(pc.Ports)
	if err := lc.startCapture(ctx, nc, lc.deps.openerFor(pc, nc)); err != nil {
		// lastError already set on nc by startCapture; entry stays in the map
		// (matches startup behavior). Siblings unaffected.
		log.Printf("[rec] Reconcile: namespace capture for %q failed: %v — continuing", pc.Name, err)
		return
	}
	log.Printf("[rec] Reconcile: now monitoring container %q (%s)", pc.Name, shortID(pc.ID))
}

// applyClose tears down an orphaned instance and removes it from the map.
func (lc *liveCollector) applyClose(a reconcileAction) {
	lc.teardownInstance(a.nc, a.mapKey)
	log.Printf("[rec] Reconcile: container %q (%s) removed from monitoring", a.name, a.id)
}

// applyRepair is the in-place-restart fix: the container kept its ID but its PID
// changed, so the startup socket points at a dead netns. Tear the stale instance
// down and REMOVE it from the map BEFORE rebuilding, so buildNamespaceCapture's
// name#shortID collision suffix does not create a duplicate entry; then reopen
// in the new namespace via the same open path.
func (lc *liveCollector) applyRepair(ctx context.Context, a reconcileAction) {
	log.Printf("[rec] Reconcile: container %s PID changed %d→%d — reopening namespace socket",
		a.id, a.oldPID, a.newPID)
	lc.teardownInstance(a.nc, a.mapKey)

	pc := a.desired.pc
	snifferPorts := unionPorts(lc.config.Ports, privatePorts(pc.Ports))
	nc := lc.buildNamespaceCapture(pc.Name, pc.ID, snifferPorts, lc.config.Interface, lc.vxlanPort)
	nc.ports = privatePorts(pc.Ports)
	if err := lc.startCapture(ctx, nc, lc.deps.openerFor(pc, nc)); err != nil {
		log.Printf("[rec] Reconcile: reopen for %q failed: %v — continuing", pc.Name, err)
	}
}

// teardownInstance cancels an instance, joins its goroutines, and deletes it
// from the captures map (re-verifying identity under capMu so a concurrent
// rebuild under the same key is never clobbered).
func (lc *liveCollector) teardownInstance(nc *namespaceCapture, mapKey string) {
	if nc.cancel != nil {
		nc.cancel()
	}
	nc.wg.Wait()
	lc.capMu.Lock()
	if cur, ok := lc.captures[mapKey]; ok && cur == nc {
		delete(lc.captures, mapKey)
	}
	lc.capMu.Unlock()
}

// enforceHostInvariant maintains: the host fallback capture is active IFF there
// are zero live namespace instances. This runs AFTER the diff actions, so any
// just-opened namespace capture is already confirmed running — closing the host
// here leaves no coverage gap, and avoids double-capture into the shared buffer.
// When the last namespace instance is closed, the host fallback is reopened.
func (lc *liveCollector) enforceHostInvariant(ctx context.Context) {
	lc.capMu.Lock()
	liveNS := 0
	for _, c := range lc.captures {
		if c.containerID != "" && c.running.Load() {
			liveNS++
		}
	}
	host := lc.captures["host"]
	lc.capMu.Unlock()

	switch {
	case liveNS > 0 && host != nil && host.running.Load():
		lc.teardownInstance(host, "host")
		log.Printf("[rec] Reconcile: namespace coverage active — retiring host fallback capture")
	case liveNS == 0 && (host == nil || !host.running.Load()):
		log.Printf("[rec] Reconcile: no namespace captures remain — reopening host fallback capture")
		if _, err := lc.openHostCapture(ctx, lc.config.Interface, lc.vxlanPort, lc.deps.hostOpen); err != nil {
			log.Printf("[rec] Reconcile: host fallback reopen failed: %v", err)
		}
	}
}

// =============================================================================
// Manager goroutines: reconcile loop, rescan ticker, events listener
// =============================================================================

// reconcileLoop is the single serialized consumer of reconcile triggers. One
// goroutine means lc.captures is mutated by at most one reconcile at a time.
func (lc *liveCollector) reconcileLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-lc.reconcileCh:
			lc.reconcileOnce(ctx)
		}
	}
}

// trigger requests a reconcile. The cap-1 channel coalesces bursts: if a
// reconcile is already pending, additional triggers are dropped (the single
// in-flight reconcile re-reads Docker and converges to the latest state anyway).
func (lc *liveCollector) trigger() {
	select {
	case lc.reconcileCh <- struct{}{}:
	default:
	}
}

// rescanTicker periodically triggers a reconcile — the backstop that guarantees
// coverage self-heals even if a Docker event was dropped or the event stream is
// mid-reconnect.
func (lc *liveCollector) rescanTicker(ctx context.Context) {
	interval := lc.config.RescanInterval
	if interval <= 0 {
		interval = DefaultRescanInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			lc.trigger()
		}
	}
}

// eventsURL subscribes to container lifecycle events that can imply a coverage
// change (a new/removed container, or a PID change from a restart/health flip).
const eventsURL = `http://localhost/events?filters={"type":["container"],"event":["start","die","stop","restart","health_status"]}`

// eventsListener streams Docker container events and triggers a reconcile on
// each one, reconnecting with bounded backoff if the stream errors or closes. A
// dropped stream NEVER kills the collector — the rescan ticker holds coverage
// during the gap.
func (lc *liveCollector) eventsListener(ctx context.Context) {
	const maxBackoff = 30 * time.Second
	// A healthy /events connection can stay quiet for minutes, so "zero events"
	// alone must not look unhealthy — a long-lived stream that simply had nothing
	// to report counts as healthy too.
	const healthyStreamThreshold = 1 * time.Minute
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		start := time.Now()
		gotEvent, err := lc.streamEvents(ctx)
		lived := time.Since(start)
		if ctx.Err() != nil {
			return
		}
		healthy := gotEvent || lived >= healthyStreamThreshold
		backoff = backoffAfterStream(backoff, maxBackoff, healthy)
		log.Printf("[rec] Reconcile: Docker event stream ended (%v) — reconnecting in %s; periodic rescan holds coverage meanwhile", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// nextBackoff doubles the current delay, capped at max. Pure so the backoff
// schedule is unit-testable without sleeping.
func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		next = max
	}
	return next
}

// backoffAfterStream resets to 1s after a healthy stream, else grows toward max.
// Pure so the decision is unit-testable without sleeping.
func backoffAfterStream(cur, max time.Duration, healthy bool) time.Duration {
	if healthy {
		return time.Second
	}
	return nextBackoff(cur, max)
}

// streamEvents opens one Docker /events connection and consumes it until the
// stream ends or ctx is cancelled. Returns whether at least one event was
// decoded (so the caller can reset backoff on a previously-healthy stream).
func (lc *liveCollector) streamEvents(ctx context.Context) (gotEvent bool, err error) {
	client := newDockerStreamClient(lc.config.DockerSocket)
	req, reqErr := http.NewRequestWithContext(ctx, "GET", eventsURL, nil)
	if reqErr != nil {
		return false, reqErr
	}
	resp, doErr := client.Do(req)
	if doErr != nil {
		return false, doErr
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, fmt.Errorf("docker /events returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(snippet))
	}
	return lc.consumeEvents(ctx, resp.Body)
}

// consumeEvents decodes the streamed event JSON and triggers a reconcile per
// event. The reader seam lets tests feed newline-delimited JSON without a live
// Docker socket. Returns on decode error / EOF / ctx cancellation.
func (lc *liveCollector) consumeEvents(ctx context.Context, r io.Reader) (gotEvent bool, err error) {
	dec := json.NewDecoder(r)
	for {
		if ctx.Err() != nil {
			return gotEvent, ctx.Err()
		}
		var ev struct {
			Action string `json:"Action"`
			Actor  struct {
				ID         string            `json:"ID"`
				Attributes map[string]string `json:"Attributes"`
			} `json:"Actor"`
		}
		if decErr := dec.Decode(&ev); decErr != nil {
			if ctx.Err() != nil {
				return gotEvent, ctx.Err()
			}
			return gotEvent, decErr
		}
		gotEvent = true
		// Any relevant container event → full idempotent reconcile.
		lc.trigger()
	}
}
