package rec

import "time"

// RECCoverage is a structured, queryable snapshot of what REC is covering right
// now, composed from live capture state + the discovery classification REC
// already computes. It answers "is this source actually covered, and if not,
// why?" — active namespace captures, containers skipped (with reason), excluded
// (REC_EXCLUDE_CONTAINERS), dropped by the REC_MAX_NAMESPACES cap (blind spots),
// and degraded host-fallback state. It is PURE OBSERVABILITY: composing it
// changes no capture/pairing/buffer/reconcile decision. This is the contract the
// coordinator/CLI/dashboard render later (Session 6); keep field names stable.
type RECCoverage struct {
	// Mode is the capture topology:
	//   "auto-detect"   — per-container namespace captures (≥1 namespace live)
	//   "host-fallback" — auto-detect mode degraded to the single host capture
	//   "legacy"        — REC_NS_CONTAINER pinned to one namespace
	//   "disabled"      — collector is a no-op
	Mode string `json:"mode"`

	// HostFallbackActive reports the host-fallback invariant: in auto-detect mode
	// the "host" capture is active IFF zero namespace instances are live. Coverage
	// only reports this — it never changes it.
	HostFallbackActive bool `json:"host_fallback_active"`

	// MaxNamespaces is the effective REC_MAX_NAMESPACES cap (resolved default).
	MaxNamespaces int `json:"max_namespaces"`

	// Active is one entry per live capture source, EXCLUDING the host-fallback
	// entry in auto-detect mode. A degraded capture (Running=false with LastError
	// set) still appears here so the dashboard shows "degraded", not a vanished
	// source (partial-failure isolation).
	Active []CoverageCapture `json:"active"`

	// Skipped / Excluded / DroppedByCap are the non-covered classifications,
	// retained from the latest discovery + cap. Empty in legacy mode (no
	// discovery) and until the first auto-detect classification runs.
	Skipped      []CoverageSkipped  `json:"skipped"`
	Excluded     []CoverageExcluded `json:"excluded"`
	DroppedByCap []CoverageDropped  `json:"dropped_by_cap"`
}

// CoverageCapture describes one active capture source.
type CoverageCapture struct {
	Name        string    `json:"name"`
	ContainerID string    `json:"container_id"` // 12-char shortID; empty for the host capture
	Ports       []int     `json:"ports"`        // container-side (private) ports
	PID         int       `json:"pid"`
	Running     bool      `json:"running"`
	LastError   string    `json:"last_error"`
	StartedAt   time.Time `json:"started_at"`
}

// CoverageSkipped is a running container REC chose not to monitor (internal- or
// loopback-only), with the human-readable reason.
type CoverageSkipped struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// CoverageExcluded is an externally-reachable container suppressed by
// REC_EXCLUDE_CONTAINERS.
type CoverageExcluded struct {
	Name  string `json:"name"`
	Ports []int  `json:"ports"` // container-side (private) ports
}

// CoverageDropped is a public container NOT monitored because the
// REC_MAX_NAMESPACES cap was reached — a security blind spot.
type CoverageDropped struct {
	Name string `json:"name"`
}

// retainCoverage stores the latest discovery classification + cap-dropped set
// for the coverage-status model. Called at startup (startAutoDetect) and on
// every reconcile (reconcileOnce), at the same classify+cap step. Guarded by
// coverageMu, which is never held simultaneously with capMu.
func (lc *liveCollector) retainCoverage(inv discoveryInventory, dropped []publicContainer) {
	lc.coverageMu.Lock()
	lc.lastInventory = inv
	lc.droppedByCap = dropped
	lc.coverageMu.Unlock()
}

// Coverage returns a snapshot of what REC is covering right now. Safe to call
// from any goroutine; it does not block the capture/reconcile hot paths.
//
// Lock discipline: capMu and coverageMu are NEVER held simultaneously. Coverage
// snapshots the captures map under capMu into locals, releases it, then reads the
// retained inventory under coverageMu.
func (lc *liveCollector) Coverage() RECCoverage {
	cov := RECCoverage{
		MaxNamespaces: lc.config.MaxNamespaces,
	}
	if cov.MaxNamespaces <= 0 {
		cov.MaxNamespaces = DefaultMaxNamespaces
	}
	legacy := lc.config.NSContainer != ""

	// 1. Snapshot the captures map under capMu into locals, then release.
	lc.capMu.Lock()
	active := make([]CoverageCapture, 0, len(lc.captures))
	hostPresent := false
	nonHost := 0
	for key, c := range lc.captures {
		isHost := key == "host"
		if isHost {
			hostPresent = true
		} else {
			nonHost++
		}
		cc := CoverageCapture{
			Name:        c.name,
			ContainerID: shortID(c.containerID),
			Ports:       append([]int(nil), c.ports...),
			PID:         c.pid,
			Running:     c.running.Load(),
			LastError:   c.lastError,
			StartedAt:   c.startedAt,
		}
		// In auto-detect mode the host-fallback entry is reported via
		// HostFallbackActive/Mode, NOT as a namespace in Active. In legacy mode the
		// lone capture may itself be the host fallback and must still appear.
		if isHost && !legacy {
			continue
		}
		active = append(active, cc)
	}
	lc.capMu.Unlock()
	cov.Active = active

	if legacy {
		// Legacy single-namespace mode never runs discovery/reconcile — no inventory
		// to report. Otherwise byte-for-byte unchanged.
		cov.Mode = "legacy"
		return cov
	}

	cov.HostFallbackActive = hostPresent && nonHost == 0
	if cov.HostFallbackActive {
		cov.Mode = "host-fallback"
	} else {
		cov.Mode = "auto-detect"
	}

	// 2. Read the retained discovery classification under coverageMu, then release.
	lc.coverageMu.Lock()
	inv := lc.lastInventory
	dropped := lc.droppedByCap
	lc.coverageMu.Unlock()

	for _, s := range inv.Skipped {
		cov.Skipped = append(cov.Skipped, CoverageSkipped{Name: s.Name, Reason: s.Reason})
	}
	for _, e := range inv.Excluded {
		cov.Excluded = append(cov.Excluded, CoverageExcluded{Name: e.Name, Ports: privatePorts(e.Ports)})
	}
	for _, d := range dropped {
		cov.DroppedByCap = append(cov.DroppedByCap, CoverageDropped{Name: d.Name})
	}

	return cov
}
