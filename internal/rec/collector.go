package rec

import (
	"context"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// =============================================================================
// EvidenceCollector Interface
// =============================================================================
//
// The main pipeline interacts with REC exclusively through this interface.
// If REC can't start (missing CAP_NET_RAW, not opted in), the pipeline gets
// a NoOp implementation. Observer keeps running — REC is enrichment-only.
//
// PHASE 1 CONSTRAINT: REC is read-only enrichment.
// It NEVER influences classification or alert routing.
// It ONLY attaches evidence to already-generated alerts.

type EvidenceCollector interface {
	// Start begins the packet capture goroutine.
	// Returns an error if capture cannot be initialized (logged, not fatal).
	Start(ctx context.Context) error

	// Lookup correlates a request with a captured response.
	// Returns Evidence with an explicit status — never nil.
	Lookup(req LookupRequest) *Evidence

	// Enabled returns true if the collector is actively capturing.
	Enabled() bool

	// Stats returns a snapshot of REC telemetry counters.
	// Safe to call from any goroutine. Returns zero stats if disabled.
	Stats() RECStats
}

// DefaultCorrelationWindow is the agreed-upon L7 heuristic window.
// Tight enough to avoid false associations on low-traffic servers,
// wide enough to account for log write latency.
const DefaultCorrelationWindow = 500 * time.Millisecond

// =============================================================================
// Collector Config
// =============================================================================

type CollectorConfig struct {
	// Whether REC is enabled (opt-in, disabled by default)
	Enabled bool

	// Network interface to capture on (e.g., "docker0", "br-xxxxx")
	// Empty = capture on all interfaces
	Interface string

	// Ports to capture plaintext HTTP traffic on.
	// Framing: "plaintext HTTP visible after TLS termination" — not "port 80."
	Ports []int

	// Ring buffer configuration
	Buffer BufferConfig

	// VXLAN destination port for overlay network decapsulation.
	// 0 = auto-detect from Docker Swarm (or default 4789).
	// Docker Swarm defaults to 4789 but it's configurable via
	// `docker swarm init --data-path-port`.
	VXLANPort uint16

	// Docker socket path for Swarm detection at startup.
	// Defaults to /var/run/docker.sock if empty.
	DockerSocket string

	// NSContainer is a container name pattern for namespace capture mode.
	// If set and a matching running container is found, REC opens its
	// AF_PACKET socket inside that container's network namespace instead
	// of the host's. This is required for single-node Docker Swarm where
	// overlay traffic never touches the host network stack.
	//
	// Typical value: "captain-nginx" (CapRover), "nginx", "traefik", etc.
	// Substring match, case-insensitive.
	//
	// Empty = host namespace capture (existing behavior).
	NSContainer string
}

// DefaultCollectorConfig returns the design team-agreed defaults.
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		Enabled:      false, // opt-in, not surprise packet capture
		Interface:    "",
		Ports:        []int{80, 8080},
		Buffer:       DefaultBufferConfig(),
		VXLANPort:    0, // 0 = auto-detect from Docker API
		DockerSocket: "/var/run/docker.sock",
		NSContainer:  "", // empty = host namespace
	}
}

// =============================================================================
// NewCollector — Factory with Graceful Degradation
// =============================================================================

func NewCollector(cfg CollectorConfig) EvidenceCollector {
	if !cfg.Enabled {
		log.Println("[rec] Response Evidence Capture is disabled (opt-in via REC_ENABLED=true)")
		return &noOpCollector{reason: EvidenceNotAvailableCollectorDisabled}
	}

	if !hasCapNetRaw() {
		log.Println("[rec] WARNING: REC enabled but missing CAP_NET_RAW capability. " +
			"Add AmbientCapabilities=CAP_NET_RAW to observer.service or run with cap_add:[NET_RAW]. " +
			"REC is disabled — log classification continues normally.")
		return &noOpCollector{reason: EvidenceNotAvailableCollectorDisabled}
	}

	return &liveCollector{
		config: cfg,
		buffer: NewRingBuffer(cfg.Buffer),
	}
}

// =============================================================================
// NoOp Collector — Returned when REC can't run
// =============================================================================

type noOpCollector struct {
	reason EvidenceStatus
}

func (n *noOpCollector) Start(ctx context.Context) error { return nil }

func (n *noOpCollector) Lookup(req LookupRequest) *Evidence {
	return &Evidence{
		Status:                n.reason,
		CorrelationConfidence: ConfidenceNone,
	}
}

func (n *noOpCollector) Enabled() bool { return false }

func (n *noOpCollector) Stats() RECStats { return RECStats{} }

// =============================================================================
// Live Collector
// =============================================================================
//
// Phase 1: gopacket on plaintext HTTP behind reverse proxy.
//
// KNOWN BLIND SPOT (code review's catch):
//   Phase 1 captures traffic between the reverse proxy and backend containers.
//   It CANNOT see responses generated directly by nginx/caddy/traefik:
//     - 403 Forbidden (block pages)
//     - 404 Not Found (static file misses)
//     - 301/302 Redirects
//     - Static file responses
//     - Edge-generated error pages
//   These never traverse the backend network. Phase 1 returns
//   EvidenceNotAvailableNoMatch for these — it cannot distinguish them
//   from genuinely missing evidence. Phase 2+ could detect edge-generated
//   responses by checking nginx upstream_response_time == "-".

type liveCollector struct {
	config  CollectorConfig
	buffer  *RingBuffer
	sniffer *sniffer      // stored for stats access
	running atomic.Bool   // atomic — Start() and Lookup() can race (code review's fix)
}

func (lc *liveCollector) Start(ctx context.Context) error {
	// --- Swarm detection + VXLAN port resolution ---
	vxlanPort := lc.config.VXLANPort
	if vxlanPort == 0 {
		swarm := detectSwarm(lc.config.DockerSocket)
		if swarm.Active {
			vxlanPort = swarm.DataPathPort
			log.Printf("[rec] Docker Swarm detected — VXLAN decapsulation active on UDP port %d", vxlanPort)
		} else {
			vxlanPort = DefaultVXLANPort
			log.Printf("[rec] Docker Swarm not detected — VXLAN decapsulation still active (always-on, no-op when absent)")
		}
	} else {
		log.Printf("[rec] VXLAN port explicitly configured: %d", vxlanPort)
	}

	iface := lc.config.Interface

	s := newSniffer(lc.buffer, iface, lc.config.Ports, lc.config.Buffer.MaxBodyBytes, vxlanPort)
	lc.sniffer = s

	// --- Decide capture mode: namespace or host ---
	var fd int
	var err error
	captureMode := "host"

	if lc.config.NSContainer != "" {
		// Namespace capture mode: find container PID, open socket in its namespace.
		// This is required for single-node Swarm where overlay traffic stays
		// inside Docker's network namespaces and never touches the host.
		info, findErr := findContainerPID(lc.config.DockerSocket, lc.config.NSContainer)
		if findErr != nil {
			log.Printf("[rec] Namespace capture requested for %q but container not found: %v — falling back to host capture",
				lc.config.NSContainer, findErr)
			// Fall back to host capture
			fd, err = s.openSocket()
		} else {
			log.Printf("[rec] Found container %s (PID %d) — opening socket in its network namespace",
				info.Name, info.PID)
			fd, err = openSocketInNamespace(info.PID)
			if err != nil {
				log.Printf("[rec] Namespace socket failed: %v — falling back to host capture", err)
				fd, err = s.openSocket()
			} else {
				captureMode = fmt.Sprintf("namespace:%s(pid=%d)", info.Name, info.PID)
			}
		}
	} else {
		// Host capture mode (default)
		fd, err = s.openSocket()
	}

	if err != nil {
		return fmt.Errorf("REC capture failed to start: %w", err)
	}

	// Socket is open and verified — NOW we can mark as running
	lc.running.Store(true)

	// Launch read loop goroutine (socket already open)
	go func() {
		s.readLoop(ctx, fd)
		lc.running.Store(false)
	}()

	// Launch cleanup goroutine for stale pending requests
	go s.cleanupLoop(ctx)

	ifaceDesc := iface
	if ifaceDesc == "" {
		ifaceDesc = "(all interfaces)"
	}
	log.Printf("[rec] Response Evidence Capture started — capture=%s interface=%s ports=%v vxlanPort=%d "+
		"buffer=[maxEntries=%d maxBytes=%d maxAge=%s maxBody=%d]",
		captureMode,
		ifaceDesc,
		lc.config.Ports,
		vxlanPort,
		lc.config.Buffer.MaxEntries,
		lc.config.Buffer.MaxTotalBytes,
		lc.config.Buffer.MaxAge,
		lc.config.Buffer.MaxBodyBytes,
	)
	return nil
}

func (lc *liveCollector) Lookup(req LookupRequest) *Evidence {
	if !lc.running.Load() {
		return &Evidence{
			Status:                EvidenceNotAvailableCollectorDisabled,
			CorrelationConfidence: ConfidenceNone,
		}
	}

	if req.Window == 0 {
		req.Window = DefaultCorrelationWindow
	}

	// Ring buffer handles all hard filtering:
	// Method + Path + StatusCode + Host + SourceContainer + time window.
	candidates := lc.buffer.Lookup(req)

	if len(candidates) == 0 {
		return &Evidence{
			Status:                EvidenceNotAvailableNoMatch,
			CorrelationConfidence: ConfidenceNone,
			CandidateCount:        0,
		}
	}

	// Pick the best candidate: closest in time, with UserAgent as tie-breaker
	best := candidates[0]
	minDelta := absDuration(best.Timestamp.Sub(req.Timestamp))
	for _, c := range candidates[1:] {
		delta := absDuration(c.Timestamp.Sub(req.Timestamp))

		// Prefer closer timestamp
		if delta < minDelta {
			best = c
			minDelta = delta
		} else if delta == minDelta && req.UserAgent != "" {
			// Tie-breaker: prefer matching UserAgent (code review's improvement)
			if c.UserAgent == req.UserAgent && best.UserAgent != req.UserAgent {
				best = c
			}
		}
	}

	// Determine correlation confidence
	corrConf := ConfidenceHigh
	if len(candidates) > 1 {
		corrConf = ConfidenceLow
	}

	// Build transport evidence (Layer 1 — always included)
	transport := &TransportEvidence{
		StatusCode:      best.StatusCode,
		ContentType:     best.ContentType,
		ContentLength:   best.ContentLength,
		BodyPreviewHash: best.BodyPreviewHash,
		CaptureMode:     "single_segment_preview",
		CapturedAt:      best.Timestamp,
		ResponseLatency: absDuration(best.Timestamp.Sub(req.Timestamp)),
	}

	// Build disclosure analysis (Layer 2)
	disclosure := classifyAndRedact(best.BodyPreview, best.ContentType)

	// === DUAL-GATE RULE: Evaluate once at construction, populate exported field ===
	// Body preview is ONLY exposed when BOTH gates pass:
	//   Gate 1: CorrelationConfidence == High (correct transaction matched)
	//   Gate 2: RedactionConfidence  == High (secrets properly stripped)
	// This is enforced HERE, not via a getter. The field is exported for JSON
	// serialization. If either gate fails, SafeBodyPreview stays empty. Period.
	safePreview := ""
	if corrConf == ConfidenceHigh &&
		disclosure != nil &&
		disclosure.RedactionConfidence == ConfidenceHigh {
		safePreview = disclosure.redactedPreview
	}

	status := EvidenceAvailableHighConfidence
	if corrConf == ConfidenceLow {
		status = EvidenceAvailableLowConfidence
	}

	return &Evidence{
		Status:                status,
		CorrelationConfidence: corrConf,
		Transport:             transport,
		Disclosure:            disclosure,
		SafeBodyPreview:       safePreview,
		CandidateCount:        len(candidates),
	}
}

func (lc *liveCollector) Enabled() bool {
	return lc.running.Load()
}

func (lc *liveCollector) Stats() RECStats {
	stats := RECStats{}
	if lc.sniffer != nil {
		stats.PacketsSeen = lc.sniffer.packetCount
		stats.HTTPRequests = lc.sniffer.httpReqCount
		stats.HTTPResponses = lc.sniffer.httpRespCount
		stats.PairMisses = lc.sniffer.pairMissCount
		stats.VXLANUnwrapped = lc.sniffer.vxlanCount
		stats.VXLANHTTPReq = lc.sniffer.vxlanHTTPReq
		stats.VXLANHTTPResp = lc.sniffer.vxlanHTTPResp
	}
	if lc.buffer != nil {
		stats.BufferEntries, stats.BufferBytes = lc.buffer.Stats()
	}
	return stats
}

// =============================================================================
// Format Classifier + Structural Redaction
// =============================================================================
//
// IMPORTANT: classifyAndRedact operates on the TRUNCATED body preview
// (max 2KB), not the full response body. Format detection and redaction
// confidence are based on partial content. This is acceptable for Phase 1
// but should be documented in any API that exposes these fields.
//
// FAIL-CLOSED RULE ('s law):
//   If format is unknown, no body preview at all. Only transport metadata.
//   Content-Length: 45032 on a 404 path IS the evidence.

func classifyAndRedact(bodyPreview []byte, contentType string) *DisclosureAnalysis {
	if len(bodyPreview) == 0 {
		return &DisclosureAnalysis{
			Format:              FormatUnknown,
			RedactionConfidence: ConfidenceNone,
			DisclosureSummary:   "NO RESPONSE BODY CAPTURED",
		}
	}

	format, confidence := detectFormat(bodyPreview, contentType)

	analysis := &DisclosureAnalysis{
		Format:              format,
		RedactionConfidence: confidence,
	}

	switch format {
	case FormatDotenv:
		analysis.redactedPreview = redactDotenv(bodyPreview)
		analysis.DisclosureSummary = "DOTENV/CONFIG STRUCTURE DETECTED"
	case FormatPasswd:
		analysis.redactedPreview = redactPasswd(bodyPreview)
		analysis.DisclosureSummary = "PASSWD FILE STRUCTURE DETECTED"
	case FormatJSON:
		analysis.redactedPreview = redactJSON(bodyPreview)
		analysis.DisclosureSummary = "JSON STRUCTURE DETECTED"
	case FormatHTML:
		analysis.redactedPreview = redactHTML(bodyPreview)
		analysis.DisclosureSummary = "HTML CONTENT DETECTED"
	case FormatBinary:
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.DisclosureSummary = "BINARY CONTENT DETECTED — METADATA ONLY"
	default:
		// FAIL-CLOSED: unknown format = no body preview.
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.DisclosureSummary = "UNKNOWN FORMAT — METADATA ONLY"
	}

	return analysis
}

// =============================================================================
// Format Detection + Redaction — see redaction.go
// =============================================================================
// detectFormat(), redactHTML(), redactJSON(), redactDotenv(), redactPasswd()
// are implemented in redaction.go. They were stubs here until v0.12.2.

// =============================================================================
// Utilities
// =============================================================================

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// FormatEvidence produces a human-readable multi-line evidence block
// suitable for inclusion in alert emails.
func FormatEvidence(e *Evidence) string {
	if e == nil || !e.HasEvidence() {
		if e != nil {
			return fmt.Sprintf("RESPONSE EVIDENCE: %s\n", e.Status)
		}
		return "RESPONSE EVIDENCE: not_available_collector_disabled\n"
	}

	out := "RESPONSE EVIDENCE:\n"
	out += fmt.Sprintf("  Status: %s\n", e.Status)
	out += fmt.Sprintf("  Correlation: %s (%d candidates)\n", e.CorrelationConfidence, e.CandidateCount)
	if e.Transport != nil {
		out += fmt.Sprintf("  Response Code: %d\n", e.Transport.StatusCode)
		out += fmt.Sprintf("  Content-Type: %s\n", e.Transport.ContentType)
		out += fmt.Sprintf("  Content-Length: %d\n", e.Transport.ContentLength)
		out += fmt.Sprintf("  Body Preview Hash: sha256:%s\n", e.Transport.BodyPreviewHash)
		out += fmt.Sprintf("  Capture Mode: %s\n", e.Transport.CaptureMode)
		out += fmt.Sprintf("  Captured: %s\n", e.Transport.CapturedAt.Format(time.RFC3339))
		if e.Transport.ResponseLatency > 0 {
			out += fmt.Sprintf("  Response Latency: %s\n", e.Transport.ResponseLatency)
		}
	}
	if e.Disclosure != nil {
		out += fmt.Sprintf("  Disclosure: %s\n", e.Disclosure.DisclosureSummary)
	}
	if e.SafeBodyPreview != "" {
		out += fmt.Sprintf("  Body (redacted):\n    %s\n", e.SafeBodyPreview)
	} else if e.HasEvidence() {
		// Explain WHY the preview is missing (code review #9)
		if e.CorrelationConfidence != ConfidenceHigh {
			out += "  Body Preview: withheld (low correlation confidence)\n"
		} else if e.Disclosure != nil && e.Disclosure.RedactionConfidence != ConfidenceHigh {
			out += fmt.Sprintf("  Body Preview: withheld (%s format — redaction not confident)\n", e.Disclosure.Format)
		} else {
			out += "  Body Preview: not available\n"
		}
	}
	return out
}