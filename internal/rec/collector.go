// internal/rec/collector.go
package rec

import (
	"context"
	"fmt"
	"log"
	"sync"
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

	// --- Fix 1: VIP Lane for Malicious Evidence ---

	// PinVIP registers interest in evidence for a malicious event.
	// When a captured response matches the criteria, it's stored in a
	// protected VIP map that CANNOT be evicted by traffic floods.
	// The push callback (if set) fires immediately on match.
	PinVIP(eventID string, correlationKey string, req LookupRequest)

	// SetVIPCallback registers the push notification function.
	// Called from main.go with a function that has access to the coordinator.
	// Fires with the correlation key when VIP evidence is matched.
	SetVIPCallback(fn func(correlationKey string))
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

	// Verbose enables per-packet REQ/RESP logging. When false (default),
	// only pair misses, parse failures, and periodic stats are logged.
	// Set REC_VERBOSE=true for debugging packet capture issues.
	Verbose bool
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
		config:      cfg,
		buffer:      NewRingBuffer(cfg.Buffer),
		vipPins:     make(map[string]*vipPin),
		vipEvidence: make(map[string]CapturedResponse),
	}
}

// =============================================================================
// NoOp Collector — Returned when REC can't run
// =============================================================================

type noOpCollector struct {
	reason EvidenceStatus
}

func (n *noOpCollector) Start(ctx context.Context) error                            { return nil }
func (n *noOpCollector) Enabled() bool                                              { return false }
func (n *noOpCollector) Stats() RECStats                                            { return RECStats{} }
func (n *noOpCollector) PinVIP(eventID string, correlationKey string, req LookupRequest) {}
func (n *noOpCollector) SetVIPCallback(fn func(correlationKey string))               {}

func (n *noOpCollector) Lookup(req LookupRequest) *Evidence {
	return &Evidence{
		Status:                n.reason,
		CorrelationConfidence: ConfidenceNone,
	}
}

// =============================================================================
// Fix 1: VIP Lane Data Structures
// =============================================================================
//
// When the classifier flags a request as malicious, we pin its tracking
// metadata in a separate high-priority map that CANNOT be evicted by
// traffic floods. The ring buffer has 1000 entries and 30s TTL — an
// attacker flooding 50K garbage requests evicts malicious evidence before
// the coordinator can look it up.
//
// The VIP lane solves both problems:
//   1. Anti-eviction: VIP evidence has its own map (120s TTL, max 200 entries)
//   2. Push notification: when a response matches VIP criteria, a callback
//      fires immediately so the coordinator can re-check without waiting
//      for the next poll cycle.

const (
	vipMaxEntries = 200           // max pending VIP pins
	vipTTL        = 120 * time.Second // 120s > coordinator's 5s window — catches late evidence
)

// vipPin holds the criteria for a pending VIP match.
type vipPin struct {
	eventID        string
	correlationKey string // coordinator key for push callback
	criteria       LookupRequest
	createdAt      time.Time
}

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

	// Fix 1: VIP lane for malicious evidence
	vipMu        sync.Mutex
	vipPins      map[string]*vipPin         // eventID → pending match criteria
	vipEvidence  map[string]CapturedResponse // eventID → matched response (protected)
	onVIPMatch   func(correlationKey string)  // push callback → coordinator
	vipMatches   int64                        // telemetry counter
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

	s := newSniffer(lc.buffer, iface, lc.config.Ports, lc.config.Buffer.MaxBodyBytes, vxlanPort, lc.config.Verbose)

	// Fix 1: Wire sniffer capture callback for VIP lane.
	// Every successfully parsed response fires this callback.
	// The callback checks VIP pins and resolves matches immediately.
	s.onCapture = lc.handleCapturedResponse

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

	// Fix 1: Launch VIP cleanup goroutine (expire stale pins)
	go lc.vipCleanupLoop(ctx)

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

// Lookup performs L7 heuristic correlation.
// Fix 1: Checks VIP-protected evidence first, then falls back to ring buffer.
func (lc *liveCollector) Lookup(req LookupRequest) *Evidence {
	if !lc.running.Load() {
		return &Evidence{
			Status:                EvidenceNotAvailableCollectorDisabled,
			CorrelationConfidence: ConfidenceNone,
		}
	}

	// --- Fix 1: Check VIP evidence first ---
	// VIP evidence is protected from eviction. If there's a match,
	// use it — the coordinator already knows this is high-priority.
	candidates := lc.lookupVIPEvidence(req)

	// --- Standard ring buffer lookup ---
	bufferCandidates := lc.buffer.Lookup(req)
	candidates = append(candidates, bufferCandidates...)

	if len(candidates) == 0 {
		return &Evidence{
			Status:                EvidenceNotAvailableNoMatch,
			CorrelationConfidence: ConfidenceNone,
		}
	}

	// --- Score and select best candidate (existing logic) ---
	best := candidates[0]
	bestScore := candidateScore(best, req)
	for _, c := range candidates[1:] {
		score := candidateScore(c, req)
		if score < bestScore {
			best = c
			bestScore = score
		} else if score == bestScore && req.UserAgent != "" {
			if c.UserAgent == req.UserAgent && best.UserAgent != req.UserAgent {
				best = c
			}
		}
	}

	// === CLONE CHECK (Option A, design consensus) ===
	corrConf := ConfidenceHigh
	if len(candidates) > 1 {
		allClones := true
		refHash := candidates[0].BodyPreviewHash
		refLen := candidates[0].ContentLength
		refType := candidates[0].ContentType
		for _, c := range candidates[1:] {
			if c.BodyPreviewHash != refHash || c.ContentLength != refLen || c.ContentType != refType {
				allClones = false
				break
			}
		}

		if allClones && refHash != "" {
			corrConf = ConfidenceHigh
			log.Printf("[rec] Clone check: %d identical candidates (hash=%.16s len=%d type=%s) → HIGH confidence",
				len(candidates), refHash, refLen, refType)
		} else {
			corrConf = ConfidenceLow
		}
	}

	// Detect orphan match
	isOrphan := best.Method == ""

	// Build transport evidence (Layer 1)
	captureMode := "single_segment_preview"
	if isOrphan {
		captureMode = "single_segment_preview_orphan"
	}
	transport := &TransportEvidence{
		StatusCode:      best.StatusCode,
		ContentType:     best.ContentType,
		ContentLength:   best.ContentLength,
		BodyPreviewHash: best.BodyPreviewHash,
		CaptureMode:     captureMode,
		CapturedAt:      best.Timestamp,
		ResponseLatency: absDuration(best.Timestamp.Sub(req.Timestamp)),
	}

	// Build disclosure analysis (Layer 2)
	disclosure := classifyAndRedact(best.BodyPreview, best.ContentType)

	// === DUAL-GATE RULE ===
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
		stats.ReqPrefixHits = lc.sniffer.reqPrefixHits
		stats.ReqParseFails = lc.sniffer.reqParseFails
		stats.RespPrefixHits = lc.sniffer.respPrefixHits
		stats.RespParseFails = lc.sniffer.respParseFails
		stats.BodyEmptyInSegment = lc.sniffer.bodyEmptyInSegment
		stats.BodyExpectedButMissing = lc.sniffer.bodyExpectedButMissing
		stats.ChunkedRespCount = lc.sniffer.chunkedRespCount
		stats.CompressedRespCount = lc.sniffer.compressedRespCount
	}
	if lc.buffer != nil {
		stats.BufferEntries, stats.BufferBytes = lc.buffer.Stats()
	}
	stats.VIPMatches = lc.vipMatches
	return stats
}

// =============================================================================
// Fix 1: VIP Lane Methods
// =============================================================================

// PinVIP registers interest in evidence for a malicious event.
// Called from resultrouter.go when a malicious HTTP verdict is routed to coordinator.
func (lc *liveCollector) PinVIP(eventID string, correlationKey string, req LookupRequest) {
	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()

	// Enforce max entries — evict oldest if full
	if len(lc.vipPins) >= vipMaxEntries {
		var oldestID string
		var oldestTime time.Time
		for id, pin := range lc.vipPins {
			if oldestID == "" || pin.createdAt.Before(oldestTime) {
				oldestID = id
				oldestTime = pin.createdAt
			}
		}
		if oldestID != "" {
			delete(lc.vipPins, oldestID)
		}
	}

	lc.vipPins[eventID] = &vipPin{
		eventID:        eventID,
		correlationKey: correlationKey,
		criteria:       req,
		createdAt:      time.Now(),
	}

	log.Printf("[rec:vip] Pinned evidence for %s: method=%s path=%s host=%s status=%d",
		eventID, req.Method, req.Path, req.Host, req.StatusCode)
}

// SetVIPCallback registers the push notification callback.
// Called from main.go after coordinator is created.
func (lc *liveCollector) SetVIPCallback(fn func(correlationKey string)) {
	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()
	lc.onVIPMatch = fn
}

// handleCapturedResponse is called by the sniffer on every successfully
// parsed HTTP response. Checks VIP pins for a match.
func (lc *liveCollector) handleCapturedResponse(resp CapturedResponse) {
	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()

	for eventID, pin := range lc.vipPins {
		if matchesVIP(resp, pin.criteria) {
			// Store in protected VIP evidence map
			lc.vipEvidence[eventID] = resp
			correlationKey := pin.correlationKey
			delete(lc.vipPins, eventID)
			lc.vipMatches++

			log.Printf("[rec:vip] Evidence matched for %s: status=%d method=%s path=%s",
				eventID, resp.StatusCode, resp.Method, resp.Path)

			// Fire push callback (non-blocking)
			if lc.onVIPMatch != nil {
				go lc.onVIPMatch(correlationKey)
			}
			return
		}
	}
}

// matchesVIP checks if a captured response matches VIP pin criteria.
// Uses the same hard filters as ring buffer Lookup:
//   - Method + Path (if response has request info — orphans skip this)
//   - StatusCode (hard filter)
//   - Host (hard filter if both sides have it)
//   - Time window
func matchesVIP(resp CapturedResponse, req LookupRequest) bool {
	window := req.Window
	if window == 0 {
		window = 5 * time.Second // wider window for VIP — evidence may arrive late
	}

	// Time window
	windowStart := req.Timestamp.Add(-window)
	windowEnd := req.Timestamp.Add(window)
	if resp.Timestamp.Before(windowStart) || resp.Timestamp.After(windowEnd) {
		return false
	}

	// Method + Path (if response has request info)
	if resp.Method != "" {
		if resp.Method != req.Method || resp.Path != req.Path {
			return false
		}
	}

	// Status code hard filter
	if req.StatusCode > 0 && resp.StatusCode != req.StatusCode {
		return false
	}

	// Host hard filter
	if req.Host != "" && resp.Host != "" && resp.Host != req.Host {
		return false
	}

	return true
}

// lookupVIPEvidence returns VIP-protected candidates matching the request.
func (lc *liveCollector) lookupVIPEvidence(req LookupRequest) []CapturedResponse {
	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()

	var candidates []CapturedResponse
	for _, resp := range lc.vipEvidence {
		if matchesVIP(resp, req) {
			candidates = append(candidates, resp)
		}
	}
	return candidates
}

// vipCleanupLoop removes expired VIP pins and evidence periodically.
func (lc *liveCollector) vipCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lc.vipMu.Lock()
			cutoff := time.Now().Add(-vipTTL)
			for id, pin := range lc.vipPins {
				if pin.createdAt.Before(cutoff) {
					delete(lc.vipPins, id)
				}
			}
			for id, resp := range lc.vipEvidence {
				if resp.Timestamp.Before(cutoff) {
					delete(lc.vipEvidence, id)
				}
			}
			lc.vipMu.Unlock()
		}
	}
}

// =============================================================================
// Utilities
// =============================================================================

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// candidateScore computes a ranking score for an orphan candidate.
// Lower score = better match. Combines byte-count proximity and timestamp proximity.
func candidateScore(c CapturedResponse, req LookupRequest) time.Duration {
	timeDelta := absDuration(c.Timestamp.Sub(req.Timestamp))

	if req.ExpectedBytes > 0 && c.ContentLength > 0 {
		bytesDiff := req.ExpectedBytes - c.ContentLength
		if bytesDiff < 0 {
			bytesDiff = -bytesDiff
		}

		// Tolerance: 20% of expected, minimum 2KB
		tolerance := req.ExpectedBytes / 5
		if tolerance < 2048 {
			tolerance = 2048
		}

		if bytesDiff > tolerance {
			timeDelta += time.Hour
		}
	}

	return timeDelta
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