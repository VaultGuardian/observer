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

	// PrePin preserves REC evidence before LLM classification delay.
	// Called when an event enters the LLM path (pattern miss). Checks
	// the existing ring buffer for a matching response and promotes it
	// to VIP (protected from eviction). If no match yet, registers a
	// VIP pin for future responses.
	PrePin(eventID string, req LookupRequest)

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

	// LearnedPortCap bounds runtime port learning by the sniffer.
	//
	// When a TCP segment arrives on a port not in Ports, the sniffer
	// peeks at the payload — if it looks like an HTTP/1.x request line
	// or response status line, the port is learned and used for
	// subsequent traffic. This catches backends on non-default ports
	// (e.g. CapRover's captain-captain on 3000) without operator config.
	//
	// Bounded to prevent unbounded growth from pathological traffic.
	// Default 64 is comfortably more than any realistic deployment
	// needs. Set to 0 to disable runtime learning entirely.
	LearnedPortCap int

	// Reassembly configures the response-only TCP reassembly path (v0.42.7+).
	Reassembly ReassemblyConfig

	// Flow configures the bidirectional pairing queue bounds (v0.42.7+).
	Flow FlowConfig
}

// DefaultCollectorConfig returns the standard defaults.
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		Enabled:        false, // opt-in, not surprise packet capture
		Interface:      "",
		Ports:          []int{80, 8080},
		Buffer:         DefaultBufferConfig(),
		VXLANPort:      0, // 0 = auto-detect from Docker API
		DockerSocket:   "/var/run/docker.sock",
		NSContainer:    "", // empty = host namespace
		LearnedPortCap: 64, // bounded runtime port learning
		Reassembly:     DefaultReassemblyConfig(),
		Flow:           DefaultFlowConfig(),
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
		captures:    make(map[string]*namespaceCapture),
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

func (n *noOpCollector) Start(ctx context.Context) error                                 { return nil }
func (n *noOpCollector) Enabled() bool                                                   { return false }
func (n *noOpCollector) Stats() RECStats                                                 { return RECStats{} }
func (n *noOpCollector) PinVIP(eventID string, correlationKey string, req LookupRequest) {}
func (n *noOpCollector) PrePin(eventID string, req LookupRequest)                        {}
func (n *noOpCollector) SetVIPCallback(fn func(correlationKey string))                   {}

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
// traffic floods. The standard ring buffer is still a bounded best-effort
// evidence cache; under sufficiently large bursts, older evidence can still
// be evicted before the coordinator looks it up.
//
// The VIP lane protects high-value malicious-request correlation separately:
//   1. Anti-eviction: VIP evidence has its own map (120s TTL, max 200 entries)
//   2. Push notification: when a response matches VIP criteria, a callback
//      fires immediately so the coordinator can re-check without waiting
//      for the next poll cycle.

const (
	vipMaxEntries = 200               // max pending VIP pins
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
// KNOWN BLIND SPOT:
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
	config CollectorConfig
	buffer *RingBuffer

	// captures holds one namespaceCapture per capture source, keyed by a stable
	// id (container name, or "host"). Today exactly one entry resolved from
	// cfg.NSContainer; later sessions add more via auto-discovery. All instances
	// feed the single shared buffer + VIP store below.
	captures map[string]*namespaceCapture
	capMu    sync.Mutex

	// running is RETAINED only as a manual/white-box gate: an existing test sets
	// it directly, and Enabled() ORs it in. Production never sets it — namespace
	// liveness is tracked per-instance (namespaceCapture.running), and Enabled()
	// reports "at least one namespace active". This deliberately replaces the old
	// global "last read loop alive" semantics that were the root of the
	// single-namespace bug (one dead loop must not disable the collector).
	running atomic.Bool

	// Fix 1: VIP lane for malicious evidence
	vipMu       sync.Mutex
	vipPins     map[string]*vipPin          // eventID → pending match criteria
	vipEvidence map[string]CapturedResponse // eventID → matched response (protected)
	onVIPMatch  func(correlationKey string) // push callback → coordinator
	vipMatches  int64                       // telemetry counter
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

	// --- Build the capture set ---
	// Today this resolves to exactly one capture source — the configured
	// namespace container (REC_NS_CONTAINER) or the host. Later sessions expand
	// this to N instances via auto-discovery; the collector machinery below is
	// already N-safe (shared buffer/VIP, per-instance liveness, partial-failure
	// isolation). Key by container name, or "host".
	key := "host"
	if lc.config.NSContainer != "" {
		key = lc.config.NSContainer
	}

	s := newSniffer(lc.buffer, iface, lc.config.Ports, lc.config.LearnedPortCap, lc.config.Buffer.MaxBodyBytes, vxlanPort, lc.config.Verbose, lc.config.Reassembly, lc.config.Flow)

	// Fix 1: Wire this instance's sniffer into the SHARED VIP handler. Every
	// successfully parsed response fires this callback regardless of which
	// namespace captured it — the VIP pins/evidence maps are owned by the
	// collector, not the sniffer, so all instances resolve against one store.
	s.onCapture = lc.handleCapturedResponse

	nc := &namespaceCapture{name: key, sniffer: s}
	lc.capMu.Lock()
	lc.captures[key] = nc
	lc.capMu.Unlock()

	// --- Decide capture mode: namespace or host ---
	// The opener replicates today's namespace→host fallback exactly, including
	// log lines, and records the resolved mode for the startup line below. It
	// runs synchronously inside startCapture, preserving the pre-refactor log
	// ordering (sniffer reassembly/flow lines, then namespace logs, then the
	// aggregate "started" line).
	captureMode := "host"
	open := func() (int, error) {
		if lc.config.NSContainer != "" {
			// Namespace capture mode: find container PID, open socket in its
			// namespace. Required for single-node Swarm where overlay traffic
			// stays inside Docker's network namespaces and never touches the host.
			info, findErr := findContainerPID(lc.config.DockerSocket, lc.config.NSContainer)
			if findErr != nil {
				log.Printf("[rec] Namespace capture requested for %q but container not found: %v — falling back to host capture",
					lc.config.NSContainer, findErr)
				return s.openSocket() // fall back to host capture
			}
			log.Printf("[rec] Found container %s (PID %d) — opening socket in its network namespace",
				info.Name, info.PID)
			nc.containerID = info.ID
			nc.pid = info.PID
			fd, nsErr := openSocketInNamespace(info.PID)
			if nsErr != nil {
				log.Printf("[rec] Namespace socket failed: %v — falling back to host capture", nsErr)
				return s.openSocket()
			}
			captureMode = fmt.Sprintf("namespace:%s(pid=%d)", info.Name, info.PID)
			return fd, nil
		}
		// Host capture mode (default)
		return s.openSocket()
	}

	if err := lc.startCapture(ctx, nc, open); err != nil {
		// At N=1, a failed sole instance means zero captures started — preserve
		// today's behavior exactly: report the error so the pipeline runs
		// without REC. (At N>1, later sessions return nil when at least one
		// instance starts; the failed ones keep their lastError and the healthy
		// ones keep capturing — see startCapture.)
		return fmt.Errorf("REC capture failed to start: %w", err)
	}

	// Fix 1: Launch VIP cleanup goroutine (expire stale pins). Collector-level,
	// bound to the parent ctx — NOT stopped by Close() (see Close()).
	go lc.vipCleanupLoop(ctx)

	ifaceDesc := iface
	if ifaceDesc == "" {
		ifaceDesc = "(all interfaces)"
	}
	log.Printf("[rec] Response Evidence Capture started — capture=%s interface=%s ports=%v learnedPortCap=%d vxlanPort=%d "+
		"buffer=[maxEntries=%d maxBytes=%d maxAge=%s maxBody=%d]",
		captureMode,
		ifaceDesc,
		lc.config.Ports,
		lc.config.LearnedPortCap,
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
	if !lc.Enabled() {
		return &Evidence{
			Status:                EvidenceNotAvailableCollectorDisabled,
			CorrelationConfidence: ConfidenceNone,
		}
	}

	// Decode nginx access-log escaping so the log-derived path matches REC's
	// literal wire capture (both the VIP and ring-buffer compares below).
	req = normalizeLookupRequest(req)

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

// Enabled reports whether REC is actively capturing — defined as "at least one
// namespace is active", not "the last read loop is alive". This is the crux of
// the multi-namespace refactor: one dead/failed instance must not disable the
// collector while siblings keep capturing.
func (lc *liveCollector) Enabled() bool {
	// Manual/white-box override: an existing test sets lc.running directly.
	// Production never sets it; liveness comes from the per-instance flags below.
	if lc.running.Load() {
		return true
	}
	// NOTE: this takes capMu. Lookup is hot (fires ~14x/event during bursts),
	// but at realistic N this is one mutex + a tiny map walk — negligible. If
	// lock contention ever shows up under load, replace with a lockless
	// activeCount atomic bumped by startCapture / Close.
	lc.capMu.Lock()
	defer lc.capMu.Unlock()
	for _, c := range lc.captures {
		if c.running.Load() {
			return true
		}
	}
	return false
}

func (lc *liveCollector) Stats() RECStats {
	stats := RECStats{}

	// Aggregate across all capture instances. At N=1 (today's config) the sums
	// equal the single-sniffer values, so this is byte-for-byte identical to the
	// pre-refactor stats. The sniffer counters and flow state live per-instance;
	// the buffer and VIP counters below are collector-wide (shared).
	lc.capMu.Lock()
	caps := make([]*namespaceCapture, 0, len(lc.captures))
	for _, c := range lc.captures {
		caps = append(caps, c)
	}
	lc.capMu.Unlock()

	for _, c := range caps {
		s := c.sniffer
		if s == nil {
			continue
		}
		stats.PacketsSeen += atomic.LoadInt64(&s.packetCount)
		stats.VXLANUnwrapped += atomic.LoadInt64(&s.vxlanCount)

		// Inline parser
		stats.InlineRequests += atomic.LoadInt64(&s.inlineRequests)
		stats.InlineDuplicateDrops += atomic.LoadInt64(&s.inlineDuplicateDrops)
		stats.InlineBodySkips += atomic.LoadInt64(&s.inlineBodySkips)

		// Response reassembly
		stats.ReassemblyStreamsActive += atomic.LoadInt64(&s.reassemblyStreamsActive)
		stats.ReassemblyStreamsTotal += atomic.LoadInt64(&s.reassemblyStreamsTotal)
		stats.ReassemblyStreamsTimedOut += atomic.LoadInt64(&s.reassemblyStreamsTimedOut)
		stats.ReassemblyStreamDrops += atomic.LoadInt64(&s.reassemblyStreamDrops)
		stats.ReassemblyResponses += atomic.LoadInt64(&s.reassemblyResponses)
		stats.ReassemblyParseErrors += atomic.LoadInt64(&s.reassemblyParseErrors)

		// Pairing
		stats.PairImmediate += atomic.LoadInt64(&s.pairImmediate)
		stats.OrphanResponses += atomic.LoadInt64(&s.orphanResponses)
		stats.RequestsExpired += atomic.LoadInt64(&s.requestsExpired)

		// Flow state
		s.flowsMu.Lock()
		stats.FlowStates += int64(len(s.flows))
		s.flowsMu.Unlock()
		stats.FlowEvictions += atomic.LoadInt64(&s.flowEvictions)
		stats.FlowEvictionsLive += atomic.LoadInt64(&s.flowEvictionsLive)

		stats.FeedHTTP += atomic.LoadInt64(&s.feedHTTP)

		// Port registry telemetry (v0.47.1). Summed across instances; at N=1
		// this equals the single registry. (A per-namespace breakdown is a later
		// session — aggregate-only here.)
		if s.ports != nil {
			ps := s.ports.stats()
			stats.PortConfiguredCount += ps.ConfiguredCount
			stats.PortLearnedCount += ps.LearnedCount
			stats.PortLearnAttempts += ps.LearnedAttempts
			stats.PortLearnAdded += ps.LearnedAdded
			stats.PortLearnRefused += ps.LearnedRefused
			stats.PortLearnCap += ps.LearnCap
		}
	}

	// Dashboard backward compat
	stats.HTTPRequests = stats.InlineRequests
	stats.HTTPResponses = stats.ReassemblyResponses
	stats.PairMisses = stats.OrphanResponses

	if lc.buffer != nil {
		bs := lc.buffer.Stats()
		stats.BufferEntries = bs.Entries
		stats.BufferBytes = bs.TotalBytes
		stats.BufferEvictionsTotal = bs.EvictionsTotal
		stats.BufferEvictionsCapacity = bs.EvictionsCapacity
		stats.BufferEvictionsAge = bs.EvictionsAge
		stats.BufferEvictionsBytes = bs.EvictionsBytes
	}
	stats.VIPMatches = atomic.LoadInt64(&lc.vipMatches)
	return stats
}

// =============================================================================
// Fix 1: VIP Lane Methods
// =============================================================================

// PinVIP registers interest in evidence for a malicious event.
// Called from resultrouter.go when a malicious HTTP verdict is routed to coordinator.
func (lc *liveCollector) PinVIP(eventID string, correlationKey string, req LookupRequest) {
	// Decode nginx access-log escaping before the criteria are stored, so the
	// pinned path matches the sniffer's literal wire capture in matchesVIP.
	req = normalizeLookupRequest(req)

	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()

	// If PrePin already promoted evidence for this event, do not add a
	// redundant future pin. The coordinator will find the VIP evidence
	// during normal Lookup.
	if _, exists := lc.vipEvidence[eventID]; exists {
		log.Printf("[rec:vip] Evidence already VIP-promoted for %s; skipping future pin", eventID)
		return
	}

	// If PrePin already created a future pin, overwrite it below to add the
	// coordinator correlationKey. If this is a brand-new pin, enforce the
	// combined pins+evidence cap first.
	if _, alreadyPinned := lc.vipPins[eventID]; !alreadyPinned {
		lc.enforceVIPCapLocked()
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

// PrePin preserves REC evidence before LLM classification delay.
//
// Called when an event enters the LLM path (pattern store miss). At this
// point the HTTP response is almost certainly still in the 30-second ring
// buffer. PrePin promotes it to VIP (120s TTL, protected from eviction)
// so the coordinator can find it after the LLM call completes.
//
// Two paths:
//  1. Response already in buffer → promote to vipEvidence immediately
//  2. Response not yet captured  → register VIP pin for future match
//
// Lock ordering: vipMu → buffer.mu (RLock). Safe because the sniffer's
// onCapture callback releases buffer.mu before calling handleCapturedResponse
// which takes vipMu. No deadlock cycle.
func (lc *liveCollector) PrePin(eventID string, req LookupRequest) {
	if !lc.Enabled() {
		return
	}

	// Decode nginx access-log escaping before buffer lookup / pin storage, so
	// the path matches REC's literal wire capture.
	req = normalizeLookupRequest(req)

	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()

	// Don't double-pin the same event
	if _, exists := lc.vipEvidence[eventID]; exists {
		return
	}
	if _, exists := lc.vipPins[eventID]; exists {
		return
	}

	// Step 1: Check existing ring buffer for a matching response
	candidates := lc.buffer.Lookup(req)
	if len(candidates) > 0 {
		// Promote best candidate to VIP (protected from eviction)
		best := candidates[0]
		bestScore := candidateScore(best, req)
		for _, c := range candidates[1:] {
			if score := candidateScore(c, req); score < bestScore {
				best = c
				bestScore = score
			}
		}

		lc.enforceVIPCapLocked()
		lc.vipEvidence[eventID] = best
		atomic.AddInt64(&lc.vipMatches, 1)

		log.Printf("[rec:prepin] Evidence promoted from buffer for %s: status=%d method=%s path=%s candidates=%d",
			eventID, best.StatusCode, best.Method, best.Path, len(candidates))
		return
	}

	// Step 2: Response not in buffer yet — register pin for future match
	// No correlationKey at this stage (coordinator key hasn't been built yet).
	// The coordinator will find the evidence via lookupVIPEvidence during
	// its normal Lookup call.
	lc.enforceVIPCapLocked()
	lc.vipPins[eventID] = &vipPin{
		eventID:   eventID,
		criteria:  req,
		createdAt: time.Now(),
	}

	log.Printf("[rec:prepin] Watching for future evidence for %s: method=%s path=%s host=%s status=%d",
		eventID, req.Method, req.Path, req.Host, req.StatusCode)
}

// enforceVIPCapLocked evicts the oldest VIP entry (pin or evidence) when
// the combined count reaches the cap. Must be called with vipMu held.
//
// With PrePin, VIP is no longer "malicious-only" — all LLM-path events
// can get temporary VIP slots. The cap prevents unbounded memory growth
// from benign events that get pre-pinned but classified as suppress/allow.
func (lc *liveCollector) enforceVIPCapLocked() {
	for len(lc.vipPins)+len(lc.vipEvidence) >= vipMaxEntries {
		var oldestID string
		var oldestTime time.Time
		var oldestKind string

		for id, pin := range lc.vipPins {
			if oldestID == "" || pin.createdAt.Before(oldestTime) {
				oldestID = id
				oldestTime = pin.createdAt
				oldestKind = "pin"
			}
		}

		for id, resp := range lc.vipEvidence {
			if oldestID == "" || resp.Timestamp.Before(oldestTime) {
				oldestID = id
				oldestTime = resp.Timestamp
				oldestKind = "evidence"
			}
		}

		if oldestID == "" {
			return
		}

		if oldestKind == "pin" {
			delete(lc.vipPins, oldestID)
		} else {
			delete(lc.vipEvidence, oldestID)
		}
	}
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
			atomic.AddInt64(&lc.vipMatches, 1)

			log.Printf("[rec:vip] Evidence matched for %s: status=%d method=%s path=%s",
				eventID, resp.StatusCode, resp.Method, resp.Path)

			// Fire push callback (non-blocking).
			// Guard: PrePin registers pins without a correlationKey (coordinator
			// key hasn't been built yet). Only fire the callback when the key
			// is known, otherwise we'd push empty strings to the coordinator.
			if correlationKey != "" && lc.onVIPMatch != nil {
				go lc.onVIPMatch(correlationKey)
			}
			return
		}
	}
}

// normalizeLookupRequest returns req with its Path decoded from nginx
// access-log escaping. Applied at every REC entry point (Lookup, PinVIP,
// PrePin) so the ring-buffer compare and the VIP compare both see a path
// that is byte-identical to the sniffer's literal wire capture. The caller's
// LookupRequest is unaffected (req is passed by value), so the displayed
// Finding.HTTPPath keeps its safe escaped form.
func normalizeLookupRequest(req LookupRequest) LookupRequest {
	req.Path = decodeNginxLogPath(req.Path)
	return req
}

// decodeNginxLogPath reverses nginx's default access-log escaping (\xHH) back
// to the literal bytes the server observed on the wire, so a log-derived path
// compares equal to REC's wire capture.
//
// nginx (escape=default) rewrites bytes it considers unsafe — control bytes
// (<0x20), high bytes (>0x7E), '"' (0x22) and '\' (0x5C) — as the 4-char
// sequence \xHH (a backslash, a literal 'x', then two hex digits). Everything
// else is written verbatim. This reverses exactly that transform:
//   - Fast path: returns s unchanged when it contains no `\x` (the common
//     case, and nginx ERROR-log paths, which are already literal/unescaped).
//   - Each well-formed \xHH (hex digits are case-insensitive) becomes one byte.
//   - A malformed sequence (\x not followed by two hex digits, or truncated at
//     end of string) is passed through verbatim.
//   - Decoding is a single forward pass, so a byte produced by decoding is
//     never re-scanned. A literal "\x5C" in a URL is logged as "\x5Cx5C"
//     (nginx escapes only its leading backslash) and round-trips back to
//     "\x5C" rather than collapsing to a single backslash.
func decodeNginxLogPath(s string) string {
	// Fast path: nothing to decode unless a `\x` marker is present.
	escapeStart := -1
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '\\' && s[i+1] == 'x' {
			escapeStart = i
			break
		}
	}
	if escapeStart < 0 {
		return s
	}

	out := make([]byte, 0, len(s))
	out = append(out, s[:escapeStart]...)
	for i := escapeStart; i < len(s); {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' &&
			isHexDigit(s[i+2]) && isHexDigit(s[i+3]) {
			out = append(out, unhexNibble(s[i+2])<<4|unhexNibble(s[i+3]))
			i += 4
			continue
		}
		out = append(out, s[i])
		i++
	}
	return string(out)
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// unhexNibble converts a single hex digit to its value. Callers must guard with
// isHexDigit first; a non-hex byte falls through to 0.
func unhexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	default:
		return 0
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
	} else if !orphanBytesCompatible(req.ExpectedBytes, resp.ContentLength) {
		// Orphan response (no method/path from request pairing). Apply the
		// same byte-tolerance gate that the ring buffer Lookup uses, so a
		// tiny healthcheck UUID body (cl=36) can't match a large attack
		// response (2401 bytes) through the VIP push lane.
		return false
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
//
// When req.EventID is set, only that event's promoted evidence is eligible:
// an exact map lookup, gated by matchesVIP, consumed on success. This prevents
// a different investigation that happens to share method+path+status from
// consuming evidence PrePin promoted for THIS event. The method+path scan is
// NOT used as a fallback in this path — that fallback is the cross-consumption
// bug. Callers that cannot supply an EventID fall back to the legacy scan.
func (lc *liveCollector) lookupVIPEvidence(req LookupRequest) []CapturedResponse {
	lc.vipMu.Lock()
	defer lc.vipMu.Unlock()

	// --- Ownership-safe path: exact event match only ---
	if req.EventID != "" {
		resp, ok := lc.vipEvidence[req.EventID]
		if !ok {
			return nil
		}
		if !matchesVIP(resp, req) {
			// Entry exists but doesn't match the request shape — a correlation
			// bug worth investigating. Keep the entry (do NOT delete): it's the
			// best evidence for diagnosing the mismatch.
			log.Printf("[rec:vip] Exact VIP evidence mismatch for %s: req method=%s path=%s status=%d host=%s; resp method=%s path=%s status=%d host=%s",
				req.EventID, req.Method, req.Path, req.StatusCode, req.Host,
				resp.Method, resp.Path, resp.StatusCode, resp.Host)
			return nil
		}
		delete(lc.vipEvidence, req.EventID)
		log.Printf("[rec:vip] Exact VIP evidence consumed for %s: status=%d method=%s path=%s",
			req.EventID, resp.StatusCode, resp.Method, resp.Path)
		return []CapturedResponse{resp}
	}

	// --- Legacy path (EventID absent): method+path scan, unchanged ---
	// Consume the first matched VIP evidence after use. Only one entry is
	// deleted per lookup — if multiple VIP evidences match (different events
	// with similar request shapes), the remaining ones stay available for
	// their own event's lookup.
	var candidates []CapturedResponse
	var consumeID string
	for id, resp := range lc.vipEvidence {
		if matchesVIP(resp, req) {
			candidates = append(candidates, resp)
			if consumeID == "" {
				consumeID = id // mark first match for consumption
			}
		}
	}
	if consumeID != "" {
		delete(lc.vipEvidence, consumeID)
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
