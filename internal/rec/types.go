// internal/rec/types.go
package rec

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// =============================================================================
// Evidence Status — The "Why Did It Fail" State Machine
// =============================================================================

type EvidenceStatus string

const (
	EvidenceAvailableHighConfidence       EvidenceStatus = "available_high_confidence"
	EvidenceAvailableLowConfidence        EvidenceStatus = "available_low_confidence"
	EvidenceNotAvailableCollectorDisabled EvidenceStatus = "not_available_collector_disabled"
	EvidenceNotAvailableNoMatch           EvidenceStatus = "not_available_no_match"
	EvidenceNotAvailableEvicted           EvidenceStatus = "not_available_evicted"
	EvidenceNotAvailableEdgeGenerated     EvidenceStatus = "not_available_edge_generated"
	EvidenceNotAvailableEncryptedPath     EvidenceStatus = "not_available_encrypted_path"
)

// =============================================================================
// Confidence Levels
// =============================================================================

type Confidence string

const (
	ConfidenceHigh Confidence = "high"
	ConfidenceLow  Confidence = "low"
	ConfidenceNone Confidence = "none"
)

// =============================================================================
// Detected Format
// =============================================================================

type DetectedFormat string

const (
	FormatDotenv  DetectedFormat = "dotenv"
	FormatJSON    DetectedFormat = "json"
	FormatPasswd  DetectedFormat = "passwd"
	FormatHTML    DetectedFormat = "html"
	FormatXML     DetectedFormat = "xml"
	FormatBinary  DetectedFormat = "binary"
	FormatUnknown DetectedFormat = "unknown"
)

// =============================================================================
// Transport Evidence — Layer 1
// =============================================================================

type TransportEvidence struct {
	StatusCode      int           `json:"status_code"`
	ContentType     string        `json:"content_type"`
	ContentLength   int64         `json:"content_length"`
	CapturedAt      time.Time     `json:"captured_at"`
	ResponseLatency time.Duration `json:"response_latency,omitempty"`
	RequestDuration time.Duration `json:"request_duration,omitempty"`
	LatencySource   string        `json:"latency_source,omitempty"`
	BodyPreviewHash string        `json:"body_preview_hash"`
	CaptureMode     string        `json:"capture_mode"`
}

// =============================================================================
// Disclosure Analysis — Layer 2
// =============================================================================

type DisclosureAnalysis struct {
	Format              DetectedFormat `json:"format"`
	RedactionConfidence Confidence     `json:"redaction_confidence"`
	DisclosureSummary   string         `json:"disclosure_summary"`
	// Number of values the redactors actually stripped as sensitive from
	// the body preview. 0 means redaction ran but found nothing to strip;
	// it does NOT mean the body is safe (fail-closed formats carry that
	// via Format/RedactionConfidence).
	SensitiveRedactions int `json:"sensitive_redactions,omitempty"`
	redactedPreview     string
}

// RedactedPreview returns the redacted body preview.
func (d *DisclosureAnalysis) RedactedPreview() string {
	if d == nil {
		return ""
	}
	return d.redactedPreview
}

// =============================================================================
// Evidence — The Complete REC Result
// =============================================================================

type Evidence struct {
	Status                EvidenceStatus      `json:"status"`
	CorrelationConfidence Confidence          `json:"correlation_confidence"`
	Transport             *TransportEvidence  `json:"transport,omitempty"`
	Disclosure            *DisclosureAnalysis `json:"disclosure,omitempty"`
	SafeBodyPreview       string              `json:"safe_body_preview,omitempty"`
	CandidateCount        int                 `json:"candidate_count"`
}

// HasEvidence returns true if any evidence is available.
func (e *Evidence) HasEvidence() bool {
	if e == nil {
		return false
	}
	return e.Status == EvidenceAvailableHighConfidence ||
		e.Status == EvidenceAvailableLowConfidence
}

// ForJournal returns a compact string for journal/log output.
func (e *Evidence) ForJournal() string {
	if e == nil {
		return "EvidenceStatus=not_available_collector_disabled Correlation=none"
	}
	s := fmt.Sprintf("EvidenceStatus=%s Correlation=%s", e.Status, e.CorrelationConfidence)
	if e.HasEvidence() && e.Transport != nil {
		s += fmt.Sprintf(" StatusCode=%d ContentLength=%d BodyPreviewHash=sha256:%.16s CaptureMode=%s",
			e.Transport.StatusCode,
			e.Transport.ContentLength,
			e.Transport.BodyPreviewHash,
			e.Transport.CaptureMode,
		)
		if e.Disclosure != nil {
			s += fmt.Sprintf(" Format=%s Disclosure=%q", e.Disclosure.Format, e.Disclosure.DisclosureSummary)
		}
		if e.SafeBodyPreview != "" {
			s += " HasPreview=true"
		}
	}
	return s
}

// =============================================================================
// Helpers
// =============================================================================

// HashBody computes the SHA-256 hex digest of a response body.
func HashBody(body []byte) string {
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h[:])
}

// =============================================================================
// REC Stats
// =============================================================================
//
// v0.42.7: counters split into inline-parser, reassembly, and pairing groups.
// Request parsing is synchronous (inline in processFrame). Response parsing
// uses TCP reassembly. Pairing is event-driven with timeout-based orphaning.

type RECStats struct {
	PacketsSeen    int64
	VXLANUnwrapped int64
	BufferEntries  int
	BufferBytes    int64

	// Buffer eviction pressure (v1.0 burst hardening).
	// Split by reason so operators can immediately diagnose which
	// constraint is binding: "I need more entries" vs "I need more bytes"
	// vs "I need a longer age window."
	BufferEvictionsTotal    int64
	BufferEvictionsCapacity int64 // entry cap hit
	BufferEvictionsAge      int64 // MaxAge expired
	BufferEvictionsBytes    int64 // byte cap hit

	// Inline request parser (synchronous in processFrame)
	InlineRequests       int64 // successful inline parses
	InlineDuplicateDrops int64 // TCP seq dedupe caught retransmit
	InlineBodySkips      int64 // skipped segment (body data, not new request)

	// Response reassembly (response-direction only, via gopacket/tcpassembly)
	ReassemblyStreamsActive   int64
	ReassemblyStreamsTotal    int64
	ReassemblyStreamsTimedOut int64
	ReassemblyStreamDrops     int64 // MaxActiveStreams cap hit
	ReassemblyResponses       int64
	ReassemblyParseErrors     int64

	// Pairing
	PairImmediate   int64 // response found waiting request (normal fast path)
	OrphanResponses int64 // response expired from queue without matching request
	RequestsExpired int64 // request expired without matching response (edge-generated)

	// Flow state
	FlowStates        int64 // current active flow entries
	FlowEvictions     int64 // flows evicted due to MaxFlowStates cap (total)
	FlowEvictionsLive int64 // subset where the evicted flow had pending request/response state

	// Dashboard backward compat — populated from above in Stats()
	HTTPRequests  int64 // = InlineRequests
	HTTPResponses int64 // = ReassemblyResponses
	PairMisses    int64 // = OrphanResponses

	FeedHTTP   int64
	VIPMatches int64

	// Port registry telemetry (v0.47.1).
	// Useful for debugging "why isn't REC seeing this port?" — operator
	// can confirm the port made it into the configured set, or watch
	// the learn counter rise as new HTTP-shaped traffic discovers ports
	// at runtime.
	PortConfiguredCount int   // ports seeded from CollectorConfig.Ports
	PortLearnedCount    int   // ports added at runtime from payload prefix detection
	PortLearnAttempts   int64 // total times learn() was called (incl. duplicates and refusals)
	PortLearnAdded      int64 // successful learns (subset of attempts)
	PortLearnRefused    int64 // refused due to cap, cap=0, or invalid port
	PortLearnCap        int   // configured upper bound on PortLearnedCount
}

// =============================================================================
// Reassembly Config (response-only as of v0.42.7)
// =============================================================================
//
// Bounded by design — REC must never become a DoS target. All limits below
// have safe defaults; an attacker cannot force unbounded memory by opening
// many partial connections, sending slowloris-style dribble, or sending
// massive bodies. Streams age out, total memory is capped, per-connection
// memory is capped.

type ReassemblyConfig struct {
	// MaxBody bounds bytes read per response body. Default 2048.
	MaxBody int

	// StreamTTL is the absolute lifetime of any stream. After this,
	// the stream is force-completed (Landmine 3 mitigation: ensures
	// the http.ReadResponse goroutine cannot leak).
	StreamTTL time.Duration

	// IdleTimeout is how long a stream can go without packets before
	// being flushed. Catches slowloris and abandoned connections.
	IdleTimeout time.Duration

	// MaxBufferedPagesTotal caps total memory across all streams.
	// tcpassembly uses 4KB pages; 4096 pages = 16 MiB ceiling.
	MaxBufferedPagesTotal int

	// MaxBufferedPagesPerConn caps memory per single stream.
	// Prevents one slow connection from consuming all memory.
	MaxBufferedPagesPerConn int

	// MaxActiveStreams caps the number of concurrent stream goroutines.
	// Above this, new streams are dropped. Each stream has 1 goroutine
	// + assembler bookkeeping; 10K is generous and bounded.
	MaxActiveStreams int
}

// DefaultReassemblyConfig returns safe defaults.
func DefaultReassemblyConfig() ReassemblyConfig {
	return ReassemblyConfig{
		MaxBody:                 2048,
		StreamTTL:               5 * time.Second,
		IdleTimeout:             2 * time.Second,
		MaxBufferedPagesTotal:   4096,
		MaxBufferedPagesPerConn: 16,
		MaxActiveStreams:        10000,
	}
}

// =============================================================================
// Flow Config — bidirectional pairing queue bounds (v0.42.7)
// =============================================================================
//
// Every queue that an attacker can influence needs hard caps. An attacker
// could flood half-open connections, weird partial requests, or spray
// responses to grow memory. These bounds prevent that.

type FlowConfig struct {
	// MaxFlowStates caps total tracked flows. When exceeded, the oldest
	// flow with both queues empty is evicted; if none, the oldest flow
	// overall. 50K flows × ~1KB each ≈ 50 MB ceiling.
	MaxFlowStates int

	// MaxRequestsPerFlow caps queued requests per flow. Protects against
	// keep-alive connections with many unanswered requests. When exceeded,
	// oldest request is dropped.
	MaxRequestsPerFlow int

	// MaxResponsesPerFlow caps queued orphan responses per flow. Protects
	// against responses flooding a flow with no matching requests.
	MaxResponsesPerFlow int

	// ResponseOrphanTimeout is how long an unmatched response sits in the
	// queue before being inserted as an orphan into the ring buffer and
	// counted as a miss. 2s is generous — the inline parser succeeds in
	// microseconds; if the request hasn't arrived by then, it was split,
	// missed, or mid-stream capture.
	ResponseOrphanTimeout time.Duration

	// RequestExpireTimeout is how long an unmatched request sits before
	// being discarded. These are requests where the response was never
	// observed (edge-generated 404, 301, static files served by nginx).
	RequestExpireTimeout time.Duration
}

// DefaultFlowConfig returns bounded defaults.
func DefaultFlowConfig() FlowConfig {
	return FlowConfig{
		MaxFlowStates:         50000,
		MaxRequestsPerFlow:    64,
		MaxResponsesPerFlow:   64,
		ResponseOrphanTimeout: 2 * time.Second,
		RequestExpireTimeout:  30 * time.Second,
	}
}
