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
	EvidenceAvailableHighConfidence      EvidenceStatus = "available_high_confidence"
	EvidenceAvailableLowConfidence       EvidenceStatus = "available_low_confidence"
	EvidenceNotAvailableCollectorDisabled EvidenceStatus = "not_available_collector_disabled"
	EvidenceNotAvailableNoMatch          EvidenceStatus = "not_available_no_match"
	EvidenceNotAvailableEvicted          EvidenceStatus = "not_available_evicted"
	EvidenceNotAvailableEdgeGenerated    EvidenceStatus = "not_available_edge_generated"
	EvidenceNotAvailableEncryptedPath    EvidenceStatus = "not_available_encrypted_path"
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
	Status                EvidenceStatus `json:"status"`
	CorrelationConfidence Confidence     `json:"correlation_confidence"`
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

type RECStats struct {
	PacketsSeen    int64
	HTTPRequests   int64
	HTTPResponses  int64
	PairMisses     int64
	VXLANUnwrapped int64
	BufferEntries  int
	BufferBytes    int64

	// Reassembly telemetry — the only HTTP parsing path
	ReassemblyStreamsActive   int64
	ReassemblyStreamsTotal    int64
	ReassemblyStreamsTimedOut int64
	ReassemblyResponses       int64
	ReassemblyRequests        int64
	ReassemblyParseErrors     int64

	// DIAG (v0.42.1)
	FeedHTTP int64

	// Fix 1: VIP lane telemetry
	VIPMatches int64
}

// =============================================================================
// Reassembly Config
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