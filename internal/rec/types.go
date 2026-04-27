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
	VXLANHTTPReq   int64
	VXLANHTTPResp  int64
	BufferEntries  int
	BufferBytes    int64

	// Speculative parse telemetry (v0.22)
	ReqPrefixHits  int64
	ReqParseFails  int64
	RespPrefixHits int64
	RespParseFails int64

	// Phase 1 segmentation diagnostics (v0.40)
	BodyEmptyInSegment     int64
	BodyExpectedButMissing int64
	ChunkedRespCount       int64
	CompressedRespCount    int64

	// Fix 1: VIP lane telemetry
	VIPMatches int64
}