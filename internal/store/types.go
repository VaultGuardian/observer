package store

import "time"

// Finding represents a single classification decision from the pipeline.
// Every event that makes it past noise suppression gets recorded here —
// alerts, denies, suppressions, downgrades, recon, everything.
//
// This is the "what happened" store. The pattern store remembers HOW to
// classify; this remembers WHAT was classified and WHAT the outcome was.
type Finding struct {
	// Event identity
	EventID    string    `json:"event_id"`
	Timestamp  time.Time `json:"timestamp"`
	SourceType string    `json:"source_type"` // "docker", "systemd", etc.
	SourceName string    `json:"source_name"` // container name or service

	// Request details
	SourceIP      string `json:"source_ip,omitempty"`
	DestHost      string `json:"dest_host,omitempty"`
	HTTPMethod    string `json:"http_method,omitempty"`
	HTTPPath      string `json:"http_path,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	ResponseBytes int64  `json:"response_bytes,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`

	// Classification
	Verdict        string  `json:"verdict"`        // allow, malicious, alert, suppress, recon, unknown
	Classification string  `json:"classification"` // safe, malicious, recon_failed, recon_success, noise
	Confidence     float64 `json:"confidence"`
	Reason         string  `json:"reason"`
	MatchedVia     string  `json:"matched_via"` // pattern, llm, noise_filter, seeded

	// Raw/normalized data
	RawLine        string `json:"raw_line,omitempty"`
	NormalizedLine string `json:"normalized_line,omitempty"`
	NormalizedHash string `json:"normalized_hash,omitempty"`

	// Evidence (from REC pipeline)
	EvidenceStatus      string `json:"evidence_status,omitempty"`
	EvidenceStatusCode  int    `json:"evidence_status_code,omitempty"`
	EvidenceContentType string `json:"evidence_content_type,omitempty"`
	EvidenceBodyHash    string `json:"evidence_body_hash,omitempty"`
	EvidenceCaptureMode string `json:"evidence_capture_mode,omitempty"`

	// Coordinator outcome
	CoordinatorKey    string `json:"coordinator_key,omitempty"`
	CoordinatorEvents int    `json:"coordinator_events,omitempty"`
	Downgraded        bool   `json:"downgraded"`
	DowngradeReason   string `json:"downgrade_reason,omitempty"`

	// Notification
	Notified bool `json:"notified"` // was an email/alert sent?
}

// ScannerSession groups probes from the same source IP that hit the same
// response body. "Scanner probed 53 PHP filenames; all returned default
// Laravel page" = one session, one potential notification.
type ScannerSession struct {
	ID          int64     `json:"id"`
	SourceIP    string    `json:"source_ip"`
	TargetApp   string    `json:"target_app"` // dest_host or source_name
	BodyHash    string    `json:"body_hash"`  // redacted body hash
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	ProbeCount  int       `json:"probe_count"`
	SamplePaths string    `json:"sample_paths"` // JSON array of first N paths
	Verdict     string    `json:"verdict"`       // recon_failed, recon_success, mixed
	Notified    bool      `json:"notified"`
}

// PipelineStats is a periodic snapshot of pipeline counters for time-series
// storage. Powers future dashboards.
type PipelineStats struct {
	Timestamp       time.Time `json:"timestamp"`
	Processed       int64     `json:"processed"`
	PatternHits     int64     `json:"pattern_hits"`
	NoiseSuppressed int64     `json:"noise_suppressed"`
	LLMCalls        int64     `json:"llm_calls"`
	LLMErrors       int64     `json:"llm_errors"`
	PatternsLearned int64     `json:"patterns_learned"`
	MaliciousCount       int64     `json:"malicious_count"`
	AlertCount      int64     `json:"alert_count"`
	SuppressCount   int64     `json:"suppress_count"`
}