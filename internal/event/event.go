package event

import (
	"crypto/rand"
	"fmt"
	"time"
)

// SourceType identifies the collector that produced the event.
const (
	SourceDocker  = "docker"
	SourceSystemd = "systemd"
	SourceFile    = "file"
	SourceJournal = "journal"
	SourceAudit   = "audit"
)

// Event is the canonical unit of work in Observer.
// Every collector — Docker, journald, file tail, audit — produces Events.
// The analyzer pipeline does not care where the event came from;
// it cares about SourceType + SourceName for pattern scoping,
// and Line for classification.
type Event struct {
	// ID is a unique identifier for this event, generated at creation.
	// Carried through the entire pipeline into alerts for provenance tracking.
	ID string `json:"id"`

	// SourceType is the collector family: "docker", "systemd", "file", etc.
	SourceType string `json:"source_type"`

	// SourceName is the specific origin within that family:
	//   docker  → container name ("nginx", "postgres")
	//   systemd → unit name ("sshd", "nginx")
	//   file    → file path ("/var/log/auth.log")
	//   journal → syslog identifier ("kernel", "sshd")
	SourceName string `json:"source_name"`

	// Line is the raw log text as received from the collector.
	Line string `json:"line"`

	// NormalizedLine is the line after source-family normalization.
	// Set by the normalizer, used for hashing. Empty until normalized.
	NormalizedLine string `json:"normalized_line,omitempty"`

	// Hash is the SHA-256 of NormalizedLine. Set by the analyzer.
	Hash string `json:"hash,omitempty"`

	// Stream distinguishes output channels: "stdout", "stderr", "journal", etc.
	Stream string `json:"stream,omitempty"`

	// Timestamp is when the event was received by the collector.
	Timestamp time.Time `json:"timestamp"`

	// Metadata holds source-specific extras that don't warrant top-level fields yet.
	// Examples: "container_id", "image", "pid", "uid", "unit_instance"
	// This is the extensibility escape hatch — add structure later when you need it.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ScopeKey returns the pattern store lookup key for this event.
// This is what the pattern store uses to find source-scoped patterns.
// Format: "source_type:source_name" e.g. "docker:nginx", "systemd:sshd"
func (e *Event) ScopeKey() string {
	return e.SourceType + ":" + e.SourceName
}

// NewID generates a short random event ID for provenance tracking.
func NewID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("evt_%x", b)
}