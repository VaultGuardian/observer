package normalizer

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/vaultguardian/observer/internal/event"
)

// Normalizer transforms a raw log line into a stable, hashable form
// by stripping source-family-specific variable fields (timestamps, PIDs,
// request IDs, durations, etc.) while preserving structural identity.
//
// A good normalizer means the exact-hash tier catches 80%+ of repeat lines
// before patterns or the LLM ever see them.
type Normalizer interface {
	// Normalize strips variable fields from a raw log line.
	// The output should be stable: structurally identical log lines
	// (differing only in timestamps, IDs, durations, etc.) should
	// produce identical normalized output.
	Normalize(line string) string

	// Family returns the source family this normalizer handles.
	// Used for registration and lookup.
	Family() string
}

// Registry maps source families to their normalizers.
// Thread-safe for concurrent collector use.
type Registry struct {
	mu          sync.RWMutex
	normalizers map[string]Normalizer // key: "source_type" or "source_type:source_name"
	fallback    Normalizer
}

// NewRegistry creates a registry with the default normalizers pre-registered.
func NewRegistry() *Registry {
	r := &Registry{
		normalizers: make(map[string]Normalizer),
		fallback:    &GenericNormalizer{},
	}

	// Register built-in source-family normalizers
	r.Register(&DockerNormalizer{})
	r.Register(&NginxNormalizer{})
	r.Register(&SshdNormalizer{})
	r.Register(&SyslogNormalizer{})
	r.Register(&PostgresNormalizer{})

	return r
}

// Register adds a normalizer to the registry.
// It registers under the normalizer's Family() key.
func (r *Registry) Register(n Normalizer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.normalizers[n.Family()] = n
}

// Lookup finds the best normalizer for an event.
// Priority:
//  1. Exact match on "source_type:source_name" (e.g. "docker:nginx")
//  2. Exact match on source_name alone (e.g. "nginx" — works across docker/systemd/file)
//  3. Fuzzy match: source_name contains a registered family (e.g. "demo-nginx" contains "nginx")
//  4. Match on source_type alone (e.g. "docker")
//  5. Fallback generic normalizer
func (r *Registry) Lookup(e *event.Event) Normalizer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Most specific: source_type:source_name
	if n, ok := r.normalizers[e.ScopeKey()]; ok {
		return n
	}

	// Service name across any collector type
	if n, ok := r.normalizers[e.SourceName]; ok {
		return n
	}

	// Fuzzy: does the source name contain a known service family?
	// Catches "demo-nginx" → "nginx", "my-postgres-db" → "postgres", etc.
	nameLower := strings.ToLower(e.SourceName)
	for family, n := range r.normalizers {
		if family != "generic" && family != e.SourceType && strings.Contains(nameLower, strings.ToLower(family)) {
			return n
		}
	}

	// Collector family
	if n, ok := r.normalizers[e.SourceType]; ok {
		return n
	}

	return r.fallback
}

// NormalizeEvent applies the best normalizer to an event, setting
// NormalizedLine and Hash in-place.
//
// Before calling the source-specific normalizer, we strip collector-level
// framing (Docker 8-byte stream headers, Docker ISO timestamp prefixes).
// This means normalizers only deal with the application's native log format.
func (r *Registry) NormalizeEvent(e *event.Event) {
	n := r.Lookup(e)

	// Strip collector framing ONCE, upstream of all normalizers.
	line := stripCollectorFraming(e.Line)

	e.NormalizedLine = n.Normalize(line)
	e.Hash = hashLine(e.NormalizedLine)
}

// stripCollectorFraming removes Docker-specific framing from a log line.
// This runs before any source-family normalizer, so normalizers never see
// Docker stream headers or Docker timestamp prefixes.
//
// After this function, a Docker nginx error log goes from:
//
//	"2026-03-18T22:32:28.411683956Z 2026/03/18 22:32:28 [error] 31#31: ..."
//
// to:
//
//	"2026/03/18 22:32:28 [error] 31#31: ..."
//
// and the nginx normalizer sees the native nginx format.
func stripCollectorFraming(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Docker 8-byte stream header (stdout=0x01, stderr=0x02).
	// The watcher already strips this at the binary level, but this is
	// a safety net for log lines from other sources (file tailing raw
	// Docker JSON logs, etc.).
	if len(line) > 8 && (line[0] == 1 || line[0] == 2) {
		line = line[8:]
	}

	// Docker ISO timestamp prefix: "2026-03-18T22:32:28.411683956Z "
	// Present when the Docker API is called with timestamps=true.
	// Format is always: YYYY-MM-DDTHH:MM:SS[.nanos]Z<space>
	if len(line) > 20 && line[4] == '-' && line[7] == '-' && line[10] == 'T' {
		if idx := strings.IndexByte(line, ' '); idx > 0 && idx < 40 {
			line = line[idx+1:]
		}
	}

	return strings.TrimSpace(line)
}

// hashLine produces a SHA-256 hex string from a normalized line.
func hashLine(normalized string) string {
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}
