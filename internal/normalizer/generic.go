package normalizer

import (
	"regexp"
	"strings"
)

// GenericNormalizer is the fallback for any source without a specific normalizer.
// It strips common variable prefixes: Docker stream headers, ISO timestamps,
// syslog timestamps, nginx bracket timestamps, and common numeric noise.
// This is the improved successor to the original normalizeLine() function.
type GenericNormalizer struct{}

func (g *GenericNormalizer) Family() string { return "generic" }

// Pre-compiled regexes — compiled once at init, zero cost per call.
var (
	// ISO 8601: 2026-03-17T21:42:30.123456789Z or with offset
	reISO8601 = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*[Z\+\-][\d:]*`)

	// Syslog: Mar 17 15:10:04
	reSyslog = regexp.MustCompile(`(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`)

	// Nginx bracket timestamps: [17/Mar/2026:15:10:04 +0000]
	reNginxTS = regexp.MustCompile(`\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+\-]\d{4}\]`)

	// Common date: 2026-03-17 or 2026/03/17
	reDate = regexp.MustCompile(`\d{4}[-/]\d{2}[-/]\d{2}`)

	// Time with optional milliseconds: 15:10:04 or 15:10:04.123
	reTime = regexp.MustCompile(`\d{2}:\d{2}:\d{2}[\.\d]*`)

	// IP addresses (v4)
	reIPv4 = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

	// Hex UUIDs: 550e8400-e29b-41d4-a716-446655440000
	reUUID = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

	// Pure numeric sequences of 4+ digits (PIDs, ports, durations, byte counts)
	reNumbers = regexp.MustCompile(`\b\d{4,}\b`)

	// Duration-like patterns: 3ms, 47ms, 1.23s, 200µs, 5m30s
	reDuration = regexp.MustCompile(`\b\d+[\.\d]*(?:ns|µs|us|μs|ms|s|m|h)\b`)
)

func (g *GenericNormalizer) Normalize(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Docker framing already stripped by NormalizeEvent().

	// Strip timestamps (most specific first)
	line = reISO8601.ReplaceAllString(line, "<TS>")
	line = reNginxTS.ReplaceAllString(line, "<TS>")
	line = reSyslog.ReplaceAllString(line, "<TS>")

	// Strip UUIDs before general hex might interfere
	line = reUUID.ReplaceAllString(line, "<UUID>")

	// Strip IPs
	line = reIPv4.ReplaceAllString(line, "<IP>")

	// Strip durations (before generic numbers eat the digits)
	line = reDuration.ReplaceAllString(line, "<DUR>")

	// Strip long numeric sequences (PIDs, ports, byte counts)
	line = reNumbers.ReplaceAllString(line, "<NUM>")

	// Collapse whitespace
	line = strings.Join(strings.Fields(line), " ")

	return line
}
