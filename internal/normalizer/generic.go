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

	// Bare date+time, no brackets: "2026/05/25 16:45:24" or "2026-05-25 16:45:24"
	// (optional fractional seconds). nginx ERROR-log timestamp format. Anchored as
	// a date+time PAIR on purpose: a naked time regex would also flatten incidental
	// "12:34:56" substrings elsewhere in a generic log line.
	reBareDateTime = regexp.MustCompile(`\b\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\b`)

	// IP addresses (v4)
	reIPv4 = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

	// Hex UUIDs: 550e8400-e29b-41d4-a716-446655440000
	reUUID = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

	// Pure numeric sequences of 4+ digits (PIDs, ports, durations, byte counts)
	reNumbers = regexp.MustCompile(`\b\d{4,}\b`)

	// Duration-like patterns: 3ms, 47ms, 1.23s, 200µs, 5m30s
	reDuration = regexp.MustCompile(`\b\d+[\.\d]*(?:ns|µs|us|μs|ms|s|m|h)\b`)

	// ANSI escape codes: color, bold, reset, etc. (e.g. \x1b[0m, \x1b[32m, \x1b[1;31m)
	// Zero security signal — purely presentation. Destabilizes hashes and breaks
	// JSON parsing when the LLM echoes them back in its response.
	reANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

func (g *GenericNormalizer) Normalize(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Docker framing already stripped by NormalizeEvent().

	// Strip ANSI escape codes first — they're presentation noise that
	// destabilizes hashes and can break JSON parsing downstream.
	line = reANSI.ReplaceAllString(line, "")

	// Strip timestamps (most specific first)
	line = reISO8601.ReplaceAllString(line, "<TS>")
	line = reNginxTS.ReplaceAllString(line, "<TS>")
	line = reSyslog.ReplaceAllString(line, "<TS>")
	line = reBareDateTime.ReplaceAllString(line, "<TS>") // bare nginx error-log TS, before reNumbers eats the year

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
