package main

import (
	"regexp"
	"strconv"
)

// =============================================================================
// HTTP Request Extraction from Normalized Log Lines
// =============================================================================
//
// Observer's normalizers produce three different formats depending on the
// source. All three need to be parsed to extract the HTTP request identity
// (method, path, status code) used for:
//   - Coordinator correlation keys (nginx + backend → same investigation)
//   - REC evidence lookup (match captured response to the right request)
//
// Format 1 — Hostname-prefixed (CapRover nginx normalizer):
//   "api.admin.kovicloud.com GET /?q=UNION+SELECT HTTP/2.0 200"
//
// Format 2 — Quoted request line (generic normalizer):
//   `<IP> - - [<TS>] "GET /?q=UNION+SELECT HTTP/1.0" 200 <NUM>`
//
// Format 3 — Bare (no hostname, no quotes):
//   "GET /?q=UNION+SELECT+1,2,3 HTTP/1.0 200"

var httpMethods = `GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE`

// reNormalizedHTTPHosted matches Format 1 — hostname prefix + method + path + status.
var reNormalizedHTTPHosted = regexp.MustCompile(
	`^(\S+)\s+(` + httpMethods + `)\s+(\S+)\s+HTTP/\S+\s+(\d{3})`)

// reNormalizedHTTPQuoted matches Format 2 — method + path inside quotes, status after.
var reNormalizedHTTPQuoted = regexp.MustCompile(
	`"(` + httpMethods + `)\s+(\S+)\s+HTTP/\S+"\s+(\d{3})`)

// reNormalizedHTTPBare matches Format 3 — method at start of line, no quotes.
var reNormalizedHTTPBare = regexp.MustCompile(
	`^(` + httpMethods + `)\s+(\S+)\s+HTTP/\S+\s+(\d{3})`)

// parseNormalizedLine extracts HTTP components from a normalized log line.
// Tries all three formats in order: hostname-prefixed, quoted, bare.
// Returns method, path (with query string), host, statusCode.
// Returns zero values for non-HTTP logs (error logs, syslog, etc.)
func parseNormalizedLine(normalized string) (method, path, host string, statusCode int) {
	// Format 1: hostname-prefixed (CapRover nginx normalizer)
	if m := reNormalizedHTTPHosted.FindStringSubmatch(normalized); m != nil {
		code, _ := strconv.Atoi(m[4])
		return m[2], m[3], m[1], code
	}

	// Format 2: quoted request line (generic normalizer)
	if m := reNormalizedHTTPQuoted.FindStringSubmatch(normalized); m != nil {
		code, _ := strconv.Atoi(m[3])
		return m[1], m[2], "", code
	}

	// Format 3: bare (no hostname, no quotes)
	if m := reNormalizedHTTPBare.FindStringSubmatch(normalized); m != nil {
		code, _ := strconv.Atoi(m[3])
		return m[1], m[2], "", code
	}

	return "", "", "", 0
}

// extractResponseBytes extracts the response byte count from a RAW log line.
// The normalized line strips byte counts, but the raw line preserves them.
//
// Used as a ranking signal for orphan response disambiguation (Option D,
// design consensus 2026-03-25). When multiple orphan responses match
// the same status code + time window, the one whose ContentLength is closest
// to the logged byte count is most likely the correct match.
//
// Raw nginx:   `... "GET /path HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`
// Raw backend: `... "GET /path HTTP/1.0" 200 34020 "-" "curl/8.5.0" "x.x.x.x"`
//
// NOTE: nginx logs "bytes sent to client" which includes headers and may
// reflect compression. This won't exactly match the Content-Length header.
// Use as a ranking signal with tolerance, not an exact match.
// Returns 0 if no bytes found.
var reResponseBytes = regexp.MustCompile(`HTTP/\S+"\s+\d{3}\s+(\d+)`)

func extractResponseBytes(rawLine string) int64 {
	if m := reResponseBytes.FindStringSubmatch(rawLine); m != nil {
		bytes, err := strconv.ParseInt(m[1], 10, 64)
		if err == nil {
			return bytes
		}
	}
	return 0
}

// canonicalPath normalizes a URL path for coordinator correlation keys.
//
// The nginx normalizer preserves query strings raw (sacred rule for classification),
// but the generic normalizer replaces 4+ digit numbers with <NUM>. This means
// the same request produces different paths from different containers:
//
//   nginx:   /?debug=true&test=1774472800
//   backend: /?debug=true&test=<NUM>
//
// canonicalPath applies the same number replacement so both containers produce
// the same coordinator key. This does NOT affect normalizer output, hash stability,
// or classification — only the coordinator's correlation key.
var reCanonicalNumbers = regexp.MustCompile(`\b\d{4,}\b`)

func canonicalPath(path string) string {
	return reCanonicalNumbers.ReplaceAllString(path, "<NUM>")
}