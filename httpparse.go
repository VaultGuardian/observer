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
