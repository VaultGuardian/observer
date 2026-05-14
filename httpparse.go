// httpparse.go
package main

import (
	"net"
	"regexp"
	"strconv"
)

// =============================================================================
// HTTP Request Extraction from Log Lines
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
//
// =============================================================================
// NORMALIZED vs RAW — why we have two parsers (P0 fix, design consensus)
// =============================================================================
//
// The generic/Docker normalizer applies `\b\d{4,}\b -> <NUM>` GLOBALLY on the
// log line, including inside the quoted HTTP request line. So a backend log:
//
//   Raw:        "GET /api/orders/123456?ts=1774472800 HTTP/1.1" 200 1234
//   Normalized: "GET /api/orders/<NUM>?ts=<NUM> HTTP/1.1" 200 <NUM>
//
// The nginx normalizer treats the request line as SACRED and preserves it raw.
//
// REC's AF_PACKET sniffer captures the literal wire path. Its lookup does an
// exact string match on (Method, Path). For backend-sourced events with
// numeric URL components, looking up REC with the normalized `<NUM>` path
// fails every time because REC has the raw `123456` form.
//
// Fix: parse RAW path from evt.Line for REC correlation. Keep parseNormalizedLine
// for coordinator correlation key (where collapsing numbers is desirable so
// nginx and backend events for the same request join the same huddle).

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

// parseNormalizedLine extracts HTTP components from a NORMALIZED log line.
// Tries all three formats in order: hostname-prefixed, quoted, bare.
// Returns method, path (with query string), host, statusCode.
// Returns zero values for non-HTTP logs (error logs, syslog, etc.)
//
// USE FOR: coordinator correlation key (canonicalPath collapses numbers,
// joining nginx + backend events for the same request), pattern store
// scope keys, anything that wants stable hashing.
//
// DO NOT USE FOR: REC evidence lookup. The normalized path may contain
// <NUM> placeholders that will never match REC's raw wire capture.
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

// parseRawHTTPLine extracts HTTP components from a RAW (pre-normalization)
// log line. Used for REC evidence lookup, which requires the literal path
// the client sent on the wire — including any numeric values that the
// generic/Docker normalizer would substitute with <NUM>.
//
// Tries Format 2 (quoted request line) and Format 3 (bare). Format 1
// (hostname-prefixed) does NOT occur in raw logs — it is produced by the
// nginx normalizer prepending the resolved vhost to the request line.
//
// Returns method, path (with query string, RAW), host (always empty — raw
// access logs do not carry the resolved vhost in a position we can extract
// generically), and statusCode. Returns zero values for non-HTTP logs.
//
// CALLER NOTE: when you need a host, fall back to parseNormalizedLine's
// host field. The combination "raw path from this function + host from
// parseNormalizedLine" is what feeds REC's LookupRequest.
func parseRawHTTPLine(raw string) (method, path, host string, statusCode int) {
	// Format 2: quoted request line (covers raw nginx access log AND raw
	// generic backend access log — both wrap the request line in quotes).
	if m := reNormalizedHTTPQuoted.FindStringSubmatch(raw); m != nil {
		code, _ := strconv.Atoi(m[3])
		return m[1], m[2], "", code
	}

	// Format 3: bare (rare — some custom containers emit "METHOD path HTTP/x" directly).
	if m := reNormalizedHTTPBare.FindStringSubmatch(raw); m != nil {
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
//	nginx:   /?debug=true&test=1774472800
//	backend: /?debug=true&test=<NUM>
//
// canonicalPath applies the same number replacement so both containers produce
// the same coordinator key. This does NOT affect normalizer output, hash stability,
// or classification — only the coordinator's correlation key.
var reCanonicalNumbers = regexp.MustCompile(`\b\d{4,}\b`)

func canonicalPath(path string) string {
	return reCanonicalNumbers.ReplaceAllString(path, "<NUM>")
}

// statusCodeRejectsAttack returns true if the HTTP status code is conclusive
// evidence that the server rejected/ignored the attack. Used by the cache-hit
// status-aware routing in routeAlert() to short-circuit repeat probes.
//
// Conservative first cut: 403/404/405/410 only.
// 400 excluded — revisit after watching production logs.
// 200/3xx/5xx/unknown always route to coordinator for REC/T2 evidence.
func statusCodeRejectsAttack(code int) bool {
	switch code {
	case 403, 404, 405, 410:
		return true
	}
	return false
}

// isBareIP returns true if the host string is an IP address rather than a
// domain name. Handles IPv4, IPv6, and host:port formats.
//
// Used by the edge-generated response routing in routeAlert() to detect
// bare-IP requests hitting the default server. When the Host header is an
// IP address, the request almost certainly hit the web server's default
// server block, not a configured vhost with a backend application.
func isBareIP(host string) bool {
	if host == "" {
		return false
	}
	// Strip port if present (handles "1.2.3.4:80" and "[::1]:443")
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	return net.ParseIP(host) != nil
}
