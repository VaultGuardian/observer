package normalizer

import (
	"regexp"
	"strings"
)

// NginxNormalizer handles nginx access and error log formats.
//
// Docker-specific framing is stripped upstream in NormalizeEvent().
// This normalizer only sees native nginx log content.
//
// Nginx combined log format (access):
//
//	172.17.0.1 - - [17/Mar/2026:15:10:04 +0000] "GET /api/health HTTP/1.1" 200 15 "-" "curl/7.88"
//
// Nginx error log format:
//
//	2026/03/17 15:10:04 [error] 28#28: *1 open() "/usr/share/nginx/html/favicon.ico" failed ...
//
// We strip: IP, timestamps, PID#TID, *connID, client IP, user-agent, referrer,
// byte count, upstream times, and numeric path segments — preserving the
// structural identity (method, path pattern, status code, error type).
type NginxNormalizer struct{}

func (n *NginxNormalizer) Family() string { return "nginx" }

var (
	// Access log leading IP + " - - " or " - user "
	reNginxAccessPrefix = regexp.MustCompile(`^\S+\s+-\s+\S+\s+`)

	// Bracket timestamp: [17/Mar/2026:15:10:04 +0000]
	reNginxBracketTS = regexp.MustCompile(`\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+\-]\d{4}\]`)

	// Error log timestamp: 2026/03/17 15:10:04
	reNginxErrorTS = regexp.MustCompile(`^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+`)

	// PID#TID: 28#28, 30#30, etc.
	reNginxPidTid = regexp.MustCompile(`\d+#\d+:`)

	// Connection number: *1, *234, *10
	reNginxConnNum = regexp.MustCompile(`\*\d+`)

	// Client info in error log: "client: 172.19.0.1,"
	reNginxClient = regexp.MustCompile(`client:\s+\S+,`)

	// Worker/child process numbers in notice logs: "start worker process 31"
	// These are short numbers (1-2 digits) that the generic normalizer won't catch.
	reNginxProcessNum = regexp.MustCompile(`process \d+`)

	// Query string in request path
	reQueryString = regexp.MustCompile(`\?[^"]*`)

	// Numeric path segments: /users/12345 → /users/<ID>
	reNumericPathSeg = regexp.MustCompile(`/\d+(/|"|$)`)

	// Access log: status code + byte count after closing quote of request line.
	// Used on the full line in fallback mode.
	reAccessStatusBytes = regexp.MustCompile(`" (\d{3}) \d+`)

	// Trailing status + bytes when the line has been split at the request line end.
	// The trailing part starts with: " 200 896 ..." (space, status, space, bytes)
	reTrailingStatusBytes = regexp.MustCompile(`^\s*(\d{3})\s+\d+`)

	// Upstream response time: 0.001, 1.234
	reUpstreamTime = regexp.MustCompile(`\b\d+\.\d{3}\b`)

	// Any quoted string: "anything here" — used to strip referrer, user-agent,
	// x-forwarded-for AFTER the request line has been processed.
	// We apply this only to the trailing portion of access logs.
	reQuotedField = regexp.MustCompile(`"[^"]*"`)
)

func (n *NginxNormalizer) Normalize(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Docker framing already stripped by NormalizeEvent().

	// Detect format: error log starts with YYYY/, access log starts with IP.
	if len(line) > 4 && line[4] == '/' {
		return n.normalizeError(line)
	}

	return n.normalizeAccess(line)
}

func (n *NginxNormalizer) normalizeAccess(line string) string {
	// Strip leading IP + identity + user: "172.19.0.1 - - "
	line = reNginxAccessPrefix.ReplaceAllString(line, "")

	// Strip bracket timestamp: [18/Mar/2026:22:32:28 +0000]
	line = reNginxBracketTS.ReplaceAllString(line, "")

	line = strings.TrimSpace(line)

	// At this point the line looks like:
	// "GET /;ls+-la HTTP/1.1" 404 153 "-" "curl/8.5.0" "-"
	//
	// We need to:
	// 1. Keep the request line (first quoted string) — that's the classification signal
	// 2. Keep the status code
	// 3. Replace everything else (bytes, referrer, user-agent, x-forwarded-for)

	// Find the end of the request line (first closing quote after opening)
	requestEnd := -1
	if len(line) > 0 && line[0] == '"' {
		// Find the matching close quote for the request line
		requestEnd = strings.Index(line[1:], `"`)
		if requestEnd >= 0 {
			requestEnd += 2 // adjust for offset + include closing quote
		}
	}

	if requestEnd > 0 && requestEnd < len(line) {
		requestPart := line[:requestEnd]
		trailingPart := line[requestEnd:]

		// Normalize the request part
		requestPart = reQueryString.ReplaceAllString(requestPart, "?<QUERY>")
		requestPart = reNumericPathSeg.ReplaceAllStringFunc(requestPart, func(match string) string {
			last := match[len(match)-1:]
			return "/<ID>" + last
		})

		// Normalize the trailing part: status + bytes + quoted fields
		// Replace byte count: " 200 896" → " 200 <BYTES>"
		trailingPart = reTrailingStatusBytes.ReplaceAllString(trailingPart, " $1 <BYTES>")

		// Replace ALL remaining quoted strings (referrer, user-agent, x-forwarded-for)
		trailingPart = reQuotedField.ReplaceAllString(trailingPart, `"<VAR>"`)

		// Strip upstream response times if present
		trailingPart = reUpstreamTime.ReplaceAllString(trailingPart, "<TIME>")

		line = requestPart + trailingPart
	} else {
		// Couldn't parse request line — fall back to simple replacements
		line = reQueryString.ReplaceAllString(line, "?<QUERY>")
		line = reNumericPathSeg.ReplaceAllStringFunc(line, func(match string) string {
			last := match[len(match)-1:]
			return "/<ID>" + last
		})
		line = reAccessStatusBytes.ReplaceAllString(line, `" $1 <BYTES>`)
		line = reUpstreamTime.ReplaceAllString(line, "<TIME>")
	}

	// Collapse whitespace
	line = strings.Join(strings.Fields(line), " ")

	return line
}

func (n *NginxNormalizer) normalizeError(line string) string {
	// Strip error log timestamp prefix
	line = reNginxErrorTS.ReplaceAllString(line, "")

	// Strip PID#TID: "28#28:" → "<PID>:"
	line = reNginxPidTid.ReplaceAllString(line, "<PID>:")

	// Strip connection number: "*1" → "*<CONN>"
	line = reNginxConnNum.ReplaceAllString(line, "*<CONN>")

	// Strip client IP: "client: 172.19.0.1," → "client: <CLIENT>,"
	line = reNginxClient.ReplaceAllString(line, "client: <CLIENT>,")

	// Strip worker/child process numbers: "start worker process 31" → "start worker process <NUM>"
	line = reNginxProcessNum.ReplaceAllString(line, "process <NUM>")

	// Collapse whitespace
	line = strings.Join(strings.Fields(line), " ")

	return line
}