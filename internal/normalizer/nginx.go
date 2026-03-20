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
	reNginxProcessNum = regexp.MustCompile(`process \d+`)

	// All quoted fields in a log line
	reAllQuotedFields = regexp.MustCompile(`"([^"]*)"`)

	// Matches an HTTP request line: METHOD /path HTTP/version
	reRequestLine = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP/\d(?:\.\d)?$`)

	// Trailing status + bytes after request line
	reTrailingStatusBytes = regexp.MustCompile(`^\s*(\d{3})\s+\d+`)

	// Upstream response time: 0.001, 1.234
	reUpstreamTime = regexp.MustCompile(`\b\d+\.\d{3}\b`)
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
	if line == "" {
		return ""
	}

	// Extract all quoted fields from the line.
	// Standard nginx combined:  "GET /path HTTP/1.1" 200 1234 "-" "curl/8.5.0"
	// CapRover nginx:           "api.admin.kovicloud.com" "GET /path HTTP/2.0" 200 1234 "-" "curl/8.5.0" "-"
	//
	// The request line is the quoted field that starts with an HTTP method.
	// If a quoted field appears before it (e.g. hostname), preserve it as HOST.
	// Everything after the request line (referrer, user-agent, etc.) is stripped.
	fields := reAllQuotedFields.FindAllStringSubmatch(line, -1)

	var host string
	var requestLine string
	var requestFieldIdx int

	for i, f := range fields {
		val := f[1]
		if reRequestLine.MatchString(val) {
			requestLine = val
			requestFieldIdx = i

			// If the field before this one is not itself a request line,
			// it's the hostname/vhost (CapRover format).
			if i > 0 && !reRequestLine.MatchString(fields[i-1][1]) {
				host = fields[i-1][1]
			}
			break
		}
	}

	// Couldn't find a request line — return minimally cleaned version
	if requestLine == "" {
		return strings.Join(strings.Fields(line), " ")
	}

	// Find status code from the text after the request line's closing quote
	requestQuoted := `"` + requestLine + `"`
	idx := strings.Index(line, requestQuoted)

	status := "000"
	if idx >= 0 {
		suffix := line[idx+len(requestQuoted):]
		if m := reTrailingStatusBytes.FindStringSubmatch(strings.TrimSpace(suffix)); len(m) > 1 {
			status = m[1]
		}
	}

	// Build the normalized output.
	// The request line is SACRED — method, path, query string, protocol all preserved.
	// This ensures different attack payloads produce different hashes.
	//
	// We strip: IP, timestamp, byte count, referrer, user-agent, x-forwarded-for.
	// We keep: host (if present), full request line, status code.
	_ = requestFieldIdx // used above for host detection

	parts := make([]string, 0, 4)
	if host != "" {
		parts = append(parts, host)
	}
	parts = append(parts, requestLine)
	parts = append(parts, status)

	return strings.Join(parts, " ")
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