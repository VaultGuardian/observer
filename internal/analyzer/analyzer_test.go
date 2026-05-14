package analyzer

import (
	"testing"
)

// =============================================================================
// isFailedProbe Tests
// =============================================================================

func TestIsFailedProbe_NginxErrorFileNotFound(t *testing.T) {
	tests := []struct {
		name       string
		normalized string
		suppress   bool
		desc       string
	}{
		{
			name:       "phpunit scanner spray — clean path, file not found",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "THE BIG ONE — 20+ emails from phpunit spray should be suppressed",
		},
		{
			name:       "phpunit different prefix — api path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "same scanner, different prefix",
		},
		{
			name:       "random php probe — file not found",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/x.php" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /x.php HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "webshell hunting — clean path, file not found",
		},
		{
			name:       "mcp probe — file not found",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/mcp" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "POST /mcp HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "MCP server scanning — no sensitive path, no payload",
		},
		// === v0.47 policy override: sensitive paths now suppress ===
		// (previously: not suppressed, sent to LLM for sensitive-path classification)
		// Failed = failed. Probe intelligence preserved via Verdict: "recon" findings,
		// not by surfacing as orange/alert on main dashboard.
		{
			name:       ".env probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/.env" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /.env HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       ".env probe failed — suppress (policy override)",
		},
		{
			name:       ".git probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/.git/config" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /.git/config HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       ".git probe failed — suppress (policy override)",
		},
		{
			name:       "containers/json Docker API probe",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/containers/json" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /containers/json HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "containers/json probe failed — suppress (policy override)",
		},
		{
			name:       "ThinkPHP exploit with attack payload",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/index.php" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "POST /index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "attack payload + failed status — still a failed probe (policy override)",
		},
		{
			name:       "path traversal — failed probe",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/something" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /../../etc/passwd HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "path traversal in failed request — suppress (policy override)",
		},
		{
			name:       "wp-admin probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/wp-admin/setup-config.php" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /wp-admin/setup-config.php HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "wp-admin probe failed — suppress (policy override)",
		},
		{
			name:       "actuator probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/actuator/health" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /actuator/health HTTP/1.1", host: "example.com"`,
			suppress:   true,
			desc:       "actuator probe failed — suppress (policy override)",
		},
		// === Non-matching lines ===
		{
			name:       "permission denied — NOT file not found",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/secret" failed (13: Permission denied), client: <CLIENT>, server: _, request: "GET /secret HTTP/1.1"`,
			suppress:   false,
			desc:       "Permission denied is not 'file not found' — regex doesn't match",
		},
		{
			name:       "not an nginx error line",
			normalized: `api.example.com GET /some/path HTTP/2.0 200`,
			suppress:   false,
			desc:       "access log with 200 — not a failed probe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, suppressed := isFailedProbe(tt.normalized)
			if suppressed != tt.suppress {
				t.Errorf("%s\nsuppressed=%v (want %v)\nreason=%s\nline=%s",
					tt.desc, suppressed, tt.suppress, reason, tt.normalized)
			}
		})
	}
}

func TestIsFailedProbe_AccessLogFormat(t *testing.T) {
	tests := []struct {
		name       string
		normalized string
		suppress   bool
	}{
		// Suppressed: clean probe + failed status
		{"clean 404", `api.example.com GET /nonexistent HTTP/2.0 404`, true},
		{"clean 405", `api.example.com GET /something HTTP/2.0 405`, true},
		{"clean 400", `api.example.com GET /bad HTTP/2.0 400`, true},
		{"clean 410", `api.example.com GET /gone HTTP/2.0 410`, true},
		{"bare format 404", `GET /random.php HTTP/1.1 404`, true},

		// NOT suppressed: successful response
		{"200 OK", `api.example.com GET /page HTTP/2.0 200`, false},
		{"301 redirect", `api.example.com GET /old HTTP/2.0 301`, false},
		{"500 error", `api.example.com GET /broken HTTP/2.0 500`, false},

		// NOT suppressed: 401 surface discovery (endpoint exists + auth required)
		{"401 auth required", `api.example.com GET /admin HTTP/2.0 401`, false},

		// SUPPRESSED: failed-status probes regardless of payload shape
		// (v0.47 policy override of v0.16 March 24 decision — failed = failed,
		// no escapes for sensitive paths or attack indicators on failed probes)
		{"SQL injection 404", `api.example.com GET /?q=UNION+SELECT+1,2,3 HTTP/2.0 404`, true},
		{"path traversal 404", `api.example.com GET /../../etc/passwd HTTP/2.0 404`, true},
		{"XSS 404", `api.example.com GET /?x=<script>alert(1)</script> HTTP/2.0 404`, true},
		{"command injection 404", `api.example.com GET /;ls+-la HTTP/2.0 404`, true},
		{"PHP wrapper 404", `api.example.com GET /?f=php://filter/convert.base64-encode HTTP/2.0 404`, true},
		{"TP-Link CVE 404", `api.example.com GET /cgi-bin/luci/;stok=/locale?form=country&op=$(wget|sh) HTTP/2.0 404`, true},

		// SUPPRESSED: sensitive paths on failed probes (policy override)
		{".env 404", `api.example.com GET /.env HTTP/2.0 404`, true},
		{".git 404", `api.example.com GET /.git/HEAD HTTP/2.0 404`, true},
		{"wp-login 404", `api.example.com GET /wp-login.php HTTP/2.0 404`, true},
		{"actuator 403", `api.example.com GET /actuator/env HTTP/2.0 403`, true},
		{"phpinfo 404", `api.example.com GET /phpinfo.php HTTP/2.0 404`, true},
		{"containers/json 404", `api.example.com GET /containers/json HTTP/2.0 404`, true},

		// EXCEPTION: high-risk disclosure indicators STILL bypass suppression
		// (the disclosure means the line contains evidence of leakage,
		// regardless of failed status)
		{"404 with etc/passwd content", `api.example.com GET /random HTTP/2.0 404 root:x:0:0:root:/root:/bin/bash`, false},
		{"404 with private key content", `api.example.com GET /random HTTP/2.0 404 -----BEGIN RSA PRIVATE KEY-----`, false},
		{"404 with AWS secret content", `api.example.com GET /random HTTP/2.0 404 AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, suppressed := isFailedProbe(tt.normalized)
			if suppressed != tt.suppress {
				t.Errorf("suppressed=%v (want %v) for line: %s", suppressed, tt.suppress, tt.normalized)
			}
		})
	}
}

// =============================================================================
// isOperationalNoise Tests
// =============================================================================

func TestIsOperationalNoise(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		isNoise bool
	}{
		// Node.js stack frames
		{"node stack frame with spaces", "    at handleDocumentRequest (/app/node_modules/@remix-run/server-runtime/dist/server.js:275:35)", true},
		{"node stack frame with tab", "\tat Object.requestHandler (/app/node_modules/thing.js:12:5)", true},
		{"node async stack frame", "    at async Object.requestHandler (/app/node_modules/express/lib/router/layer.js:95:5)", true},

		// With Docker timestamp prefix
		{"docker ts + node frame", "2026-03-25T13:45:30.123456Z     at handleDocumentRequest (/app/server.js:275:35)", true},

		// Python tracebacks
		{"python traceback header", "Traceback (most recent call last):", true},
		{"python file line", `File "/app/main.py", line 42, in handle`, true},

		// Go panics
		{"go goroutine line", "goroutine 1 [running]:", true},

		// Java
		{"java stack frame", "at com.example.MyClass.method(MyClass.java:42)", true},
		{"java caused by", "Caused by: java.lang.NullPointerException", true},

		// NOT noise
		{"normal log line", "2026/03/25 13:45:30 [info] Server started on :8080", false},
		{"http access log", `172.17.0.1 - - [25/Mar/2026:13:45:30 +0000] "GET / HTTP/1.1" 200 612`, false},
		{"word 'at' in normal log", "Looking at the database connection pool", false},
		{"empty line", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isOperationalNoise(tt.line)
			if got != tt.isNoise {
				t.Errorf("isOperationalNoise=%v (want %v) for: %s", got, tt.isNoise, tt.line)
			}
		})
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestHasAttackIndicators(t *testing.T) {
	tests := []struct {
		request string
		want    bool
	}{
		{"GET /normal/path HTTP/1.1", false},
		{"GET /?q=UNION+SELECT+1,2,3 HTTP/1.1", true},
		{"GET /../../etc/passwd HTTP/1.1", true},
		{"GET /?x=<script>alert(1)</script> HTTP/1.1", true},
		{"GET /;ls+-la HTTP/1.1", true},
		{"GET /?f=php://filter HTTP/1.1", true},
		{"GET /page?id=1;DROP+TABLE HTTP/1.1", true},
		{"POST /login?cmd=eval(something) HTTP/1.1", true},
		// Case insensitive
		{"GET /?q=union+select HTTP/1.1", true},
	}
	for _, tt := range tests {
		got := hasAttackIndicators(tt.request)
		if got != tt.want {
			t.Errorf("hasAttackIndicators(%q)=%v want %v", tt.request, got, tt.want)
		}
	}
}

func TestHasSensitivePath(t *testing.T) {
	tests := []struct {
		request string
		want    bool
	}{
		{"GET /normal/path HTTP/1.1", false},
		{"GET /random.php HTTP/1.1", false},
		{"GET /vendor/phpunit/eval-stdin.php HTTP/1.1", false},
		// Sensitive paths
		{"GET /.env HTTP/1.1", true},
		{"GET /.git/config HTTP/1.1", true},
		{"GET /.git/HEAD HTTP/1.1", true},
		{"GET /wp-admin/setup.php HTTP/1.1", true},
		{"GET /wp-login.php HTTP/1.1", true},
		{"GET /actuator/health HTTP/1.1", true},
		{"GET /actuator/env HTTP/1.1", true},
		{"GET /phpinfo.php HTTP/1.1", true},
		{"GET /server-status HTTP/1.1", true},
		{"GET /.aws/credentials HTTP/1.1", true},
		{"GET /containers/json HTTP/1.1", true},
		// Case insensitive
		{"GET /.ENV HTTP/1.1", true},
		{"GET /WP-ADMIN/install.php HTTP/1.1", true},
	}
	for _, tt := range tests {
		got := hasSensitivePath(tt.request)
		if got != tt.want {
			t.Errorf("hasSensitivePath(%q)=%v want %v", tt.request, got, tt.want)
		}
	}
}

// =============================================================================
// v0.47 — Structural HTTP Parser (the design review ZD#1)
// =============================================================================

func TestParseHTTPIdentity_StandardFormats(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		wantMethod     string
		wantPath       string
		wantStatusCode string
	}{
		// Format 1: hostname-prefixed (CapRover nginx normalizer)
		{
			name:           "format1 hosted standard",
			line:           `api.example.com GET /users HTTP/2.0 200`,
			wantMethod:     "GET",
			wantPath:       "/users",
			wantStatusCode: "200",
		},
		{
			name:           "format1 hosted with query",
			line:           `api.example.com POST /login?next=/dashboard HTTP/2.0 302`,
			wantMethod:     "POST",
			wantPath:       "/login?next=/dashboard",
			wantStatusCode: "302",
		},
		// Format 2: quoted request line (generic normalizer)
		{
			name:           "format2 quoted standard",
			line:           `<IP> - - [<TS>] "GET /api/users HTTP/1.1" 200 <NUM>`,
			wantMethod:     "GET",
			wantPath:       "/api/users",
			wantStatusCode: "200",
		},
		{
			name:           "format2 quoted 404",
			line:           `<IP> - - [<TS>] "POST /missing HTTP/1.0" 404 <NUM>`,
			wantMethod:     "POST",
			wantPath:       "/missing",
			wantStatusCode: "404",
		},
		// Format 3: bare
		{
			name:           "format3 bare",
			line:           `GET /index.html HTTP/1.1 200`,
			wantMethod:     "GET",
			wantPath:       "/index.html",
			wantStatusCode: "200",
		},
		// Non-matches
		{
			name:           "empty line",
			line:           ``,
			wantMethod:     "",
			wantPath:       "",
			wantStatusCode: "",
		},
		{
			name:           "non-HTTP log line",
			line:           `2026-05-04T12:00:00Z [info] worker started pid=1234`,
			wantMethod:     "",
			wantPath:       "",
			wantStatusCode: "",
		},
		{
			name:           "stack frame",
			line:           `    at handleRequest (/app/server.js:42:5)`,
			wantMethod:     "",
			wantPath:       "",
			wantStatusCode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, path, status := parseHTTPIdentity(tt.line)
			if method != tt.wantMethod || path != tt.wantPath || status != tt.wantStatusCode {
				t.Errorf("parseHTTPIdentity(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.line, method, path, status, tt.wantMethod, tt.wantPath, tt.wantStatusCode)
			}
		})
	}
}

// TestParseHTTPIdentity_SpoofingDefense — attacker-controlled content in the
// path must not trick the parser into reporting a fake status. The OLD loose
// `HTTP/\S+\s+(\d{3})` regex would match the first "HTTP/X NNN" anywhere in
// the line. The structural parser anchors to ^ (Format 1, 3) or to the literal
// closing quote of the HTTP version (Format 2), so injected mid-path content
// either parses correctly or fails entirely (zero values, no false match).
func TestParseHTTPIdentity_SpoofingDefense(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		wantStatusCode string
		// note: we do NOT require any particular method/path on spoofing
		// rejections — the parser may return zero values entirely. We only
		// require that when it DOES return a status, it is the structurally
		// correct one (the actual response status), never a spoofed one.
	}{
		{
			name: "bare format with HTTP-shaped string in path",
			// Path consumes /api/lookup?ref=HTTP/1.1+404 greedily up to whitespace;
			// HTTP/<version> + status anchor catches the REAL 200 at end of line,
			// not the injected 404. OLD loose regex would have matched 404.
			line:           `GET /api/lookup?ref=HTTP/1.1+404 HTTP/1.1 200`,
			wantStatusCode: "200",
		},
		{
			name: "format1 with HTTP-shaped param",
			// Path contains "HTTP/1.1+404" but real status is 200 at end.
			// Format 1 is anchored ^, so path consumes via \S+ until whitespace,
			// then HTTP/<version> + status must follow. Robust.
			line:           `api.example.com GET /api?fake=HTTP/1.1+404 HTTP/2.0 200`,
			wantStatusCode: "200",
		},
		{
			name: "quoted format with HTTP-shaped param",
			// Path contains "HTTP/1.1+404" inside quotes; real status 200
			// after closing quote. The closing quote anchor makes this safe.
			line:           `1.2.3.4 - - [date] "GET /api?fake=HTTP/1.1+404 HTTP/1.1" 200 1234`,
			wantStatusCode: "200",
		},
		{
			name: "malformed application log with HTTP-shaped phrase",
			// Application log mentions "HTTP/1.1 404" in prose. OLD loose regex
			// would have matched and suppressed; structural parser fails to
			// anchor on any of Format 1/2/3 and returns zero values.
			line:           `[WARN] upstream service returned HTTP/1.1 404 — falling back`,
			wantStatusCode: "",
		},
		{
			name: "syslog with HTTP-shaped phrase",
			// System logs that happen to discuss HTTP statuses must not be
			// parsed as HTTP access logs. The METHOD/^ anchors prevent it.
			line:           `Mar 25 13:45:30 host service[123]: probe got HTTP/1.1 200 from origin`,
			wantStatusCode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, status := parseHTTPIdentity(tt.line)
			if status != tt.wantStatusCode {
				t.Errorf("parseHTTPIdentity(%q) status = %q, want %q (parser must not be tricked into reporting injected status)",
					tt.line, status, tt.wantStatusCode)
			}
		})
	}
}

// TestIsFailedProbe_RegexSpoofingDefense — end-to-end regression that
// the design review's spoofing attack class cannot trick the deterministic suppression
// gate into suppressing a successful exploit (HTTP 200 with attack payload).
//
// Critical safety property: a real 200 response with attack content in the
// URL must NEVER be suppressed by the failed-probe gate, even if the URL
// contains "HTTP/X NNN"-shaped strings that the OLD loose regex would have
// false-matched as a failed status.
func TestIsFailedProbe_RegexSpoofingDefense(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		suppress bool
		desc     string
	}{
		{
			name:     "200 with HTTP-shaped param — must not suppress",
			line:     `api.example.com GET /api?fake=HTTP/1.1+404 HTTP/2.0 200`,
			suppress: false,
			desc:     "OLD loose regex would have matched the injected 404 and suppressed; structural parser sees the real 200 status",
		},
		{
			name:     "quoted 200 with HTTP-shaped param — must not suppress",
			line:     `1.2.3.4 - - [date] "GET /api?fake=HTTP/1.1+404 HTTP/1.1" 200 1234`,
			suppress: false,
			desc:     "Format 2 with closing-quote anchor must read real status 200, not injected 404",
		},
		{
			name:     "bare format with HTTP-shaped param — must not suppress",
			line:     `GET /api?ref=HTTP/1.1+404 HTTP/1.1 200`,
			suppress: false,
			desc:     "Bare format anchored to ^ — path consumed greedily up to whitespace, real status 200 read structurally; OLD loose regex would have matched injected 404",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, suppressed := isFailedProbe(tt.line)
			if suppressed != tt.suppress {
				t.Errorf("%s\nsuppressed=%v (want %v)\nreason=%s\nline=%s",
					tt.desc, suppressed, tt.suppress, reason, tt.line)
			}
		})
	}
}

// =============================================================================
// v0.47 — URL-Decoded Attack Indicators (code review F6)
// =============================================================================

func TestHasAttackIndicators_URLEncoded(t *testing.T) {
	tests := []struct {
		name    string
		request string
		want    bool
	}{
		// === Single URL-encoded payloads ===
		{
			name:    "encoded path traversal %2e%2e%2f",
			request: "GET /files?p=%2e%2e%2fetc%2fpasswd HTTP/1.1",
			want:    true,
		},
		{
			name:    "encoded XSS %3cscript%3e",
			request: "GET /search?q=%3cscript%3ealert(1)%3c/script%3e HTTP/1.1",
			want:    true,
		},
		{
			name:    "encoded php wrapper php%3a%2f%2f",
			request: "GET /?f=php%3a%2f%2ffilter HTTP/1.1",
			want:    true,
		},
		{
			name:    "encoded command injection %3bcat",
			request: "GET /tools?cmd=ls%3bcat+/etc/passwd HTTP/1.1",
			want:    true,
		},

		// === Double URL-encoded payloads ===
		{
			name:    "double-encoded path traversal %252e%252e%252f",
			request: "GET /files?p=%252e%252e%252fetc%252fpasswd HTTP/1.1",
			want:    true,
		},
		{
			name:    "double-encoded XSS %253cscript%253e",
			request: "GET /search?q=%253cscript%253e HTTP/1.1",
			want:    true,
		},

		// === Negative: benign URL-encoded content ===
		{
			name:    "benign URL-encoded space",
			request: "GET /search?q=hello%20world HTTP/1.1",
			want:    false,
		},
		{
			name:    "benign URL-encoded plus",
			request: "GET /search?q=hello%2bworld HTTP/1.1",
			want:    false,
		},
		{
			name:    "benign UTF-8 encoded character",
			request: "GET /search?q=%E2%9C%93 HTTP/1.1",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAttackIndicators(tt.request)
			if got != tt.want {
				t.Errorf("hasAttackIndicators(%q) = %v, want %v", tt.request, got, tt.want)
			}
		})
	}
}

// =============================================================================
// v0.47 — High-Risk Disclosure Detection (code review F5)
// =============================================================================

// TestContainsHighRiskDisclosure validates the helper directly.
func TestContainsHighRiskDisclosure(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		// === Positive: known disclosure strings ===
		{"etc passwd line", "root:x:0:0:root:/root:/bin/bash", true},
		{"RSA private key header", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"OpenSSH private key header", "-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"EC private key header", "-----BEGIN EC PRIVATE KEY-----", true},
		{"generic private key header", "-----BEGIN PRIVATE KEY-----", true},
		{"AWS env var leak", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},
		{"id command output uid=0", "uid=0(root) gid=0(root) groups=0(root)", true},

		// === Positive: disclosure embedded in stack-trace-shaped lines ===
		{
			name: "java caused-by wrapping etc/passwd content",
			line: "Caused by: java.io.IOException: Read file: root:x:0:0:root:/root:/bin/bash",
			want: true,
		},
		{
			name: "node stack frame wrapping private key",
			line: "    at FileReader.read (/app/index.js:42:7) -----BEGIN RSA PRIVATE KEY-----",
			want: true,
		},

		// === Negative: ordinary log content must NOT trigger ===
		{"normal log line", "2026-05-04T12:00:00Z worker started", false},
		{"java NPE", "Caused by: java.lang.NullPointerException", false},
		{"node stack frame benign", "    at handleRequest (/app/index.js:42:7)", false},
		{"http access log", `"GET /api/users HTTP/1.1" 200 1234`, false},
		{"empty line", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsHighRiskDisclosure(tt.line)
			if got != tt.want {
				t.Errorf("containsHighRiskDisclosure(%q) = %v, want %v", tt.line, got, tt.want)
			}
		})
	}
}

// TestIsOperationalNoise_HighRiskDisclosureOverride validates that lines
// containing high-risk disclosure strings are NEVER suppressed as operational
// noise, even when the line shape (e.g., "Caused by: ", stack frames) would
// normally classify as noise.
//
// Both directions matter:
//   - Positive: malicious content wrapped in noise-shaped line → NOT noise
//     (so it proceeds to malicious-seed match and LLM)
//   - Negative: ordinary noise-shaped lines (no disclosure) → STILL noise
//     (so the operational-noise filter keeps doing its job)
func TestIsOperationalNoise_HighRiskDisclosureOverride(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		isNoise bool
	}{
		// === Positive: disclosure escapes the noise filter ===
		{
			name:    "caused-by wrapping etc passwd content",
			line:    "Caused by: java.io.IOException: Read failed: root:x:0:0:root:/root:/bin/bash",
			isNoise: false,
		},
		{
			name:    "java stack frame wrapping private key",
			line:    "\tat FileSystemService.read(FileSystemService.java:88) -----BEGIN RSA PRIVATE KEY-----",
			isNoise: false,
		},
		{
			name:    "node stack frame leaking AWS secret",
			line:    "    at AwsClient.send (/app/aws.js:42:7) AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI",
			isNoise: false,
		},
		{
			name:    "python traceback wrapping uid=0(root)",
			line:    "Traceback (most recent call last): ...command produced uid=0(root)",
			isNoise: false,
		},

		// === Negative: ordinary noise-shaped lines still suppressed ===
		{
			name:    "java NPE caused-by — still noise",
			line:    "Caused by: java.lang.NullPointerException at line 42",
			isNoise: true,
		},
		{
			name:    "node stack frame benign — still noise",
			line:    "    at handleRequest (/app/index.js:42:7)",
			isNoise: true,
		},
		{
			name:    "java stack frame benign — still noise",
			line:    "\tat com.example.Service.handle(Service.java:88)",
			isNoise: true,
		},
		{
			name:    "python traceback header — still noise",
			line:    "Traceback (most recent call last):",
			isNoise: true,
		},
		{
			name:    "go panic line — still noise",
			line:    "goroutine 1 [running]:",
			isNoise: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isOperationalNoise(tt.line)
			if got != tt.isNoise {
				t.Errorf("isOperationalNoise(%q) = %v, want %v", tt.line, got, tt.isNoise)
			}
		})
	}
}

// TestIsFailedProbe_HighRiskDisclosureOverride validates that lines containing
// high-risk disclosure strings are NEVER suppressed as failed probes, even
// when the line embeds a quoted request shape with a failed status code.
//
// This guards the same semantic rule as the noise-filter override —
// "high-risk disclosure bypasses all deterministic suppression" — at the
// SECOND deterministic gate. code review's catch: without this guard, a line
// like:
//
//	`ERROR dumped root:x:0:0:root "GET /random HTTP/1.1" 404`
//
// would survive the noise filter (no stack-trace shape) but get suppressed
// by isFailedProbe (parses the embedded 404 + clean path). The disclosure
// would never reach the malicious seeds.
//
// Production guard lives at the Analyze() orchestration layer; this test
// also exercises the function-level safety check inside isFailedProbe to
// ensure defense-in-depth.
func TestIsFailedProbe_HighRiskDisclosureOverride(t *testing.T) {
	tests := []struct {
		name string
		line string
		// suppress=true means isFailedProbe says "deterministic suppress"
		// — which would be WRONG for any of these disclosure-bearing lines.
		// All entries below set suppress=false.
		suppress bool
	}{
		// === Positive: disclosure embedded in failed-probe-shaped line ===
		{
			name:     "etc passwd content + quoted 404",
			line:     `ERROR dumped root:x:0:0:root "GET /random HTTP/1.1" 404`,
			suppress: false,
		},
		{
			name:     "private key + quoted 404",
			line:     `Caused by: IOException: -----BEGIN RSA PRIVATE KEY----- "GET /x HTTP/1.1" 404`,
			suppress: false,
		},
		{
			name:     "AWS secret leak + quoted 404",
			line:     `worker output AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG "GET /missing HTTP/1.1" 404`,
			suppress: false,
		},
		{
			name:     "uid=0 output + quoted 403",
			line:     `command output uid=0(root) gid=0(root) "GET /admin HTTP/1.1" 403`,
			suppress: false,
		},

		// === Negative: ordinary failed probe (no disclosure) — still suppressed ===
		{
			name:     "ordinary clean 404 — still suppressed",
			line:     `1.2.3.4 - - [date] "GET /random HTTP/1.1" 404 0`,
			suppress: true,
		},
		{
			name:     "ordinary clean 403 — still suppressed",
			line:     `api.example.com GET /forbidden HTTP/2.0 403`,
			suppress: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, suppressed := isFailedProbe(tt.line)
			if suppressed != tt.suppress {
				t.Errorf("isFailedProbe(%q) suppressed=%v, want %v (reason=%q)",
					tt.line, suppressed, tt.suppress, reason)
			}
		})
	}
}

// =============================================================================
// v0.47 — Forgiving URL Decode (the design review adversarial review of F6)
// =============================================================================

// TestForgivingURLDecode validates that the byte-level decoder tolerates
// malformed percent-escapes, where the stdlib url.QueryUnescape would
// fail the entire string.
func TestForgivingURLDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Valid encoded forms decode correctly
		{"empty", "", ""},
		{"no encoding", "/api/users", "/api/users"},
		{"single triplet", "%2e%2e%2f", "../"},
		{"plus to space", "hello+world", "hello world"},
		{"mixed", "a+b%2cc", "a b,c"},

		// Malformed forms — pass through, do NOT discard the rest
		{"trailing %zz", "%3cscript%3e&garbage=%zz", "<script>&garbage=%zz"},
		{"leading %zz", "%zz%3cscript%3e", "%zz<script>"},
		{"middle %zz", "before%zzafter", "before%zzafter"},
		{"lone percent at end", "abc%", "abc%"},
		{"non-hex after percent", "abc%zzdef", "abc%zzdef"},
		{"truncated triplet", "abc%2", "abc%2"},

		// Hex case insensitive
		{"lowercase hex", "%2f", "/"},
		{"uppercase hex", "%2F", "/"},
		{"mixed case hex", "%2f%2F", "//"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := forgivingURLDecode(tt.input)
			if got != tt.want {
				t.Errorf("forgivingURLDecode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestHasAttackIndicators_MalformedDecodeBypass — the design review's bonus zero-day.
// An encoded payload paired with a malformed percent-triplet elsewhere in
// the string would cause stdlib url.QueryUnescape to error out and leave
// the encoded payload undetected. The forgiving decoder must catch it.
func TestHasAttackIndicators_MalformedDecodeBypass(t *testing.T) {
	tests := []struct {
		name    string
		request string
		want    bool
	}{
		{
			name:    "encoded XSS with trailing malformed escape",
			request: "/search?q=%3Cscript%3E&garbage=%zz",
			want:    true,
		},
		{
			name:    "encoded traversal with leading malformed escape",
			request: "/files?p=%zz&path=%2e%2e%2fetc%2fpasswd",
			want:    true,
		},
		{
			name:    "double-encoded XSS with malformed segment",
			request: "/search?q=%253Cscript%253E&debug=%zz",
			want:    true,
		},
		{
			name:    "benign request with malformed escape — must NOT trigger",
			request: "/search?q=hello+world&debug=%zz",
			want:    false,
		},
		{
			name:    "benign UTF-8 + malformed escape — must NOT trigger",
			request: "/search?q=%E2%9C%93&debug=%xx",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasAttackIndicators(tt.request)
			if got != tt.want {
				t.Errorf("hasAttackIndicators(%q) = %v, want %v", tt.request, got, tt.want)
			}
		})
	}
}

// =============================================================================
// v0.47 — Disclosure Learning Guard (code review third-iteration review)
// =============================================================================

// TestLearnFromVerdict_DisclosureRefusal validates that learnFromVerdict
// refuses to create new suppress/allow cache entries when the line contains
// a high-risk disclosure string. Completes the three-layer disclosure rule:
//
//  1. Disclosure bypasses deterministic gates       (TestIsOperationalNoise / TestIsFailedProbe)
//  2. Disclosure bypasses cached suppress/allow     (orchestration override in Analyze)
//  3. Disclosure cannot CREATE new suppress/allow   (this test)
//
// Without this guard, an LLM that hallucinates suppress/allow on a disclosure
// line would pollute the pattern store, causing repeated DISCLOSURE_OVERRIDE
// churn on every recurrence (correct security outcome, wasteful operationally).
//
// Note: this is a unit test of the guard's input shape. We don't construct a
// full Analyzer here — we use the helper directly because that's where the
// rule lives. Integration testing happens in real soak.
func TestContainsHighRiskDisclosure_LearnGuardInputs(t *testing.T) {
	// These are the line shapes that learnFromVerdict will refuse on
	// when paired with action=suppress or action=allow at confidence>=0.70.
	disclosureLines := []string{
		"Caused by: java.io.IOException: leaked content root:x:0:0:root:/root:/bin/bash",
		"-----BEGIN RSA PRIVATE KEY----- (output line)",
		"env dump: AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",
		"shell: uid=0(root) gid=0(root) groups=0(root)",
	}
	benignLines := []string{
		`api.example.com GET /users HTTP/2.0 200`,
		`Caused by: java.lang.NullPointerException at line 42`,
		`worker started with pid=1234`,
	}

	for _, line := range disclosureLines {
		if !containsHighRiskDisclosure(line) {
			t.Errorf("expected disclosure detection on: %q", line)
		}
	}
	for _, line := range benignLines {
		if containsHighRiskDisclosure(line) {
			t.Errorf("false-positive disclosure detection on: %q", line)
		}
	}
}
