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
		// === SAFETY: These should NOT be suppressed ===
		{
			name:       ".env probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/.env" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /.env HTTP/1.1", host: "example.com"`,
			suppress:   false,
			desc:       "SAFETY: .env is a sensitive path — always report",
		},
		{
			name:       ".git probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/.git/config" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /.git/config HTTP/1.1", host: "example.com"`,
			suppress:   false,
			desc:       "SAFETY: .git is a sensitive path — always report",
		},
		{
			name:       "containers/json Docker API probe",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/containers/json" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /containers/json HTTP/1.1", host: "example.com"`,
			suppress:   false,
			desc:       "SAFETY: Docker API probe — sensitive path",
		},
		{
			name:       "ThinkPHP exploit with path traversal",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/index.php" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "POST /index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id HTTP/1.1", host: "example.com"`,
			suppress:   false,
			desc:       "SAFETY: attack payload in query string (system(, call_user_func)",
		},
		{
			name:       "path traversal in request",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/something" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /../../etc/passwd HTTP/1.1", host: "example.com"`,
			suppress:   false,
			desc:       "SAFETY: path traversal in request",
		},
		{
			name:       "wp-admin probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/wp-admin/setup-config.php" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /wp-admin/setup-config.php HTTP/1.1", host: "example.com"`,
			suppress:   false,
			desc:       "SAFETY: wp-admin is sensitive",
		},
		{
			name:       "actuator probe — sensitive path",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/actuator/health" failed (2: No such file or directory), client: <CLIENT>, server: _, request: "GET /actuator/health HTTP/1.1", host: "example.com"`,
			suppress:   false,
			desc:       "SAFETY: Spring actuator is sensitive",
		},
		// === Non-matching lines ===
		{
			name:       "permission denied — NOT file not found",
			normalized: `[error] <PID>: *<CONN> open() "/usr/share/nginx/default/secret" failed (13: Permission denied), client: <CLIENT>, server: _, request: "GET /secret HTTP/1.1"`,
			suppress:   false,
			desc:       "Permission denied is not 'file not found' — don't match",
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

		// NOT suppressed: 401 surface discovery
		{"401 auth required", `api.example.com GET /admin HTTP/2.0 401`, false},

		// NOT suppressed: attack payload in request
		{"SQL injection 404", `api.example.com GET /?q=UNION+SELECT+1,2,3 HTTP/2.0 404`, false},
		{"path traversal 404", `api.example.com GET /../../etc/passwd HTTP/2.0 404`, false},
		{"XSS 404", `api.example.com GET /?x=<script>alert(1)</script> HTTP/2.0 404`, false},
		{"command injection 404", `api.example.com GET /;ls+-la HTTP/2.0 404`, false},
		{"PHP wrapper 404", `api.example.com GET /?f=php://filter/convert.base64-encode HTTP/2.0 404`, false},

		// NOT suppressed: sensitive path
		{".env 404", `api.example.com GET /.env HTTP/2.0 404`, false},
		{".git 404", `api.example.com GET /.git/HEAD HTTP/2.0 404`, false},
		{"wp-login 404", `api.example.com GET /wp-login.php HTTP/2.0 404`, false},
		{"actuator 403", `api.example.com GET /actuator/env HTTP/2.0 403`, false},
		{"phpinfo 404", `api.example.com GET /phpinfo.php HTTP/2.0 404`, false},
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