// internal/normalizer/shapeprofile_test.go
package normalizer

import (
	"strings"
	"testing"

	"github.com/vaultguardian/observer/internal/event"
)

// Shape-profile tests.
//
// A shape profile is a DECLARED log grammar, selected only because the
// operator named it in NORMALIZER_HINTS_JSON. http-combined-v1 is strict:
// a line either satisfies the full combined-access-log grammar or the
// profile declines and the line falls through to the normal Lookup chain
// unchanged. Declining is always safe; mis-parsing is not.
//
// Accepted grammar (decided with the operator, see round-1 plan):
//
//	client ident user [timestamp] "request" status bytes "referer" "user-agent"
//	client ident user [timestamp] "request" status bytes "referer" "user-agent" "xff"
//
// The 4-field form is nginx's $http_x_forwarded_for extension and is what
// every access line in this repo's corpus actually looks like. Anything
// else - including the 5-field CapRover vhost variant - declines.

// spNormalize runs a line through a named profile directly, bypassing the
// registry. The line is assumed already stripped of collector framing and
// the vgrid lineage token, exactly as Registry.NormalizeEvent delivers it.
func spNormalize(t *testing.T, profileName, line string) (string, bool) {
	t.Helper()
	p, ok := LookupProfile(profileName)
	if !ok {
		t.Fatalf("LookupProfile(%q) returned !ok; valid profiles: %v", profileName, ProfileNames())
	}
	return p.Normalize(line)
}

func TestShapeProfileRegistration(t *testing.T) {
	t.Run("http-combined-v1 is registered", func(t *testing.T) {
		p, ok := LookupProfile(ProfileHTTPCombinedV1)
		if !ok {
			t.Fatalf("LookupProfile(%q) returned !ok", ProfileHTTPCombinedV1)
		}
		if p.Name() != ProfileHTTPCombinedV1 {
			t.Errorf("Name() = %q, want %q", p.Name(), ProfileHTTPCombinedV1)
		}
	})

	t.Run("constant matches the documented name", func(t *testing.T) {
		// docs/configuration.md documents this exact string. If the constant
		// ever changes, the docs and every operator's env file break.
		if ProfileHTTPCombinedV1 != "http-combined-v1" {
			t.Errorf("ProfileHTTPCombinedV1 = %q, want %q", ProfileHTTPCombinedV1, "http-combined-v1")
		}
	})

	t.Run("unknown profile name is not registered", func(t *testing.T) {
		for _, name := range []string{"", "http-combined", "http-combined-v2", "nginx", "HTTP-COMBINED-V1"} {
			if _, ok := LookupProfile(name); ok {
				t.Errorf("LookupProfile(%q) returned ok, want !ok", name)
			}
		}
	})

	t.Run("ProfileNames is exactly the shipped set, sorted", func(t *testing.T) {
		got := ProfileNames()
		want := []string{"http-combined-v1"}
		if len(got) != len(want) {
			t.Fatalf("ProfileNames() = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ProfileNames() = %v, want %v", got, want)
			}
		}
	})
}

// TestHTTPCombinedV1Preservation asserts that for lines the profile accepts,
// the normalized form keeps method, path and status and drops client IP,
// identd/user, bracket timestamp, byte count, referrer and user-agent.
func TestHTTPCombinedV1Preservation(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "canonical combined, three quoted fields",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
			want: `GET /a/b?c=1 HTTP/1.1 200`,
		},
		{
			name: "combined plus x-forwarded-for, four quoted fields",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
			want: `GET /a/b?c=1 HTTP/1.1 200`,
		},
		{
			// The soak box emits both protocol versions: the edge logs
			// HTTP/2.0 while the backend twin logs HTTP/1.1.
			name: "HTTP/2.0 request line",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/2.0" 200 896 "-" "curl/8.5.0" "-"`,
			want: `GET /a/b?c=1 HTTP/2.0 200`,
		},
		{
			name: "real referrer is stripped",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "https://google.com/search?q=test" "curl/8.5.0"`,
			want: `GET /a/b HTTP/1.1 200`,
		},
		{
			name: "real username in the user position is stripped",
			line: `1.2.3.4 - alice [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
			want: `GET /a/b HTTP/1.1 200`,
		},
		{
			name: "real identd and username are both stripped",
			line: `1.2.3.4 identd alice [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
			want: `GET /a/b HTTP/1.1 200`,
		},
		{
			name: "dash byte count",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 - "-" "curl/8.5.0"`,
			want: `GET /a/b HTTP/1.1 200`,
		},
		{
			name: "hostname in the client position",
			line: `client.example.com - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
			want: `GET /a/b HTTP/1.1 200`,
		},
		{
			name: "IPv6 client",
			line: `2001:db8::1 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
			want: `GET /a/b HTTP/1.1 200`,
		},
		{
			name: "POST is preserved",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.5.0"`,
			want: `POST /login HTTP/1.1 302`,
		},
		{
			name: "HEAD is preserved",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "HEAD /healthz HTTP/1.1" 200 0 "-" "kube-probe/1.29"`,
			want: `HEAD /healthz HTTP/1.1 200`,
		},
		{
			name: "OPTIONS is preserved",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "OPTIONS /api HTTP/1.1" 204 0 "-" "curl/8.5.0"`,
			want: `OPTIONS /api HTTP/1.1 204`,
		},
		{
			name: "attack payload in the query string survives verbatim",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /?q=UNION+SELECT+1,2,3 HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
			want: `GET /?q=UNION+SELECT+1,2,3 HTTP/2.0 200`,
		},
		{
			name: "dotfile probe keeps its status",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /.env HTTP/2.0" 403 146 "-" "curl/8.5.0" "-"`,
			want: `GET /.env HTTP/2.0 403`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := spNormalize(t, ProfileHTTPCombinedV1, tt.line)
			if !ok {
				t.Fatalf("profile declined a line it must accept:\n  line: %s", tt.line)
			}
			if got != tt.want {
				t.Errorf("normalized mismatch\n  line: %s\n   got: %q\n  want: %q", tt.line, got, tt.want)
			}
		})
	}
}

// TestHTTPCombinedV1DropsVariableFields is the explicit negative half of
// preservation: the volatile fields must not survive into the normalized
// line, because everything here feeds the hash, the learned pattern store
// and the LLM cache key.
func TestHTTPCombinedV1DropsVariableFields(t *testing.T) {
	line := `98.152.173.124 - alice [20/Mar/2026:19:05:08 +0000] "GET /a/b?c=1 HTTP/1.1" 200 34020 "https://ref.example.com/x" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "10.0.0.7"`

	got, ok := spNormalize(t, ProfileHTTPCombinedV1, line)
	if !ok {
		t.Fatalf("profile declined a well-formed combined line: %s", line)
	}

	mustDrop := []struct {
		field    string
		fragment string
	}{
		{"client IP", "98.152.173.124"},
		{"username", "alice"},
		{"bracket timestamp", "20/Mar/2026"},
		{"bracket timestamp", "19:05:08"},
		{"timezone offset", "+0000"},
		{"byte count", "34020"},
		{"referrer", "ref.example.com"},
		{"user-agent", "Mozilla"},
		{"user-agent detail", "Win64"},
		{"x-forwarded-for", "10.0.0.7"},
	}
	for _, m := range mustDrop {
		if strings.Contains(got, m.fragment) {
			t.Errorf("%s survived normalization (%q found)\n  got: %q", m.field, m.fragment, got)
		}
	}

	mustKeep := []struct {
		field    string
		fragment string
	}{
		{"method", "GET"},
		{"path", "/a/b"},
		{"query string", "c=1"},
		{"protocol version", "HTTP/1.1"},
		{"status code", "200"},
	}
	for _, m := range mustKeep {
		if !strings.Contains(got, m.fragment) {
			t.Errorf("%s was stripped (%q missing)\n  got: %q", m.field, m.fragment, got)
		}
	}
}

// TestHTTPCombinedV1IdentdUserVariance pins the operator's decision: both the
// "- -" form and a real identd/username parse, and both strip to the SAME
// normalized line. If these diverged, one client authenticating would split
// an otherwise identical request into two hashes.
func TestHTTPCombinedV1IdentdUserVariance(t *testing.T) {
	variants := []string{
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		`1.2.3.4 - alice [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		`1.2.3.4 identd alice [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		`1.2.3.4 - bob [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
	}

	var first string
	for i, line := range variants {
		got, ok := spNormalize(t, ProfileHTTPCombinedV1, line)
		if !ok {
			t.Fatalf("variant %d declined, want accepted: %s", i, line)
		}
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Errorf("identd/user variance changed the normalized line\n  variant 0: %q\n  variant %d: %q", first, i, got)
		}
	}
}

// TestHTTPCombinedV1ProtocolVersionIsPreserved documents deliberate behavior:
// the request line is preserved whole, so HTTP/1.1 and HTTP/2.0 forms of the
// same request normalize differently. This matches NginxNormalizer exactly -
// changing it would be a normalizer behavior change, not a profile addition.
func TestHTTPCombinedV1ProtocolVersionIsPreserved(t *testing.T) {
	h1 := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /.env HTTP/1.1" 403 146 "-" "curl/8.5.0"`
	h2 := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /.env HTTP/2.0" 403 146 "-" "curl/8.5.0"`

	gotH1, ok1 := spNormalize(t, ProfileHTTPCombinedV1, h1)
	gotH2, ok2 := spNormalize(t, ProfileHTTPCombinedV1, h2)
	if !ok1 || !ok2 {
		t.Fatalf("profile declined a well-formed line (h1 ok=%v, h2 ok=%v)", ok1, ok2)
	}
	if gotH1 == gotH2 {
		t.Errorf("protocol version was flattened; want it preserved\n  got both: %q", gotH1)
	}
	if !strings.Contains(gotH1, "HTTP/1.1") || !strings.Contains(gotH2, "HTTP/2.0") {
		t.Errorf("protocol version not preserved verbatim\n  h1: %q\n  h2: %q", gotH1, gotH2)
	}
}

// TestHTTPCombinedV1DifferentAttacksDoNotCollide guards the property the
// whole pipeline rests on: distinct payloads must not share a hash.
func TestHTTPCombinedV1DifferentAttacksDoNotCollide(t *testing.T) {
	attacks := map[string]string{
		"SQL injection":     `1.2.3.4 - - [20/Mar/2026:19:05:08 +0000] "GET /?q=UNION+SELECT+1,2,3 HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
		"command injection": `1.2.3.4 - - [20/Mar/2026:19:05:09 +0000] "GET /?cmd=cat+/etc/passwd HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
		"shell injection":   `1.2.3.4 - - [20/Mar/2026:19:05:10 +0000] "GET /?page=;ls+-la HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
		"path traversal":    `1.2.3.4 - - [20/Mar/2026:19:05:11 +0000] "GET /?file=../../etc/shadow HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
		"DROP TABLE":        `1.2.3.4 - - [20/Mar/2026:19:05:11 +0000] "GET /?id=1;DROP+TABLE+users HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
		"dotfile probe":     `1.2.3.4 - - [20/Mar/2026:19:05:12 +0000] "GET /.env HTTP/2.0" 403 146 "-" "curl/8.5.0" "-"`,
		"same path 404":     `1.2.3.4 - - [20/Mar/2026:19:05:12 +0000] "GET /.env HTTP/2.0" 404 146 "-" "curl/8.5.0" "-"`,
	}

	seen := make(map[string]string, len(attacks))
	for name, line := range attacks {
		got, ok := spNormalize(t, ProfileHTTPCombinedV1, line)
		if !ok {
			t.Fatalf("profile declined %s: %s", name, line)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("COLLISION: %q and %q both normalized to %q", name, prev, got)
		}
		seen[got] = name
	}
}

// httpCombinedDeclineCases are lines the strict profile must refuse rather
// than mis-parse. Shared by the profile-level and registry-level tests so
// "declines" and "falls through unchanged" are proven over the same corpus.
func httpCombinedDeclineCases() []struct {
	name string
	line string
} {
	return []struct {
		name string
		line string
	}{
		{
			name: "backslash-escaped quote in path",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a\"b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "literal quote in path shifts field boundaries",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a"b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "user-agent contains a bracketed timestamp-shaped substring",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "Bot [18/Mar/2026:22:32:28 +0000] x"`,
		},
		{
			name: "referrer contains a bracketed timestamp-shaped substring",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "[18/Mar/2026:22:32:28 +0000]" "curl/8.5.0"`,
		},
		{
			name: "missing user-agent, only two quoted fields",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-"`,
		},
		{
			name: "missing referrer and user-agent, common log format",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896`,
		},
		{
			name: "five quoted fields, CapRover vhost variant",
			line: `1.2.3.4 - - [20/Mar/2026:19:05:08 +0000] "api.admin.kovicloud.com" "GET /a/b HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
		},
		{
			name: "nginx error-log line fed to a source hinted http-combined-v1",
			line: `2026/03/17 15:10:04 [error] 28#28: *1 open() "/usr/share/nginx/html/favicon.ico" failed`,
		},
		{
			name: "empty line",
			line: ``,
		},
		{
			name: "whitespace-only line",
			line: `   `,
		},
		{
			name: "tab-only line",
			line: "\t\t",
		},
		{
			name: "missing bracket timestamp",
			line: `1.2.3.4 - - "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "bracket timestamp is not timestamp-shaped",
			line: `1.2.3.4 - - [not-a-timestamp] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "status code is not three digits",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 20 896 "-" "curl/8.5.0"`,
		},
		{
			name: "status code is non-numeric",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" OK 896 "-" "curl/8.5.0"`,
		},
		{
			name: "byte count is non-numeric",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 many "-" "curl/8.5.0"`,
		},
		{
			name: "request line has no protocol version",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "request line has an unknown method",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "FROB /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "request line is a bare URL, no method",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "/a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "quoted field where the client IP belongs",
			line: `"1.2.3.4" - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "trailing garbage after the last quoted field",
			line: `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" trailing`,
		},
		{
			name: "leading garbage before the client field",
			line: `garbage 1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		},
		{
			name: "plain application log line",
			line: `INFO  request completed in 12ms status=200`,
		},
		{
			name: "JSON access log",
			line: `{"remote_addr":"1.2.3.4","request":"GET /a/b HTTP/1.1","status":200}`,
		},
	}
}

// TestHTTPCombinedV1Declines is the ambiguity gate. Every line here must be
// refused outright - no partial credit, no heuristics, no best-effort parse.
func TestHTTPCombinedV1Declines(t *testing.T) {
	for _, tt := range httpCombinedDeclineCases() {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := spNormalize(t, ProfileHTTPCombinedV1, tt.line)
			if ok {
				t.Errorf("profile ACCEPTED a line it must decline\n  line: %s\n   got: %q", tt.line, got)
			}
			if got != "" {
				t.Errorf("a declining profile must return an empty string, got %q", got)
			}
		})
	}
}

// TestHTTPCombinedV1DeclineFallsThroughUnchanged proves the safety property
// at registry level: when the profile declines, the line is normalized by
// exactly the normalizer Lookup would have chosen, byte for byte.
func TestHTTPCombinedV1DeclineFallsThroughUnchanged(t *testing.T) {
	hinted := phMustParse(t, `{"docker:edge":"http-combined-v1"}`)

	hintedReg := NewRegistryWithProfileHints(hinted)
	plainReg := NewRegistry()

	for _, tt := range httpCombinedDeclineCases() {
		t.Run(tt.name, func(t *testing.T) {
			gotHinted, hashHinted := phNormalize(hintedReg, "docker", "edge", tt.line)
			gotPlain, hashPlain := phNormalize(plainReg, "docker", "edge", tt.line)

			if gotHinted != gotPlain {
				t.Errorf("declined line did not fall through unchanged\n  line:   %s\n  hinted: %q\n  plain:  %q",
					tt.line, gotHinted, gotPlain)
			}
			if hashHinted != hashPlain {
				t.Errorf("declined line produced a different hash\n  line: %s", tt.line)
			}
		})
	}
}

// TestHTTPCombinedV1MatchesNginxOutput is the payoff for the whole change: a
// proxy named "edge" that the operator hints, and a container named
// "captain-nginx" that matches the nginx normalizer by name, must produce a
// byte-identical normalized line and the same hash for the same request. That
// identity is what lets the exact-hash tier catch backend twins.
func TestHTTPCombinedV1MatchesNginxOutput(t *testing.T) {
	lines := []string{
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
		`1.2.3.4 - - [20/Mar/2026:19:05:08 +0000] "GET /?q=UNION+SELECT+1,2,3 HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`,
		`1.2.3.4 - - [20/Mar/2026:19:05:12 +0000] "GET /.env HTTP/2.0" 403 146 "-" "curl/8.5.0" "-"`,
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "POST /login HTTP/1.1" 302 0 "https://ref.example.com/x" "Mozilla/5.0"`,
	}

	hintedReg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))
	plainReg := NewRegistry()

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			gotEdge, hashEdge := phNormalize(hintedReg, "docker", "edge", line)
			gotNginx, hashNginx := phNormalize(plainReg, "docker", "captain-nginx", line)

			if gotEdge != gotNginx {
				t.Errorf("hinted proxy and name-matched nginx disagree\n  line:  %s\n  edge:  %q\n  nginx: %q",
					line, gotEdge, gotNginx)
			}
			if hashEdge != hashNginx {
				t.Errorf("hinted proxy and name-matched nginx produced different hashes\n  line: %s", line)
			}
			if gotEdge == "" {
				t.Errorf("hinted proxy produced an empty normalized line for %s", line)
			}
		})
	}
}

// TestHTTPCombinedV1BackendTwinCacheHit is the concrete scenario from the
// CLAUDE.md gotcha: an nginx edge and an Apache-format backend twin logging
// the same request with DIFFERENT user-agents. Once both are hinted, the
// user-agent no longer splits the hash and the twin hits the exact-hash tier.
func TestHTTPCombinedV1BackendTwinCacheHit(t *testing.T) {
	reg := NewRegistryWithProfileHints(phMustParse(t,
		`{"docker:edge":"http-combined-v1","docker:wp":"http-combined-v1"}`))

	edgeLine := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /.env HTTP/1.1" 403 146 "-" "curl/8.5.0" "-"`
	backendLine := `10.0.0.7 - - [18/Mar/2026:22:32:29 +0000] "GET /.env HTTP/1.1" 403 291 "-" "Mozilla/5.0 (X11; Linux x86_64)"`

	_, edgeHash := phNormalize(reg, "docker", "edge", edgeLine)
	_, backendHash := phNormalize(reg, "docker", "wp", backendLine)

	if edgeHash != backendHash {
		gotEdge, _ := phNormalize(reg, "docker", "edge", edgeLine)
		gotBackend, _ := phNormalize(reg, "docker", "wp", backendLine)
		t.Errorf("backend twin missed the exact-hash tier\n  edge:    %q\n  backend: %q", gotEdge, gotBackend)
	}
}

// TestHTTPCombinedV1IsStableAcrossVolatileFields restates the core normalizer
// contract for the profile: lines differing only in volatile fields must
// share one hash.
func TestHTTPCombinedV1IsStableAcrossVolatileFields(t *testing.T) {
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))

	lines := []string{
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		`10.0.0.5 - - [19/Mar/2026:01:00:00 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		`1.2.3.4 - - [18/Mar/2026:22:33:17 +0000] "GET /a/b HTTP/1.1" 200 1024 "-" "curl/8.5.0"`,
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "https://google.com/search?q=test" "python-requests/2.31.0"`,
		`1.2.3.4 - alice [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 - "-" "some-unknown-bot/1.0" "10.0.0.9"`,
	}

	var firstHash, firstNorm string
	for i, line := range lines {
		got, hash := phNormalize(reg, "docker", "edge", line)
		if i == 0 {
			firstHash, firstNorm = hash, got
			continue
		}
		if hash != firstHash {
			t.Errorf("volatile field changed the hash\n  line[0]: %q\n  line[%d]: %q", firstNorm, i, got)
		}
	}
}

// TestHTTPCombinedV1NeverSeesLineageToken asserts the D3 invariant holds for
// the new path: the vgrid token is stripped upstream, so it can never enter a
// profile, the normalized line, the hash or a cache key.
func TestHTTPCombinedV1NeverSeesLineageToken(t *testing.T) {
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))

	base := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	wantNorm, wantHash := phNormalize(reg, "docker", "edge", base)

	tokened := []struct {
		name string
		line string
	}{
		{"populated token", base + ` vgrid=b1946ac92492d2347c6235b4d2611184`},
		{"empty token", base + ` vgrid=`},
		{"token with trailing whitespace", base + ` vgrid=abc123 `},
	}

	for _, tt := range tokened {
		t.Run(tt.name, func(t *testing.T) {
			got, hash := phNormalize(reg, "docker", "edge", tt.line)

			if strings.Contains(got, "vgrid") {
				t.Errorf("lineage token reached the profile and survived: %q", got)
			}
			if got != wantNorm {
				t.Errorf("token changed the normalized line\n  with token: %q\n  without:    %q", got, wantNorm)
			}
			if hash != wantHash {
				t.Errorf("token changed the hash - this would poison the pattern store")
			}
		})
	}
}

// TestHTTPCombinedV1DockerFramingStrippedFirst asserts the profile sees the
// native line, not the collector's Docker timestamp prefix.
func TestHTTPCombinedV1DockerFramingStrippedFirst(t *testing.T) {
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))

	native := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	framed := `2026-03-18T22:32:28.411683956Z ` + native

	wantNorm, wantHash := phNormalize(reg, "docker", "edge", native)
	gotNorm, gotHash := phNormalize(reg, "docker", "edge", framed)

	if gotNorm != wantNorm || gotHash != wantHash {
		t.Errorf("Docker framing leaked into the profile\n  framed: %q\n  native: %q", gotNorm, wantNorm)
	}
}

// phNormalize is the shared registry driver: build an event, normalize it,
// return the normalized line and its hash.
func phNormalize(r *Registry, sourceType, sourceName, line string) (string, string) {
	evt := &event.Event{SourceType: sourceType, SourceName: sourceName, Line: line}
	r.NormalizeEvent(evt)
	return evt.NormalizedLine, evt.Hash
}
