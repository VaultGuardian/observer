// internal/normalizer/profilehints_test.go
package normalizer

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/vaultguardian/observer/internal/event"
)

// NORMALIZER_HINTS_JSON plumbing tests.
//
// A hint is applied because the OPERATOR wrote it. Nothing about the content
// of a log line may ever cause a profile to be selected, switched or
// un-selected at runtime - no sniffing, no confidence scores, no promotion,
// no learning. The service-log warning at the bottom of this file is the one
// content-aware code path, and it is advisory only: it must never change
// normalization.
//
// Invalid configuration fails startup rather than degrading to generic. A
// typo'd profile name that silently fell back to GenericNormalizer is the
// exact failure this feature exists to prevent, so ParseProfileHints returns
// an error and main.go fatals on it.

// phMustParse parses a hints JSON document that is expected to be valid.
func phMustParse(t *testing.T, raw string) ProfileHints {
	t.Helper()
	h, err := ParseProfileHints(raw)
	if err != nil {
		t.Fatalf("ParseProfileHints(%q) returned error: %v", raw, err)
	}
	return h
}

// phCaptureLog redirects the standard logger for the duration of fn and
// returns everything written to it.
func phCaptureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	fn()
	return buf.String()
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

func TestParseProfileHintsValid(t *testing.T) {
	raw := `{"docker:edge":"http-combined-v1","router":"http-combined-v1"}`

	hints, err := ParseProfileHints(raw)
	if err != nil {
		t.Fatalf("ParseProfileHints returned error: %v", err)
	}
	if len(hints) != 2 {
		t.Fatalf("len(hints) = %d, want 2 (%v)", len(hints), hints)
	}

	for _, key := range []string{"docker:edge", "router"} {
		p, ok := hints[key]
		if !ok {
			t.Errorf("hints is missing key %q", key)
			continue
		}
		if p == nil {
			t.Errorf("hints[%q] is nil", key)
			continue
		}
		if p.Name() != ProfileHTTPCombinedV1 {
			t.Errorf("hints[%q].Name() = %q, want %q", key, p.Name(), ProfileHTTPCombinedV1)
		}
	}
}

func TestParseProfileHintsEmptyMeansUnset(t *testing.T) {
	// Empty or unset is today's behavior, bit for bit: no hints, no error.
	for _, raw := range []string{"", "   ", "\t\n", "{}", " {} "} {
		t.Run(strings.TrimSpace(raw)+"|", func(t *testing.T) {
			hints, err := ParseProfileHints(raw)
			if err != nil {
				t.Fatalf("ParseProfileHints(%q) returned error: %v", raw, err)
			}
			if len(hints) != 0 {
				t.Errorf("ParseProfileHints(%q) = %v, want empty", raw, hints)
			}
		})
	}
}

func TestParseProfileHintsMalformedJSONFailsStartup(t *testing.T) {
	malformed := []struct {
		name string
		raw  string
	}{
		{"truncated object", `{"docker:edge":"http-combined-v1"`},
		{"unquoted value", `{"docker:edge":http-combined-v1}`},
		{"trailing comma", `{"docker:edge":"http-combined-v1",}`},
		{"single quotes", `{'docker:edge':'http-combined-v1'}`},
		{"bare word", `http-combined-v1`},
		{"stray brace", `}`},
	}

	for _, tt := range malformed {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseProfileHints(tt.raw); err == nil {
				t.Errorf("ParseProfileHints(%q) returned nil error; malformed JSON must fail startup", tt.raw)
			}
		})
	}
}

func TestParseProfileHintsNonObjectJSONFailsStartup(t *testing.T) {
	// Valid JSON, wrong shape. Still a configuration error.
	nonObjects := []struct {
		name string
		raw  string
	}{
		{"array", `["http-combined-v1"]`},
		{"string", `"http-combined-v1"`},
		{"number", `42`},
		{"boolean", `true`},
		{"null", `null`},
		{"object of objects", `{"docker:edge":{"profile":"http-combined-v1"}}`},
		{"object of numbers", `{"docker:edge":1}`},
	}

	for _, tt := range nonObjects {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseProfileHints(tt.raw); err == nil {
				t.Errorf("ParseProfileHints(%q) returned nil error; want a configuration error", tt.raw)
			}
		})
	}
}

func TestParseProfileHintsUnknownProfileFailsStartup(t *testing.T) {
	raw := `{"docker:edge":"http-combined-v1","docker:router":"http-combimed-v1"}`

	_, err := ParseProfileHints(raw)
	if err == nil {
		t.Fatal("ParseProfileHints returned nil error for an unknown profile name; " +
			"a typo must fail startup, not silently degrade to generic")
	}

	msg := err.Error()

	// The error has to be actionable without reading the source: it must name
	// the offending key, the bad value, and the valid profile names.
	if !strings.Contains(msg, "docker:router") {
		t.Errorf("error does not name the offending key %q: %s", "docker:router", msg)
	}
	if !strings.Contains(msg, "http-combimed-v1") {
		t.Errorf("error does not name the offending profile value: %s", msg)
	}
	for _, valid := range ProfileNames() {
		if !strings.Contains(msg, valid) {
			t.Errorf("error does not list valid profile name %q: %s", valid, msg)
		}
	}
}

func TestParseProfileHintsRejectsEmptyKeyOrValue(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty key", `{"":"http-combined-v1"}`},
		{"whitespace key", `{"   ":"http-combined-v1"}`},
		{"empty profile name", `{"docker:edge":""}`},
		{"whitespace profile name", `{"docker:edge":"   "}`},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseProfileHints(tt.raw); err == nil {
				t.Errorf("ParseProfileHints(%q) returned nil error, want a configuration error", tt.raw)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Hint resolution
// ---------------------------------------------------------------------------

func TestProfileHintMatchesScopeKey(t *testing.T) {
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))

	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	want := `GET /a/b?c=1 HTTP/1.1 200`

	got, _ := phNormalize(reg, "docker", "edge", line)
	if got != want {
		t.Errorf("scope-key hint did not apply\n  got:  %q\n  want: %q", got, want)
	}
}

func TestProfileHintScopeKeyDoesNotLeakAcrossSourceTypes(t *testing.T) {
	// "docker:edge" is scoped to the docker collector. A systemd unit that
	// happens to be called "edge" must be untouched.
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))
	plain := NewRegistry()

	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`

	gotHinted, _ := phNormalize(reg, "systemd", "edge", line)
	gotPlain, _ := phNormalize(plain, "systemd", "edge", line)

	if gotHinted != gotPlain {
		t.Errorf("docker-scoped hint leaked onto systemd:edge\n  hinted: %q\n  plain:  %q", gotHinted, gotPlain)
	}
}

func TestProfileHintMatchesBareSourceName(t *testing.T) {
	// A bare source name applies across collector types, exactly as the
	// existing Lookup step 2 does.
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"router":"http-combined-v1"}`))

	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	want := `GET /a/b?c=1 HTTP/1.1 200`

	for _, sourceType := range []string{"docker", "systemd", "file", "journal"} {
		t.Run(sourceType, func(t *testing.T) {
			got, _ := phNormalize(reg, sourceType, "router", line)
			if got != want {
				t.Errorf("bare-name hint did not apply for %s\n  got:  %q\n  want: %q", sourceType, got, want)
			}
		})
	}
}

func TestProfileHintBeatsExactNameLookup(t *testing.T) {
	// "postgres" is a registered family, so Lookup step 2 would hand this to
	// PostgresNormalizer. An explicit hint must win.
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:postgres":"http-combined-v1"}`))
	plain := NewRegistry()

	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	want := `GET /a/b?c=1 HTTP/1.1 200`

	gotHinted, _ := phNormalize(reg, "docker", "postgres", line)
	gotPlain, _ := phNormalize(plain, "docker", "postgres", line)

	if gotHinted != want {
		t.Errorf("hint lost to the exact-name Lookup step\n  got:  %q\n  want: %q", gotHinted, want)
	}
	if gotHinted == gotPlain {
		t.Errorf("test is vacuous: hinted and unhinted output are identical (%q)", gotHinted)
	}
}

func TestProfileHintBeatsFuzzyLookup(t *testing.T) {
	// "postgres-edge" contains "postgres", so Lookup step 3 (fuzzy substring)
	// would hand this to PostgresNormalizer. Naming luck must not beat an
	// explicit operator declaration.
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:postgres-edge":"http-combined-v1"}`))
	plain := NewRegistry()

	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	want := `GET /a/b?c=1 HTTP/1.1 200`

	gotHinted, _ := phNormalize(reg, "docker", "postgres-edge", line)
	gotPlain, _ := phNormalize(plain, "docker", "postgres-edge", line)

	if gotHinted != want {
		t.Errorf("hint lost to the fuzzy Lookup step\n  got:  %q\n  want: %q", gotHinted, want)
	}
	if gotHinted == gotPlain {
		t.Errorf("test is vacuous: hinted and unhinted output are identical (%q)", gotHinted)
	}
}

func TestProfileHintOnlyAppliesToHintedSources(t *testing.T) {
	// One hinted source must not change any other source in the same registry.
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))
	plain := NewRegistry()

	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`

	for _, name := range []string{"router", "gateway", "wp", "demo-nginx", "postgres", "myapp"} {
		t.Run(name, func(t *testing.T) {
			gotHinted, hashHinted := phNormalize(reg, "docker", name, line)
			gotPlain, hashPlain := phNormalize(plain, "docker", name, line)

			if gotHinted != gotPlain || hashHinted != hashPlain {
				t.Errorf("unhinted source %q changed\n  hinted: %q\n  plain:  %q", name, gotHinted, gotPlain)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The regression gate
// ---------------------------------------------------------------------------

// phGoldens are normalized outputs captured from main BEFORE this change.
// With NORMALIZER_HINTS_JSON unset, every one of these must still hold, byte
// for byte. A diff here means the change leaked into the default path.
var phGoldens = []struct {
	name   string
	source string
	line   string
	want   string
}{
	{
		name:   "generic proxy, canonical combined",
		source: "edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		want:   `<IP> - - <TS> "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
	},
	{
		name:   "generic proxy, combined plus xff",
		source: "edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
		want:   `<IP> - - <TS> "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
	},
	{
		name:   "generic proxy, HTTP/2.0",
		source: "edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/2.0" 200 896 "-" "curl/8.5.0" "-"`,
		want:   `<IP> - - <TS> "GET /a/b?c=1 HTTP/2.0" 200 896 "-" "curl/8.5.0" "-"`,
	},
	{
		name:   "generic proxy, common log format",
		source: "edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896`,
		want:   `<IP> - - <TS> "GET /a/b HTTP/1.1" 200 896`,
	},
	{
		name:   "generic proxy, escaped quote in path",
		source: "edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a\"b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
		want:   `<IP> - - <TS> "GET /a\"b HTTP/1.1" 200 896 "-" "curl/8.5.0"`,
	},
	{
		name:   "generic proxy, bracketed timestamp inside the user-agent",
		source: "edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "Bot [18/Mar/2026:22:32:28 +0000] x"`,
		want:   `<IP> - - <TS> "GET /a/b HTTP/1.1" 200 896 "-" "Bot <TS> x"`,
	},
	{
		name:   "generic proxy, username in the user position",
		source: "edge",
		line:   `1.2.3.4 - alice [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
		want:   `<IP> - alice <TS> "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
	},
	{
		name:   "generic proxy, dash byte count",
		source: "edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 - "-" "curl/8.5.0"`,
		want:   `<IP> - - <TS> "GET /a/b?c=1 HTTP/1.1" 200 - "-" "curl/8.5.0"`,
	},
	{
		name:   "generic proxy, nginx error line",
		source: "edge",
		line:   `2026/03/17 15:10:04 [error] 28#28: *1 open() "/x" failed`,
		want:   `<TS> [error] 28#28: *1 open() "/x" failed`,
	},
	{
		name:   "generic proxy, empty line",
		source: "edge",
		line:   ``,
		want:   ``,
	},
	{
		name:   "generic proxy, whitespace-only line",
		source: "edge",
		line:   `   `,
		want:   ``,
	},
	{
		name:   "fuzzy postgres match on an access line",
		source: "postgres-edge",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
		want:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c= <N> HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
	},
	{
		name:   "exact postgres match on an access line",
		source: "postgres",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
		want:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c= <N> HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
	},
	{
		name:   "name-matched nginx access line",
		source: "demo-nginx",
		line:   `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
		want:   `GET /a/b?c=1 HTTP/1.1 200`,
	},
}

// TestUnsetHintsLeavesNormalizationUnchanged is the regression gate. It runs
// the golden corpus through three constructions that must all be identical to
// pre-change main: NewRegistry(), a nil ProfileHints, and an empty one.
func TestUnsetHintsLeavesNormalizationUnchanged(t *testing.T) {
	registries := map[string]*Registry{
		"NewRegistry":         NewRegistry(),
		"nil hints":           NewRegistryWithProfileHints(nil),
		"empty hints":         NewRegistryWithProfileHints(ProfileHints{}),
		"parsed empty string": NewRegistryWithProfileHints(phMustParse(t, "")),
		"parsed empty object": NewRegistryWithProfileHints(phMustParse(t, "{}")),
	}

	for regName, reg := range registries {
		for _, g := range phGoldens {
			t.Run(regName+"/"+g.name, func(t *testing.T) {
				got, _ := phNormalize(reg, "docker", g.source, g.line)
				if got != g.want {
					t.Errorf("normalized output drifted from main\n  source: %s\n  line:   %s\n  got:    %q\n  want:   %q",
						g.source, g.line, got, g.want)
				}
			})
		}
	}
}

// TestUnsetHintsMatchesNewRegistryHashes is the same gate stated as hash
// identity, which is what the pattern store and the LLM cache key actually
// consume.
func TestUnsetHintsMatchesNewRegistryHashes(t *testing.T) {
	plain := NewRegistry()
	hinted := NewRegistryWithProfileHints(nil)

	for _, g := range phGoldens {
		t.Run(g.name, func(t *testing.T) {
			_, wantHash := phNormalize(plain, "docker", g.source, g.line)
			_, gotHash := phNormalize(hinted, "docker", g.source, g.line)
			if gotHash != wantHash {
				t.Errorf("hash drifted for source %s / line %s", g.source, g.line)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The service-log warning
// ---------------------------------------------------------------------------
//
// Advisory only. It fires at most once per source key per process, names the
// source and suggests NORMALIZER_HINTS_JSON, and never changes normalization.
// Warn state is per-Registry, so each test builds its own.

func TestServiceLogWarningFiresOnceForUnconfiguredGenericSource(t *testing.T) {
	reg := NewRegistry()

	lines := []string{
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`,
		`5.6.7.8 - - [18/Mar/2026:22:32:29 +0000] "GET /c/d HTTP/1.1" 404 153 "-" "curl/8.5.0" "-"`,
		`9.9.9.9 - - [18/Mar/2026:22:32:30 +0000] "POST /login HTTP/2.0" 302 0 "-" "Mozilla/5.0" "-"`,
	}

	out := phCaptureLog(t, func() {
		for i := 0; i < 50; i++ {
			for _, line := range lines {
				phNormalize(reg, "docker", "edge", line)
			}
		}
	})

	if n := strings.Count(out, "docker:edge"); n != 1 {
		t.Errorf("warning fired %d times for docker:edge over 150 lines, want exactly 1\n%s", n, out)
	}
	if !strings.Contains(out, "NORMALIZER_HINTS_JSON") {
		t.Errorf("warning does not suggest NORMALIZER_HINTS_JSON:\n%s", out)
	}
	if !strings.Contains(out, ProfileHTTPCombinedV1) {
		t.Errorf("warning does not name the profile to set (%q):\n%s", ProfileHTTPCombinedV1, out)
	}
}

func TestServiceLogWarningIsPerSourceKey(t *testing.T) {
	reg := NewRegistry()
	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`

	out := phCaptureLog(t, func() {
		for i := 0; i < 10; i++ {
			phNormalize(reg, "docker", "edge", line)
			phNormalize(reg, "docker", "router", line)
			phNormalize(reg, "systemd", "gateway", line)
		}
	})

	for _, key := range []string{"docker:edge", "docker:router", "systemd:gateway"} {
		if n := strings.Count(out, key); n != 1 {
			t.Errorf("warning for %s fired %d times, want exactly 1\n%s", key, n, out)
		}
	}
}

func TestServiceLogWarningSilentWhenHintConfigured(t *testing.T) {
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))

	accepted := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	// A line the hinted profile declines. The source is configured, so the
	// operator has already answered the question the warning would ask.
	declined := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896`

	out := phCaptureLog(t, func() {
		for i := 0; i < 20; i++ {
			phNormalize(reg, "docker", "edge", accepted)
			phNormalize(reg, "docker", "edge", declined)
		}
	})

	if strings.Contains(out, "docker:edge") {
		t.Errorf("warning fired for a source that already has a hint configured:\n%s", out)
	}
}

func TestServiceLogWarningSilentForBareNameHint(t *testing.T) {
	// The hint is configured by bare source name; the warning must respect it
	// on every collector type, the same way resolution does.
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"edge":"http-combined-v1"}`))
	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`

	out := phCaptureLog(t, func() {
		for i := 0; i < 20; i++ {
			phNormalize(reg, "docker", "edge", line)
			phNormalize(reg, "systemd", "edge", line)
		}
	})

	if strings.Contains(out, "edge") {
		t.Errorf("warning fired for a source hinted by bare name:\n%s", out)
	}
}

func TestServiceLogWarningSilentForNonCombinedSource(t *testing.T) {
	reg := NewRegistry()

	lines := []string{
		`INFO  request completed in 12ms status=200`,
		`{"remote_addr":"1.2.3.4","request":"GET /a/b HTTP/1.1","status":200}`,
		`2026/03/17 15:10:04 [error] 28#28: *1 open() "/x" failed`,
		`worker exited with code 0`,
		`1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896`,
	}

	out := phCaptureLog(t, func() {
		for i := 0; i < 20; i++ {
			for _, line := range lines {
				phNormalize(reg, "docker", "myapp", line)
			}
		}
	})

	if strings.Contains(out, "docker:myapp") {
		t.Errorf("warning fired for a source that does not emit combined access logs:\n%s", out)
	}
}

func TestServiceLogWarningSilentForNameMatchedNormalizer(t *testing.T) {
	// These sources do not resolve to GenericNormalizer, so there is nothing
	// to suggest.
	reg := NewRegistry()
	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`

	out := phCaptureLog(t, func() {
		for i := 0; i < 20; i++ {
			for _, name := range []string{"nginx", "demo-nginx", "captain-nginx"} {
				phNormalize(reg, "docker", name, line)
			}
		}
	})

	if strings.Contains(out, "NORMALIZER_HINTS_JSON") {
		t.Errorf("warning fired for a source already matched to the nginx normalizer:\n%s", out)
	}
}

// TestServiceLogWarningDoesNotChangeNormalization is the load-bearing half:
// the advisory path must be observationally inert. Normalized output and hash
// must equal the golden values whether or not the warning fired.
func TestServiceLogWarningDoesNotChangeNormalization(t *testing.T) {
	warnReg := NewRegistry()
	plainReg := NewRegistry()

	line := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`
	want := `<IP> - - <TS> "GET /a/b?c=1 HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`

	var firstNorm, firstHash string
	out := phCaptureLog(t, func() {
		for i := 0; i < 5; i++ {
			got, hash := phNormalize(warnReg, "docker", "edge", line)
			if i == 0 {
				firstNorm, firstHash = got, hash
			}
			if got != want {
				t.Errorf("iteration %d: normalization changed on the warning path\n  got:  %q\n  want: %q", i, got, want)
			}
			if got != firstNorm || hash != firstHash {
				t.Errorf("iteration %d: output differs before vs after the warning fired", i)
			}
		}
	})

	if !strings.Contains(out, "docker:edge") {
		t.Fatalf("test is vacuous: the warning never fired\n%s", out)
	}

	// And identical to a registry that never logged anything.
	gotPlain, hashPlain := phNormalize(plainReg, "docker", "edge", line)
	if gotPlain != firstNorm || hashPlain != firstHash {
		t.Errorf("warning path diverged from a clean registry\n  warned: %q\n  plain:  %q", firstNorm, gotPlain)
	}
}

// TestServiceLogWarningSurvivesConcurrentUse guards the warn-once set against
// the collector's concurrent use. Run with -race.
func TestServiceLogWarningSurvivesConcurrentUse(t *testing.T) {
	reg := NewRegistryWithProfileHints(phMustParse(t, `{"docker:edge":"http-combined-v1"}`))

	combined := `1.2.3.4 - - [18/Mar/2026:22:32:28 +0000] "GET /a/b HTTP/1.1" 200 896 "-" "curl/8.5.0" "-"`

	done := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				evt := &event.Event{SourceType: "docker", SourceName: "edge", Line: combined}
				reg.NormalizeEvent(evt)
				evt2 := &event.Event{SourceType: "docker", SourceName: "router", Line: combined}
				reg.NormalizeEvent(evt2)
			}
		}(w)
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}
