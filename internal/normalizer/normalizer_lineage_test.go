package normalizer

import (
	"testing"

	"github.com/vaultguardian/observer/internal/event"
)

// TestLineageTokenExcludedFromNormalization is the D3 cache-poisoning guard:
// a line WITH a trailing vgrid token must produce byte-identical NormalizedLine
// AND Hash as the same line WITHOUT it. If the token leaked into the hash,
// every request would look structurally unique and the pattern store's hit
// rate would collapse.
func TestLineageTokenExcludedFromNormalization(t *testing.T) {
	reg := NewRegistry()

	// Two source families with different request-line handling:
	//   - nginx: request line is sacred/raw
	//   - generic (apache backend): global `\d{4,}` → <NUM>, which WOULD chew
	//     up a hex token containing a 4+ digit run (e.g. ...2174... below),
	//     making the strip load-bearing rather than cosmetic.
	cases := []struct {
		name       string
		sourceName string
		withTok    string
		without    string
	}{
		{
			name:       "nginx_sacred_request_line",
			sourceName: "captain-nginx",
			withTok:    `107.155.87.173 - - [15/Sep/2026:04:01:00 +0000] "wp.soak.vaultguardian.io" "GET /?vg-lineage-test=3 HTTP/2.0" 200 70037 "-" "curl/8.5.0" "-" vgrid=2fb2cf19c82b36ceb7f89d50b381fcf1`,
			without:    `107.155.87.173 - - [15/Sep/2026:04:01:00 +0000] "wp.soak.vaultguardian.io" "GET /?vg-lineage-test=3 HTTP/2.0" 200 70037 "-" "curl/8.5.0" "-"`,
		},
		{
			name:       "generic_backend_numeric_token",
			sourceName: "wp",
			withTok:    `107.155.87.173 - - [15/Sep/2026:03:59:49 +0000] "GET /?vg-lineage-test=2 HTTP/1.1" 200 70364 "-" "curl/8.5.0" vgrid=d222b0a4b75f01a12a7c1c4d2174cd2c`,
			without:    `107.155.87.173 - - [15/Sep/2026:03:59:49 +0000] "GET /?vg-lineage-test=2 HTTP/1.1" 200 70364 "-" "curl/8.5.0"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			with := &event.Event{SourceType: "docker", SourceName: tc.sourceName, Line: tc.withTok}
			base := &event.Event{SourceType: "docker", SourceName: tc.sourceName, Line: tc.without}
			reg.NormalizeEvent(with)
			reg.NormalizeEvent(base)

			if with.NormalizedLine != base.NormalizedLine {
				t.Errorf("normalized line differs with/without token:\nwith:    %q\nwithout: %q",
					with.NormalizedLine, base.NormalizedLine)
			}
			if with.Hash != base.Hash {
				t.Errorf("hash differs with/without token: with=%s without=%s", with.Hash, base.Hash)
			}
			// Belt and braces: the raw token substring must be gone.
			if containsToken(with.NormalizedLine) {
				t.Errorf("normalized line still carries a vgrid token: %q", with.NormalizedLine)
			}
		})
	}
}

func containsToken(s string) bool {
	for i := 0; i+5 <= len(s); i++ {
		if s[i:i+5] == "vgrid" {
			return true
		}
	}
	return false
}

// TestStripLineageToken pins the strip helper directly, including the no-token
// no-op and the vgrid=- sentinel.
func TestStripLineageToken(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"GET / HTTP/1.1" 200 83 "-" "curl" vgrid=2fb2cf19c82b36ceb7f89d50b381fcf1`, `"GET / HTTP/1.1" 200 83 "-" "curl"`},
		{`"GET / HTTP/1.1" 200 83 "-" "curl" vgrid=-`, `"GET / HTTP/1.1" 200 83 "-" "curl"`},
		{`"GET / HTTP/1.1" 200 83 "-" "curl"`, `"GET / HTTP/1.1" 200 83 "-" "curl"`},
	}
	for _, tc := range cases {
		if got := stripLineageToken(tc.in); got != tc.want {
			t.Errorf("stripLineageToken(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
