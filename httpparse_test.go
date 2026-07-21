// httpparse_test.go
package main

import (
	"testing"

	"github.com/vaultguardian/observer/internal/rec"
)

// Shared sample lines used across the parse tests.
const (
	// Format 1 — hostname-prefixed (CapRover nginx normalizer).
	lineHosted = "api.admin.kovicloud.com GET /?q=UNION+SELECT HTTP/2.0 200"
	// Format 2 — quoted request line (generic normalizer / raw access log).
	lineQuoted = `1.2.3.4 - - [10/Oct/2025:13:55:36 +0000] "GET /?q=UNION+SELECT HTTP/1.0" 200 83`
	// Format 3 — bare (no hostname, no quotes).
	lineBare = "GET /?q=UNION+SELECT+1,2,3 HTTP/1.0 200"
	// Format 4 — Express/morgan (CapRover captain-captain).
	lineMorgan      = "GET /api/keys 200 0.563 ms - 83"
	lineMorganInt   = "POST /api/login 201 0 ms - 5"
	lineMorganDash  = "GET /healthz 200 1.2 ms - -"
	lineNonHTTP     = "2025/10/10 13:55:36 [error] 12#12: upstream timed out"
	lineMorganLarge = "GET /dump 200 12.5 ms - 83000"
)

func TestParseNormalizedLine(t *testing.T) {
	cases := []struct {
		name               string
		in                 string
		method, path, host string
		status             int
	}{
		// --- Regression: existing nginx/quoted/bare must be unchanged ---
		{"hosted", lineHosted, "GET", "/?q=UNION+SELECT", "api.admin.kovicloud.com", 200},
		{"quoted", lineQuoted, "GET", "/?q=UNION+SELECT", "", 200},
		{"bare", lineBare, "GET", "/?q=UNION+SELECT+1,2,3", "", 200},
		// --- Fix 1: morgan ---
		{"morgan", lineMorgan, "GET", "/api/keys", "", 200},
		{"morgan_int_timing", lineMorganInt, "POST", "/api/login", "", 201},
		{"morgan_unknown_bytes", lineMorganDash, "GET", "/healthz", "", 200},
		{"morgan_large_bytes", lineMorganLarge, "GET", "/dump", "", 200},
		// --- Non-HTTP yields zero values ---
		{"non_http", lineNonHTTP, "", "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method, path, host, status := parseNormalizedLine(tc.in)
			if method != tc.method || path != tc.path || host != tc.host || status != tc.status {
				t.Errorf("parseNormalizedLine(%q) = (%q,%q,%q,%d); want (%q,%q,%q,%d)",
					tc.in, method, path, host, status, tc.method, tc.path, tc.host, tc.status)
			}
		})
	}
}

func TestParseRawHTTPLine(t *testing.T) {
	// parseRawHTTPLine does NOT handle Format 1 (hosted) — that shape only
	// exists post-nginx-normalization. It covers quoted, bare, and morgan.
	cases := []struct {
		name               string
		in                 string
		method, path, host string
		status             int
	}{
		{"quoted", lineQuoted, "GET", "/?q=UNION+SELECT", "", 200},
		{"bare", lineBare, "GET", "/?q=UNION+SELECT+1,2,3", "", 200},
		{"morgan", lineMorgan, "GET", "/api/keys", "", 200},
		{"morgan_int_timing", lineMorganInt, "POST", "/api/login", "", 201},
		{"morgan_unknown_bytes", lineMorganDash, "GET", "/healthz", "", 200},
		{"non_http", lineNonHTTP, "", "", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method, path, host, status := parseRawHTTPLine(tc.in)
			if method != tc.method || path != tc.path || host != tc.host || status != tc.status {
				t.Errorf("parseRawHTTPLine(%q) = (%q,%q,%q,%d); want (%q,%q,%q,%d)",
					tc.in, method, path, host, status, tc.method, tc.path, tc.host, tc.status)
			}
		})
	}
}

func TestExtractResponseBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int64
	}{
		// nginx-format (unchanged path).
		{"nginx", `1.2.3.4 - - [t] "GET /path HTTP/2.0" 200 34020 "-" "curl/8.5.0" "-"`, 34020},
		{"quoted", lineQuoted, 83},
		// morgan: trailing byte count, including a 4+ digit count on the raw line.
		{"morgan", lineMorgan, 83},
		{"morgan_int_timing", lineMorganInt, 5},
		{"morgan_large", lineMorganLarge, 83000},
		// morgan with unknown bytes ("-") → 0.
		{"morgan_unknown_bytes", lineMorganDash, 0},
		// non-HTTP → 0.
		{"non_http", lineNonHTTP, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractResponseBytes(tc.in); got != tc.want {
				t.Errorf("extractResponseBytes(%q) = %d; want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestDeterministicDisclosure pins the shared tier-1 predicate used by both
// the evidence callback and the status shortcut: format identity only —
// redaction counts alone must never qualify, and every degenerate Evidence
// shape (nil, noOp, missing disclosure) must be false.
func TestDeterministicDisclosure(t *testing.T) {
	disclosure := func(format rec.DetectedFormat, redactions int) *rec.Evidence {
		return &rec.Evidence{
			Disclosure: &rec.DisclosureAnalysis{
				Format:              format,
				SensitiveRedactions: redactions,
				DisclosureSummary:   "TEST SUMMARY",
			},
		}
	}
	cases := []struct {
		name string
		ev   *rec.Evidence
		want bool
	}{
		{"nil_evidence", nil, false},
		{"nil_disclosure", &rec.Evidence{}, false},
		{"noop_disabled_shape", &rec.Evidence{Status: rec.EvidenceNotAvailableCollectorDisabled}, false},
		{"passwd", disclosure(rec.FormatPasswd, 1), true},
		{"dotenv", disclosure(rec.FormatDotenv, 2), true},
		{"pem_zero_preview", disclosure(rec.FormatPEM, 1), true},
		{"formatless_with_redactions", disclosure("", 3), false},
		{"html_with_redactions", disclosure(rec.FormatHTML, 5), false},
		{"json_with_redactions", disclosure(rec.FormatJSON, 2), false},
		{"binary_fail_closed", disclosure(rec.FormatBinary, 0), false},
		{"unknown_fail_closed", disclosure(rec.FormatUnknown, 0), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := deterministicDisclosure(tc.ev)
			if got != tc.want {
				t.Errorf("deterministicDisclosure = %v, want %v", got, tc.want)
			}
			if tc.want && reason == "" {
				t.Errorf("disclosing verdict carried no reason")
			}
		})
	}
}
