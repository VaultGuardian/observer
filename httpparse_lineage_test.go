// httpparse_lineage_test.go
package main

import "testing"

// The three PINNED parser fixtures from the frozen design (A1 record), byte
// exact. The first two are one request observed twice (same vgrid); the third
// is a distinct request with a distinct ID.
const (
	fixtureNginxVgrid   = `107.155.87.173 - - [15/Sep/2026:04:01:00 +0000] "wp.soak.vaultguardian.io" "GET /?vg-lineage-test=3 HTTP/2.0" 200 70037 "-" "curl/8.5.0" "-" vgrid=2fb2cf19c82b36ceb7f89d50b381fcf1`
	fixtureApacheVgrid  = `107.155.87.173 - - [15/Sep/2026:04:00:59 +0000] "GET /?vg-lineage-test=3 HTTP/1.1" 200 70364 "-" "curl/8.5.0" vgrid=2fb2cf19c82b36ceb7f89d50b381fcf1`
	fixtureApacheVgrid2 = `107.155.87.173 - - [15/Sep/2026:03:59:49 +0000] "GET /?vg-lineage-test=2 HTTP/1.1" 200 70364 "-" "curl/8.5.0" vgrid=d222b0a4b75f01a12a7c1c4d2174cd2c`

	pinnedID1 = "2fb2cf19c82b36ceb7f89d50b381fcf1"
	pinnedID2 = "d222b0a4b75f01a12a7c1c4d2174cd2c"
)

// TestExtractLineageID_PinnedFixtures pins the three design fixtures: both
// formats extract the token, and the observed pair shares one ID.
func TestExtractLineageID_PinnedFixtures(t *testing.T) {
	cases := []struct {
		name string
		in   string
		id   string
	}{
		{"nginx_format1", fixtureNginxVgrid, pinnedID1},
		{"apache_format2", fixtureApacheVgrid, pinnedID1},
		{"apache_distinct", fixtureApacheVgrid2, pinnedID2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, st := extractLineageID(tc.in)
			if st != lineageValid {
				t.Fatalf("status = %d, want lineageValid", st)
			}
			if id != tc.id {
				t.Errorf("id = %q, want %q", id, tc.id)
			}
		})
	}

	// The pinned pair is one request observed twice — same trusted ID.
	nID, _ := extractLineageID(fixtureNginxVgrid)
	aID, _ := extractLineageID(fixtureApacheVgrid)
	if nID != aID {
		t.Errorf("pinned pair IDs diverge: nginx=%q apache=%q", nID, aID)
	}
}

// TestExtractLineageID_Validation covers D3: 32 lowercase hex only; vgrid=- and
// absence are "missing" (not invalid); everything malformed is "invalid".
func TestExtractLineageID_Validation(t *testing.T) {
	cases := []struct {
		name string
		in   string
		id   string
		st   lineageStatus
	}{
		{"no_key", `1.2.3.4 - - [t] "GET / HTTP/1.1" 200 83 "-" "curl"`, "", lineageMissing},
		{"dash_sentinel", `"GET / HTTP/1.1" 200 83 vgrid=-`, "", lineageMissing},
		// F7 (round-2): a present-but-empty vgrid key is INVALID, not missing —
		// a misconfiguration/attacker signal, distinct from an honest "no key".
		{"empty_value", `"GET / HTTP/1.1" 200 83 vgrid=`, "", lineageInvalid},
		{"empty_trailing_space", `"GET / HTTP/1.1" 200 83 vgrid= `, "", lineageInvalid},
		{"empty_whitespace_tail", "\"GET / HTTP/1.1\" 200 83 vgrid=\t  ", "", lineageInvalid},
		{"valid", `"GET / HTTP/1.1" 200 83 vgrid=` + pinnedID1, pinnedID1, lineageValid},
		{"uppercase", `"GET / HTTP/1.1" 200 83 vgrid=2FB2CF19C82B36CEB7F89D50B381FCF1`, "", lineageInvalid},
		{"too_long_33", `"GET / HTTP/1.1" 200 83 vgrid=2fb2cf19c82b36ceb7f89d50b381fcf1a`, "", lineageInvalid},
		{"too_short_31", `"GET / HTTP/1.1" 200 83 vgrid=2fb2cf19c82b36ceb7f89d50b381fcf`, "", lineageInvalid},
		{"non_hex", `"GET / HTTP/1.1" 200 83 vgrid=zzz2cf19c82b36ceb7f89d50b381fcf1`, "", lineageInvalid},
		{"client_supplied_garbage", `"GET / HTTP/1.1" 200 83 vgrid=../../etc/passwd`, "", lineageInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, st := extractLineageID(tc.in)
			if id != tc.id || st != tc.st {
				t.Errorf("extractLineageID(%q) = (%q,%d); want (%q,%d)", tc.in, id, st, tc.id, tc.st)
			}
		})
	}
}

// TestParse_TokenDoesNotBreakParsing: the HTTP parsers still recover
// method/path/status from a line that carries a trailing vgrid token, and the
// non-token corpus is unchanged (missing status).
func TestParse_TokenDoesNotBreakParsing(t *testing.T) {
	m, p, _, s := parseRawHTTPLine(fixtureNginxVgrid)
	if m != "GET" || p != "/?vg-lineage-test=3" || s != 200 {
		t.Errorf("nginx vgrid parse = (%q,%q,%d); want (GET,/?vg-lineage-test=3,200)", m, p, s)
	}
	m, p, _, s = parseRawHTTPLine(fixtureApacheVgrid)
	if m != "GET" || p != "/?vg-lineage-test=3" || s != 200 {
		t.Errorf("apache vgrid parse = (%q,%q,%d); want (GET,/?vg-lineage-test=3,200)", m, p, s)
	}

	// Regression: existing no-token corpus carries no lineage.
	for _, ln := range []string{lineHosted, lineQuoted, lineBare, lineMorgan, lineNonHTTP} {
		if id, st := extractLineageID(ln); id != "" || st != lineageMissing {
			t.Errorf("corpus line %q unexpectedly carries lineage (%q,%d)", ln, id, st)
		}
	}
}
