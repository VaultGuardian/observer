// pair_test.go
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// `vaultguardian pair` tests
// =============================================================================
//
// The claim endpoint ships with the hosted side (chunk 2), so these run
// against a local mock. Systemd is replaced by recording hooks, which also
// lets the tests assert the ORDER of stop / claim / write / start - that
// order is the re-pair interlock [A12], not a style choice.

const existingEnv = `# VaultGuardian Observer environment
DATA_DIR=/var/lib/observer
DASHBOARD_PORT=9090

# Email alerts
RESEND_API_KEY=re_secret_value
ALERT_EMAIL_TO=ops@example.com

# Hosted sync
SYNC_URL=https://old.vaultguardian.io
SYNC_TOKEN=old-token
SYNC_INTERVAL=15s
`

func newVerifyKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// claimServer is a stand-in for the hosted pairing endpoint.
type claimServer struct {
	*httptest.Server
	claims   []string // canonicalized codes it received
	status   int
	response string
}

func newClaimServer(t *testing.T, response string) *claimServer {
	t.Helper()
	c := &claimServer{response: response}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/pairing/claim" {
			t.Errorf("claim request went to %s; want /api/pairing/claim", r.URL.Path)
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var req struct {
			Code string `json:"code"`
		}
		json.Unmarshal(body, &req)
		c.claims = append(c.claims, req.Code)

		status := c.status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, c.response)
	}))
	t.Cleanup(c.Close)
	return c
}

func goodClaimResponse(t *testing.T, url string) string {
	t.Helper()
	return fmt.Sprintf(`{
		"ingest_url": %q,
		"ingest_token": "new-ingest-token",
		"instance_id": "11111111-2222-3333-4444-555555555555",
		"command_verify_key": %q,
		"command_epoch": "epoch-9"
	}`, url, newVerifyKey(t))
}

// pairHarness wires runPair against a temp env file and recording hooks.
type pairHarness struct {
	envPath string
	events  []string
	out     strings.Builder
	opts    pairOptions
}

func newPairHarness(t *testing.T, envContent string, claim *claimServer) *pairHarness {
	t.Helper()
	h := &pairHarness{envPath: filepath.Join(t.TempDir(), "observer.env")}
	if envContent != "" {
		if err := os.WriteFile(h.envPath, []byte(envContent), 0600); err != nil {
			t.Fatalf("seed env: %v", err)
		}
	}
	h.opts = pairOptions{
		Code:    "abcd-efgh",
		URL:     claim.URL,
		EnvPath: h.envPath,
		Out:     &h.out,
		StopService: func(context.Context) error {
			h.events = append(h.events, "stop")
			return nil
		},
		StartService: func(context.Context) error {
			h.events = append(h.events, "start")
			return nil
		},
		StatusTail: func(context.Context) string { return "● observer.service - active (running)" },
	}
	return h
}

func (h *pairHarness) env(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(h.envPath)
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	return string(data)
}

func envValue(t *testing.T, content, key string) string {
	t.Helper()
	for _, line := range strings.Split(content, "\n") {
		if k, v, ok := splitEnvLine(line); ok && k == key {
			return v
		}
	}
	return ""
}

// The whole flow: stop, claim, atomic 0600 rewrite that preserves unrelated
// lines, start.
func TestPairRewritesEnvAtomically(t *testing.T) {
	claim := newClaimServer(t, "")
	claim.response = goodClaimResponse(t, "https://new.vaultguardian.io")
	h := newPairHarness(t, existingEnv, claim)

	if err := runPair(context.Background(), h.opts); err != nil {
		t.Fatalf("runPair: %v", err)
	}

	// --- order is the interlock: stopped before claiming, started after.
	if strings.Join(h.events, ",") != "stop,start" {
		t.Errorf("service events = %v; want stop then start", h.events)
	}
	if len(claim.claims) != 1 {
		t.Fatalf("claims = %d; want 1", len(claim.claims))
	}
	if claim.claims[0] != "ABCDEFGH" {
		t.Errorf("claimed code = %q; want the canonicalized ABCDEFGH", claim.claims[0])
	}

	content := h.env(t)

	// --- the five managed keys hold the claim's values
	for key, want := range map[string]string{
		"SYNC_URL":           "https://new.vaultguardian.io",
		"SYNC_TOKEN":         "new-ingest-token",
		"SYNC_INSTANCE_ID":   "11111111-2222-3333-4444-555555555555",
		"SYNC_COMMAND_EPOCH": "epoch-9",
	} {
		if got := envValue(t, content, key); got != want {
			t.Errorf("%s = %q; want %q", key, got, want)
		}
	}
	if key := envValue(t, content, "SYNC_VERIFY_KEY"); key == "" {
		t.Error("SYNC_VERIFY_KEY was not written")
	}

	// --- every unrelated line survived byte-for-byte
	for _, line := range []string{
		"# VaultGuardian Observer environment",
		"DATA_DIR=/var/lib/observer",
		"DASHBOARD_PORT=9090",
		"# Email alerts",
		"RESEND_API_KEY=re_secret_value",
		"ALERT_EMAIL_TO=ops@example.com",
		"# Hosted sync",
		"SYNC_INTERVAL=15s",
	} {
		if !strings.Contains(content, line) {
			t.Errorf("line %q did not survive the rewrite\n--- file ---\n%s", line, content)
		}
	}
	// ...and the old values are gone, not merely shadowed.
	for _, gone := range []string{"old.vaultguardian.io", "old-token"} {
		if strings.Contains(content, gone) {
			t.Errorf("old value %q is still in the file:\n%s", gone, content)
		}
	}
	// One line per key - a duplicate would let the last one silently win.
	for _, key := range pairEnvKeys {
		if n := strings.Count(content, key+"="); n != 1 {
			t.Errorf("%s appears %d times; want exactly 1\n%s", key, n, content)
		}
	}

	// --- permissions: owner-only, never a widened window
	info, err := os.Stat(h.envPath)
	if err != nil {
		t.Fatalf("stat env: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("env mode = %o; want 0600", perm)
	}

	// --- no temp files left behind
	entries, err := os.ReadDir(filepath.Dir(h.envPath))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "observer.env" {
			t.Errorf("leftover file %q in the env directory", entry.Name())
		}
	}

	if !strings.Contains(h.out.String(), "epoch-9") {
		t.Errorf("output did not report the new epoch:\n%s", h.out.String())
	}
}

// A first pairing has no SYNC_* lines at all: the keys get appended and
// nothing else changes.
func TestPairFirstTimeAppendsKeys(t *testing.T) {
	claim := newClaimServer(t, "")
	claim.response = goodClaimResponse(t, "https://new.vaultguardian.io")

	minimal := "DATA_DIR=/var/lib/observer\nDASHBOARD_PORT=9090\n"
	h := newPairHarness(t, minimal, claim)

	if err := runPair(context.Background(), h.opts); err != nil {
		t.Fatalf("runPair: %v", err)
	}

	content := h.env(t)
	if !strings.HasPrefix(content, minimal) {
		t.Errorf("existing content was not preserved as a prefix:\n%s", content)
	}
	for _, key := range pairEnvKeys {
		if envValue(t, content, key) == "" {
			t.Errorf("%s was not appended:\n%s", key, content)
		}
	}
}

// A file with no trailing newline must not have its last line mangled.
func TestPairPreservesMissingTrailingNewline(t *testing.T) {
	claim := newClaimServer(t, "")
	claim.response = goodClaimResponse(t, "https://new.vaultguardian.io")
	h := newPairHarness(t, "DATA_DIR=/var/lib/observer\nDASHBOARD_PORT=9090", claim)

	if err := runPair(context.Background(), h.opts); err != nil {
		t.Fatalf("runPair: %v", err)
	}
	content := h.env(t)
	if !strings.Contains(content, "DASHBOARD_PORT=9090\n") {
		t.Errorf("last original line was mangled:\n%s", content)
	}
	if envValue(t, content, "SYNC_TOKEN") != "new-ingest-token" {
		t.Errorf("appended keys are wrong:\n%s", content)
	}
}

// A refused claim must leave the env untouched and NOT start the service - a
// half-completed re-pair is a visibly stopped Observer, not a running one with
// credentials nobody can name.
func TestPairClaimFailureLeavesEnvUntouched(t *testing.T) {
	claim := newClaimServer(t, `{"error":"invalid or expired code"}`)
	claim.status = http.StatusBadRequest
	h := newPairHarness(t, existingEnv, claim)

	err := runPair(context.Background(), h.opts)
	if err == nil {
		t.Fatal("runPair should fail when the claim is refused")
	}
	if !strings.Contains(err.Error(), "invalid or expired code") {
		t.Errorf("error = %v; want the server's own message", err)
	}
	if got := h.env(t); got != existingEnv {
		t.Errorf("env changed after a failed claim:\n--- got ---\n%s", got)
	}
	if strings.Join(h.events, ",") != "stop" {
		t.Errorf("service events = %v; want only the stop (never a start after a failed claim)", h.events)
	}
}

// A 2xx whose body is unusable is treated exactly like a refusal: nothing is
// written, because writing it would disable the channel this command exists to
// set up.
func TestPairRejectsUnusableClaimResponses(t *testing.T) {
	shortKey := base64.StdEncoding.EncodeToString([]byte("not-32-bytes"))
	cases := map[string]string{
		"missing fields": `{"ingest_url":"https://new.vaultguardian.io"}`,
		"bad verify key": fmt.Sprintf(`{"ingest_url":"https://x.io","ingest_token":"t",
			"instance_id":"i","command_verify_key":%q,"command_epoch":"e"}`, shortKey),
		"verify key not base64": `{"ingest_url":"https://x.io","ingest_token":"t",
			"instance_id":"i","command_verify_key":"!!!","command_epoch":"e"}`,
		"plain http ingest url": fmt.Sprintf(`{"ingest_url":"http://x.io","ingest_token":"t",
			"instance_id":"i","command_verify_key":%q,"command_epoch":"e"}`, newVerifyKey(t)),
		"not json": `<html>gateway timeout</html>`,
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			claim := newClaimServer(t, response)
			h := newPairHarness(t, existingEnv, claim)

			if err := runPair(context.Background(), h.opts); err == nil {
				t.Fatal("runPair should reject an unusable claim response")
			}
			if got := h.env(t); got != existingEnv {
				t.Errorf("env changed despite an unusable response:\n%s", got)
			}
			if strings.Contains(strings.Join(h.events, ","), "start") {
				t.Errorf("service was started after an unusable response: %v", h.events)
			}
		})
	}
}

// If the daemon cannot be stopped, the code is never claimed: the epoch must
// not rotate while something might still be holding the old one.
func TestPairAbortsIfServiceWillNotStop(t *testing.T) {
	claim := newClaimServer(t, "")
	claim.response = goodClaimResponse(t, "https://new.vaultguardian.io")
	h := newPairHarness(t, existingEnv, claim)
	h.opts.StopService = func(context.Context) error {
		h.events = append(h.events, "stop-failed")
		return fmt.Errorf("unit observer is still active after 30s")
	}

	err := runPair(context.Background(), h.opts)
	if err == nil {
		t.Fatal("runPair should abort when the service will not stop")
	}
	if len(claim.claims) != 0 {
		t.Errorf("claims = %v; want none - the code must not be claimed while Observer may be running", claim.claims)
	}
	if got := h.env(t); got != existingEnv {
		t.Error("env changed even though pairing aborted before the claim")
	}
}

// The URL comes from the flag, or from the pairing this box already has, and a
// never-paired box with neither is told what to do.
func TestPairURLResolution(t *testing.T) {
	t.Run("falls back to SYNC_URL in the env", func(t *testing.T) {
		claim := newClaimServer(t, "")
		claim.response = goodClaimResponse(t, claim.URL)
		// Point the seeded env at the mock so the fallback has somewhere real
		// to go, and clear the flag.
		env := strings.Replace(existingEnv, "SYNC_URL=https://old.vaultguardian.io",
			"SYNC_URL="+claim.URL, 1)
		h := newPairHarness(t, env, claim)
		h.opts.URL = ""

		if err := runPair(context.Background(), h.opts); err != nil {
			t.Fatalf("runPair: %v", err)
		}
		if len(claim.claims) != 1 {
			t.Errorf("claims = %d; want 1 via the env fallback", len(claim.claims))
		}
	})

	t.Run("required on a first pairing", func(t *testing.T) {
		claim := newClaimServer(t, "")
		h := newPairHarness(t, "DATA_DIR=/var/lib/observer\n", claim)
		h.opts.URL = ""

		err := runPair(context.Background(), h.opts)
		if err == nil || !strings.Contains(err.Error(), "--url") {
			t.Errorf("error = %v; want a message telling the operator to pass --url", err)
		}
		if len(claim.claims) != 0 {
			t.Error("a code was claimed without a resolved URL")
		}
	})
}

func TestCanonicalPairingCode(t *testing.T) {
	cases := map[string]string{
		"abcd-efgh":        "ABCDEFGH",
		"ABCD EFGH":        "ABCDEFGH",
		" abcd\t-\tefgh\n": "ABCDEFGH",
		"ABCDEFGH":         "ABCDEFGH",
		"":                 "",
	}
	for in, want := range cases {
		if got := canonicalPairingCode(in); got != want {
			t.Errorf("canonicalPairingCode(%q) = %q; want %q", in, got, want)
		}
	}
}

// A missing code is refused before anything is stopped or claimed.
func TestPairRequiresCode(t *testing.T) {
	claim := newClaimServer(t, "")
	h := newPairHarness(t, existingEnv, claim)
	h.opts.Code = "  -- "

	if err := runPair(context.Background(), h.opts); err == nil {
		t.Fatal("runPair should require a pairing code")
	}
	if len(h.events) != 0 {
		t.Errorf("service events = %v; want none", h.events)
	}
}
