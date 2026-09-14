// verifycallback_test.go - fix round v3, FIX 3 (verifier leg) + FIX 4: the
// catch-all verifier must honor fail-closed formats. A withheld preview for
// PHP/PEM/XML is never substituted with the raw body, never auto-confirmed
// on hash consistency, and never persisted as a verified catch-all; with the
// FIX 3 dispatch, every rejected-XML prologue shape carries FormatXML here
// and is covered by construction.
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
)

// verifyHarness runs makeVerifyCallback against a live httptest server. The
// verifier dials http://127.0.0.1<SamplePath>, so the harness passes
// ":PORT/path" as the sample path to reach the test server.
type verifyHarness struct {
	verify coordinator.VerifyFunc
	stub   *reclassLLMStub
	db     *store.Store
	server *httptest.Server
	port   string

	// mutable fixture served by the test server
	body        []byte
	contentType string // "" = suppress the Content-Type header entirely
}

func newVerifyHarness(t *testing.T, verdictJSON string) *verifyHarness {
	t.Helper()
	h := &verifyHarness{stub: newReclassLLMStub(t, verdictJSON, 0)}

	db, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h.db = db

	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.contentType == "" {
			// Suppress Go's automatic content sniffing so the verifier sees
			// a response with NO Content-Type header (the empty-ct leg).
			w.Header()["Content-Type"] = nil
		} else {
			w.Header().Set("Content-Type", h.contentType)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(h.body)
	}))
	t.Cleanup(h.server.Close)
	u, err := url.Parse(h.server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	h.port = u.Port()

	llmClient := llm.NewClient(h.stub.server.URL, "test-model", "", "low", "medium")
	h.verify = makeVerifyCallback(
		db,
		llmClient,
		coordinator.NewSelfSuppressor(),
		Config{LLMModel: "test-model", Tier2Effort: "medium"},
		NewLLMScheduler(1),
		context.Background(),
	)
	return h
}

// run serves (body, contentType) and verifies a fingerprint matching it.
func (h *verifyHarness) run(body []byte, contentType string) *coordinator.VerifyResult {
	h.body = body
	h.contentType = contentType
	return h.verify(coordinator.VerifyRequest{
		Fingerprint: coordinator.CatchAllFingerprint{
			Host:            "verify.example.com",
			Method:          "GET",
			StatusCode:      200,
			BodyPreviewHash: rec.HashBody(body),
		},
		SamplePath: ":" + h.port + "/probe",
	})
}

func (h *verifyHarness) assertNothingPersistedOrPrompted(t *testing.T, secret string) {
	t.Helper()
	if got := h.stub.calls.Load(); got != 0 {
		t.Errorf("LLM called %d times, want 0", got)
	}
	if secret != "" && h.stub.promptContains(secret) {
		t.Errorf("withheld content %q reached an LLM prompt", secret)
	}
	rules, err := h.db.LoadVerifiedCatchAlls(context.Background())
	if err != nil {
		t.Fatalf("LoadVerifiedCatchAlls: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("verified catch-all persisted for a fail-closed format: %d rules", len(rules))
	}
	rows, err := h.db.ListLLMDecisions(context.Background(), store.LLMDecisionFilter{Tier: "catchall_verify"})
	if err != nil {
		t.Fatalf("ListLLMDecisions: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("audit rows written for a fail-closed format: %d", len(rows))
	}
}

// TestVerify_PHPSourceNeverConfirmed (FIX 4): a matching PHP body ≤200 bytes
// must not be confirmed, must not put raw source into any prompt or audit
// EvidencePreview, and must not persist a catch-all.
func TestVerify_PHPSourceNeverConfirmed(t *testing.T) {
	const phpSecret = `hunter2-php-secret`
	body := []byte(`<?php $db_password = "` + phpSecret + `"; ?>`)
	if len(body) > 200 {
		t.Fatalf("fixture must stay in the ≤200-byte raw-substitution branch")
	}
	for _, ct := range []string{"text/html", ""} {
		t.Run("ct="+ctName(ct), func(t *testing.T) {
			h := newVerifyHarness(t, verdictGenericDowngrade)
			res := h.run(body, ct)
			if res.Confirmed {
				t.Fatalf("PHP source auto-confirmed: %q", res.Reason)
			}
			if !strings.Contains(res.Reason, "fail-closed format (php)") {
				t.Errorf("reason %q does not name the fail-closed format", res.Reason)
			}
			h.assertNothingPersistedOrPrompted(t, phpSecret)
		})
	}
}

// TestVerify_XMLShapesNeverAutoConfirmed (FIX 3 verifier leg + FIX 4): every
// dispatch-rejected XML prologue shape - DOCTYPE-led, internal subset,
// oversized prologue - carries FormatXML into the verifier and is neither
// raw-substituted nor hash-auto-confirmed, under text/xml, empty, and
// text/html content types.
func TestVerify_XMLShapesNeverAutoConfirmed(t *testing.T) {
	const xmlSecret = "SECRET-verify-xml-leak"
	fixtures := []struct {
		name string
		body string
	}{
		{"doctype_led_methodResponse", `<!DOCTYPE methodResponse><methodResponse><params><param><value><string>` + xmlSecret + `</string></value></param></params></methodResponse>`},
		{"doctype_internal_subset", `<!DOCTYPE methodResponse [<!ENTITY x "` + xmlSecret + `">]><methodResponse><params><param><value>&x;</value></param></params></methodResponse>`},
		{"oversized_prologue", `<!doctype ` + strings.Repeat(" ", 600) + `html><html>` + xmlSecret + `</html>`},
		{"comment_led", `<!-- lead --><methodResponse><params><param><value><string>` + xmlSecret + `</string></value></param></params></methodResponse>`},
		// FIX A (fix round v4): an internal subset hiding behind the html
		// doctype name must not reach redactHTML via the verifier either -
		// no raw substitution, no auto-confirm.
		{"html_doctype_internal_subset", `<!DOCTYPE html [<!ENTITY x "` + xmlSecret + `">]><html/>`},
	}
	for _, fx := range fixtures {
		if len(fx.body) > 2048 {
			t.Fatalf("fixture %s exceeds maxHash - would not exercise the auto-confirm branch", fx.name)
		}
		for _, ct := range []string{"text/xml", "", "text/html"} {
			t.Run(fx.name+"/ct="+ctName(ct), func(t *testing.T) {
				h := newVerifyHarness(t, verdictGenericDowngrade)
				res := h.run([]byte(fx.body), ct)
				if res.Confirmed {
					t.Fatalf("rejected-XML shape auto-confirmed: %q", res.Reason)
				}
				if !strings.Contains(res.Reason, "fail-closed format (xml)") {
					t.Errorf("reason %q does not carry FormatXML", res.Reason)
				}
				h.assertNothingPersistedOrPrompted(t, xmlSecret)
			})
		}
	}
}

// TestVerify_HTMLDoctypeNotFailClosed (FIX A regression, verifier leg): a
// well-formed legacy PUBLIC doctype with quoted identifiers keeps the HTML
// path through the verifier - it is NOT rejected as a fail-closed format,
// proving the quote-aware declaration scan does not over-reject.
func TestVerify_HTMLDoctypeNotFailClosed(t *testing.T) {
	body := []byte(`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1.dtd"><html><body>welcome page</body></html>`)
	for _, ct := range []string{"text/xml", "", "text/html"} {
		t.Run("ct="+ctName(ct), func(t *testing.T) {
			h := newVerifyHarness(t, verdictGenericDowngrade)
			res := h.run(body, ct)
			if strings.Contains(res.Reason, "fail-closed format") {
				t.Fatalf("well-formed html doctype hit the fail-closed guard: %q", res.Reason)
			}
			if got := h.stub.calls.Load(); got != 1 {
				t.Errorf("LLM called %d times, want 1 (HTML path judges the redacted preview)", got)
			}
			if !res.Confirmed {
				t.Errorf("HTML-path verification not confirmed under downgrade verdict: %q", res.Reason)
			}
		})
	}
}

// TestVerify_FormatUnknownTinyBodyLegacyUnchanged (FIX 4 regression): the
// pre-existing behavior for FormatUnknown stays: a tiny unclassifiable body
// is raw-substituted and judged by the LLM (deferred to the Phase 2 policy
// review, on the record).
func TestVerify_FormatUnknownTinyBodyLegacyUnchanged(t *testing.T) {
	h := newVerifyHarness(t, verdictGenericDowngrade)
	res := h.run([]byte("plain tiny response ok"), "")
	if !res.Confirmed {
		t.Fatalf("legacy FormatUnknown tiny-body path changed: not confirmed (%q)", res.Reason)
	}
	if got := h.stub.calls.Load(); got != 1 {
		t.Errorf("LLM called %d times, want 1 (legacy path judges via LLM)", got)
	}
	rules, err := h.db.LoadVerifiedCatchAlls(context.Background())
	if err != nil {
		t.Fatalf("LoadVerifiedCatchAlls: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("verified catch-all rules = %d, want 1 (legacy persistence unchanged)", len(rules))
	}
}

func ctName(ct string) string {
	if ct == "" {
		return "empty"
	}
	return strings.ReplaceAll(ct, "/", "_")
}
