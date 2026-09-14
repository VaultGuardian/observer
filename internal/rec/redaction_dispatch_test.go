// internal/rec/redaction_dispatch_test.go
//
// FIX 3 (fix round v3): the three-way markup-prologue dispatch. XML-ish
// prologues classify FormatXML under EVERY content type - the CT fast path
// must never see them first - and stay withheld unless the unchanged XML-RPC
// redactor accepts them. Only the token-bounded HTML doctype takes the HTML
// path.
package rec

import (
	"strings"
	"testing"
)

// dispatchCTs: the content types every dispatch fixture runs under. The
// text/html entry is the load-bearing one - it exercises "misleading MIME
// must not reach the CT fast path".
var dispatchCTs = []string{"text/xml", "", "text/html"}

const dispatchSecret = "SECRET-9f8e7d6c-DO-NOT-LEAK"

func TestDispatch_XMLishAlwaysFormatXMLWithheld(t *testing.T) {
	doctypeMethodResponse := `<!DOCTYPE methodResponse><methodResponse><params><param><value><string>` +
		dispatchSecret + `</string></value></param></params></methodResponse>`
	cases := []struct {
		name string
		body string
	}{
		{"doctype_led_methodResponse_with_secret", doctypeMethodResponse},
		{"doctype_internal_subset", `<!DOCTYPE methodResponse [<!ENTITY x "` + dispatchSecret + `">]><methodResponse><params><param><value>&x;</value></param></params></methodResponse>`},
		{"comment_led_methodResponse", `<!-- prologue comment --><methodResponse><params><param><value><string>` + dispatchSecret + `</string></value></param></params></methodResponse>`},
		{"comment_led_html", `<!-- looks like html next --><html><body>` + dispatchSecret + `</body></html>`},
		{"oversized_prologue", `<!doctype ` + strings.Repeat(" ", 600) + `html><html>` + dispatchSecret + `</html>`},
		{"unclosed_comment", `<!--` + dispatchSecret},
		{"unclosed_doctype", `<!DOCTYPE methodResponse ` + dispatchSecret},
		{"truncated_doctype_token", `<!DOCT`},
		{"declaration_led_xhtml", `<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body><p>` + dispatchSecret + `</p></body></html>`},
		{"non_html_doctype_name", `<!doctype htmlfoo><html>` + dispatchSecret + `</html>`},
		{"doctype_missing_whitespace", `<!doctypehtml><html>` + dispatchSecret + `</html>`},
		{"uppercase_reserved_pi", `<?XML version="1.0"?><methodResponse></methodResponse>`},
		// FIX A (fix round v4): the html name alone is not enough - the
		// WHOLE declaration is inspected. An internal subset behind the
		// html name is the DTD-smuggling shape that previously leaked
		// through redactHTML; an unclosed declaration fails closed too.
		{"html_doctype_internal_subset", `<!DOCTYPE html [<!ENTITY x "` + dispatchSecret + `">]><html/>`},
		{"html_doctype_truncated_at_preview_end", `<!DOCTYPE html`},
		{"html_doctype_unclosed_with_junk", `<!DOCTYPE html SYSTEM "about:legacy-compat`},
	}
	for _, tc := range cases {
		for _, ct := range dispatchCTs {
			t.Run(tc.name+"/ct="+ctLabel(ct), func(t *testing.T) {
				a := ClassifyAndRedact([]byte(tc.body), ct, true)
				if a.Format != FormatXML {
					t.Fatalf("Format = %q, want %q (XML-ish prologue must never fall back)", a.Format, FormatXML)
				}
				if a.RedactedPreview() != "" {
					t.Errorf("preview not withheld: %q", a.RedactedPreview())
				}
				if a.RedactionConfidence != ConfidenceNone {
					t.Errorf("RedactionConfidence = %q, want %q", a.RedactionConfidence, ConfidenceNone)
				}
				if strings.Contains(a.RedactedPreview(), dispatchSecret) ||
					strings.Contains(a.DisclosureSummary, dispatchSecret) {
					t.Errorf("secret leaked into output")
				}
			})
		}
	}
}

func TestDispatch_HTMLDoctypeTokenBounded(t *testing.T) {
	htmlBodies := []struct {
		name string
		body string
	}{
		{"plain", `<!doctype html><html><body>welcome</body></html>`},
		{"uppercase", `<!DOCTYPE HTML><html></html>`},
		{"legacy_public", `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN"><html></html>`},
		// FIX A: the full legacy form with a quoted system-identifier URL -
		// the '/' characters inside the quoted string are inert.
		{"legacy_public_with_url", `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1.dtd"><html>`},
		// FIX A quote-respecting proof: '[' and '>' INSIDE quoted literals
		// neither terminate the declaration nor trip the subset check.
		{"quoted_bracket_and_gt", `<!DOCTYPE html PUBLIC "a[b" "c>d"><html>`},
	}
	for _, tc := range htmlBodies {
		for _, ct := range dispatchCTs {
			t.Run(tc.name+"/ct="+ctLabel(ct), func(t *testing.T) {
				a := ClassifyAndRedact([]byte(tc.body), ct, true)
				if a.Format != FormatHTML {
					t.Fatalf("Format = %q, want %q (regression: html doctype keeps the HTML path)", a.Format, FormatHTML)
				}
				if a.RedactionConfidence != ConfidenceHigh {
					t.Errorf("RedactionConfidence = %q, want %q", a.RedactionConfidence, ConfidenceHigh)
				}
			})
		}
	}

	// "htmlfoo" is not the html token: never high-confidence HTML - it is
	// XML-ish and withheld.
	a := ClassifyAndRedact([]byte(`<!doctype htmlfoo>`), "text/html", true)
	if a.Format == FormatHTML {
		t.Errorf("<!doctype htmlfoo> classified FormatHTML - token bound broken")
	}
	if a.Format != FormatXML || a.RedactedPreview() != "" {
		t.Errorf("<!doctype htmlfoo> = %q preview=%q, want xml/withheld", a.Format, a.RedactedPreview())
	}

	// FIX A, malformed-trailing variant from the committee spec: junk after
	// the quoted identifiers MAY fail closed - either outcome is tolerated -
	// but the quoted '[' and '>' must never be what decides it. The only
	// hard requirement: no permissive low-confidence HTML, no leak. (Current
	// behavior: the trailing unquoted '>' closes the declaration → HTML.)
	junk := ClassifyAndRedact([]byte(`<!DOCTYPE html PUBLIC "a[b" "c>d"e junk><html>`), "text/html", true)
	switch {
	case junk.Format == FormatHTML && junk.RedactionConfidence == ConfidenceHigh:
		// accepted: quotes respected, declaration closed cleanly
	case junk.Format == FormatXML && junk.RedactedPreview() == "":
		// accepted: failed closed
	default:
		t.Errorf("malformed-trailing doctype = %q/%q preview=%q - neither clean HTML nor fail-closed XML",
			junk.Format, junk.RedactionConfidence, junk.RedactedPreview())
	}
}

func TestDispatch_ValidXMLRPCStillAccepted(t *testing.T) {
	// The dispatch must not disturb the redactor's acceptance authority:
	// declaration-led and declaration-less XML-RPC still parse and redact.
	for _, ct := range dispatchCTs {
		a := ClassifyAndRedact([]byte(wpFaultBody), ct, true)
		if a.Format != FormatXML || a.RedactedPreview() != wpFaultRedacted {
			t.Errorf("ct=%q: canonical fault no longer accepted: format=%q preview=%q", ct, a.Format, a.RedactedPreview())
		}
	}
	a := ClassifyAndRedact([]byte(`<methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`), "text/html", true)
	if a.Format != FormatXML || a.RedactedPreview() == "" {
		t.Errorf("declaration-less XML-RPC regressed: format=%q preview=%q", a.Format, a.RedactedPreview())
	}
}

func ctLabel(ct string) string {
	if ct == "" {
		return "empty"
	}
	return strings.ReplaceAll(ct, "/", "_")
}
