// internal/rec/redaction_xmlrpc_test.go
package rec

import (
	"strings"
	"testing"
)

// Real bodies captured 2026-09-14 from wp.soak.vaultguardian.io
// (WordPress 6.9.4), byte-exact as served: UTF-8 declaration, two-space
// indent, trailing newline. Do not reformat or re-indent - the production
// wire shape, inter-element whitespace included, is exactly what these
// tests pin. The canonical previews below carry no whitespace because the
// emitter reconstructs the document from accepted tokens rather than
// splicing input ranges.

// wpFaultBody is the auth-failure fault - the shape the Sept 12-13 flood
// produced ~46K times.
const wpFaultBody = `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
`

const wpFaultRedacted = `<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>403</int></value></member><member><name>faultString</name><value><string>[STRING]</string></value></member></struct></value></fault></methodResponse>`

// wpUnknownMethodBody is the unknown-method fault from the same capture.
const wpUnknownMethodBody = `<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>-32601</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>server error. requested method wp.bogus does not exist.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
`

const wpUnknownMethodRedacted = `<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>-32601</int></value></member><member><name>faultString</name><value><string>[STRING]</string></value></member></struct></value></fault></methodResponse>`

// wpFaults drives the fixture-based tests in this file over BOTH captured
// bodies. A negative faultCode (-32601) is still a valid int32 and must be
// preserved verbatim, exactly as 403 is.
var wpFaults = []struct {
	name           string
	body           string
	redacted       string
	faultCode      string // int value preserved verbatim in the preview
	secret         string // full faultString content, for padding replacement
	secretFragment string // distinctive fragment that must never survive
}{
	{
		name:           "auth_failure",
		body:           wpFaultBody,
		redacted:       wpFaultRedacted,
		faultCode:      "403",
		secret:         "Incorrect username or password.",
		secretFragment: "Incorrect username",
	},
	{
		name:           "unknown_method",
		body:           wpUnknownMethodBody,
		redacted:       wpUnknownMethodRedacted,
		faultCode:      "-32601",
		secret:         "server error. requested method wp.bogus does not exist.",
		secretFragment: "wp.bogus",
	},
}

func TestRedactXMLRPC_CanonicalWordPressFault(t *testing.T) {
	for _, f := range wpFaults {
		t.Run(f.name, func(t *testing.T) {
			out, redactions, ok := redactXMLRPC([]byte(f.body), true)
			if !ok {
				t.Fatalf("captured WordPress fault body failed to parse")
			}
			if out != f.redacted {
				t.Errorf("redacted preview:\n  got:  %q\n  want: %q", out, f.redacted)
			}
			if redactions != 1 {
				t.Errorf("redactions = %d, want 1 (the faultString value)", redactions)
			}
			if !strings.Contains(out, "<value><int>"+f.faultCode+"</int></value>") {
				t.Errorf("faultCode int %s not preserved in preview: %q", f.faultCode, out)
			}
			if strings.Contains(out, f.secretFragment) {
				t.Errorf("secret fault message survived into preview")
			}
		})
	}
}

func TestRedactXMLRPC_SuccessAndFaultSameLengthDiverge(t *testing.T) {
	// Same HTTP-status semantics, same byte length (strings padded), but a
	// success-params document vs a fault document must produce DIFFERENT
	// redacted previews and different hashes.
	for _, f := range wpFaults {
		t.Run(f.name, func(t *testing.T) {
			fault := f.body
			successFmt := `<?xml version="1.0" encoding="UTF-8"?><methodResponse><params><param><value><struct><member><name>result</name><value><string>%s</string></value></member></struct></value></param></params></methodResponse>`
			pad := len(fault) - (len(successFmt) - len("%s"))
			if pad < 0 {
				t.Fatalf("success skeleton longer than fault fixture by %d bytes", -pad)
			}
			success := strings.Replace(successFmt, "%s", strings.Repeat("w", pad), 1)
			if len(fault) != len(success) {
				t.Fatalf("fixture lengths diverged: fault=%d success=%d", len(fault), len(success))
			}

			fOut, _, fOK := redactXMLRPC([]byte(fault), true)
			sOut, _, sOK := redactXMLRPC([]byte(success), true)
			if !fOK || !sOK {
				t.Fatalf("parse failed: fault=%v success=%v", fOK, sOK)
			}
			if fOut == sOut {
				t.Errorf("fault and success previews identical - outcome divergence lost")
			}
			if HashBody([]byte(fOut)) == HashBody([]byte(sOut)) {
				t.Errorf("fault and success preview hashes identical")
			}
			if !strings.Contains(fOut, "<fault>") || strings.Contains(sOut, "<fault>") {
				t.Errorf("envelope shape not preserved: fault=%q success=%q", fOut, sOut)
			}
		})
	}
}

func TestRedactXMLRPC_FaultCodeMemberInSuccessPayloadIsRedacted(t *testing.T) {
	// A member literally named faultCode inside a success payload stays
	// success-shaped with the name redacted like any other member.
	body := `<methodResponse><params><param><value><struct><member><name>faultCode</name><value><int>500</int></value></member></struct></value></param></params></methodResponse>`
	out, redactions, ok := redactXMLRPC([]byte(body), true)
	if !ok {
		t.Fatalf("success payload with faultCode member failed to parse")
	}
	if strings.Contains(out, "faultCode") {
		t.Errorf("faultCode name preserved outside validated fault position: %q", out)
	}
	if strings.Contains(out, "500") {
		t.Errorf("int value preserved outside validated faultCode position: %q", out)
	}
	if !strings.Contains(out, "<params>") || strings.Contains(out, "<fault>") {
		t.Errorf("document did not stay success-shaped: %q", out)
	}
	if redactions != 2 { // member name + int value
		t.Errorf("redactions = %d, want 2", redactions)
	}
}

func TestRedactXMLRPC_MulticallNestedArraysWithFaultShapedResults(t *testing.T) {
	// system.multicall-style: an array mixing a fault-shaped struct and a
	// normal result. All names/values redacted, document stays success-shaped.
	body := `<methodResponse><params><param><value><array><data>` +
		`<value><struct><member><name>faultCode</name><value><int>-32601</int></value></member><member><name>faultString</name><value><string>method not found</string></value></member></struct></value>` +
		`<value><array><data><value><string>ok-result</string></value></data></array></value>` +
		`</data></array></value></param></params></methodResponse>`
	out, _, ok := redactXMLRPC([]byte(body), true)
	if !ok {
		t.Fatalf("multicall-style document failed to parse")
	}
	for _, leaked := range []string{"faultCode", "faultString", "-32601", "method not found", "ok-result"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%q survived into the multicall preview: %q", leaked, out)
		}
	}
	if strings.Contains(out, "<fault>") {
		t.Errorf("success-shaped multicall grew a fault envelope: %q", out)
	}
}

func TestRedactXMLRPC_SecretsNeverSurvive(t *testing.T) {
	// Secrets planted in member names, explicit strings, implicit strings,
	// CDATA, base64, and fault messages - none may survive redaction.
	cases := []struct {
		name   string
		body   string
		secret string
	}{
		{
			"member_name",
			`<methodResponse><params><param><value><struct><member><name>SECRET_API_KEY_NAME</name><value><int>1</int></value></member></struct></value></param></params></methodResponse>`,
			"SECRET_API_KEY_NAME",
		},
		{
			"explicit_string",
			`<methodResponse><params><param><value><string>hunter2-explicit</string></value></param></params></methodResponse>`,
			"hunter2-explicit",
		},
		{
			"implicit_string",
			`<methodResponse><params><param><value>hunter2-implicit</value></param></params></methodResponse>`,
			"hunter2-implicit",
		},
		{
			"cdata",
			`<methodResponse><params><param><value><![CDATA[hunter2-cdata <b>raw</b>]]></value></param></params></methodResponse>`,
			"hunter2-cdata",
		},
		{
			"base64",
			`<methodResponse><params><param><value><base64>aHVudGVyMi1iNjQ=</base64></value></param></params></methodResponse>`,
			"aHVudGVyMi1iNjQ=",
		},
		{
			"fault_message_auth_failure",
			wpFaultBody,
			"Incorrect username or password",
		},
		{
			"fault_message_unknown_method",
			wpUnknownMethodBody,
			"requested method wp.bogus does not exist",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, redactions, ok := redactXMLRPC([]byte(tc.body), true)
			if !ok {
				t.Fatalf("fixture failed to parse")
			}
			if strings.Contains(out, tc.secret) {
				t.Errorf("secret %q survived into preview: %q", tc.secret, out)
			}
			if redactions == 0 {
				t.Errorf("redactions = 0, want >0")
			}
		})
	}
}

func TestRedactXMLRPC_Rejections(t *testing.T) {
	pad := strings.Repeat("A", 64)
	longName := strings.Repeat("n", 65)
	deepValue := strings.Repeat("<value><array><data>", 6) + "<value><int>1</int></value>" + strings.Repeat("</data></array></value>", 6)
	// 65 items in one <data> breaches the per-container cap (shared with
	// struct members; 65 minimal struct members cannot fit inside the
	// 2048-byte input cap, so the data-items path is the reachable breach).
	manyItems := strings.Repeat("<value/>", 65)
	// >512 tokens inside <=2048 input bytes: whitespace CharData + <value/>
	// is 3 tokens per 9 bytes, nested so no single <data> exceeds 64 items.
	tokenItems := strings.Repeat(" <value/>", 60) // 180 tokens, 540 bytes
	tokenL3 := "<value><array><data>" + tokenItems + "</data></array></value>"
	tokenL2 := "<value><array><data>" + tokenItems + tokenL3 + "</data></array></value>"
	manyTokens := tokenItems + tokenL2 // ~550 tokens total under the envelope
	// >2048 output bytes from <=2048 input bytes: <value/> (8 bytes) redacts
	// to <value>[STRING]</value> (23 bytes), so 121 values overflow the
	// output cap while every other limit holds.
	outItems := strings.Repeat("<value/>", 60)
	outValues := outItems + "<value><array><data>" + outItems + "</data></array></value>"

	cases := []struct {
		name string
		body string
	}{
		{"internal_dtd", `<?xml version="1.0"?><!DOCTYPE methodResponse [<!ENTITY x "y">]><methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"external_dtd", `<?xml version="1.0"?><!DOCTYPE methodResponse SYSTEM "http://evil.example/dtd"><methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"entity_expansion", `<?xml version="1.0"?><!DOCTYPE a [<!ENTITY b "` + pad + `"><!ENTITY c "&b;&b;&b;&b;">]><methodResponse><params><param><value>&c;</value></param></params></methodResponse>`},
		{"undeclared_entity", `<methodResponse><params><param><value>&custom;</value></param></params></methodResponse>`},
		{"comment", `<methodResponse><!-- comment --><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"non_leading_pi", `<methodResponse><?php echo 1; ?><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"second_xml_decl", `<?xml version="1.0"?><?xml version="1.0"?><methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"namespace_on_root", `<methodResponse xmlns="http://example.com"><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"prefixed_element", `<x:methodResponse><x:params><x:param><x:value><x:int>1</x:int></x:value></x:param></x:params></x:methodResponse>`},
		{"attribute_on_value", `<methodResponse><params><param><value type="int">1</value></param></params></methodResponse>`},
		{"unsupported_element", `<methodResponse><params><param><value><i4>1</i4></value></param></params></methodResponse>`},
		{"wrong_root", `<params><param><value><int>1</int></value></param></params>`},
		{"two_roots", `<methodResponse><params><param><value><int>1</int></value></param></params></methodResponse><methodResponse></methodResponse>`},
		{"trailing_junk", `<methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>junk`},
		{"both_fault_and_params", `<methodResponse><params><param><value><int>1</int></value></param></params><fault><value><struct><member><name>faultCode</name><value><int>1</int></value></member><member><name>faultString</name><value><string>x</string></value></member></struct></value></fault></methodResponse>`},
		{"neither_fault_nor_params", `<methodResponse></methodResponse>`},
		{"duplicate_fault_code_members", `<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>1</int></value></member><member><name>faultCode</name><value><int>2</int></value></member><member><name>faultString</name><value><string>x</string></value></member></struct></value></fault></methodResponse>`},
		{"fault_missing_fault_string", `<methodResponse><fault><value><struct><member><name>faultCode</name><value><int>1</int></value></member></struct></value></fault></methodResponse>`},
		{"fault_value_not_struct", `<methodResponse><fault><value><string>oops</string></value></fault></methodResponse>`},
		{"two_params", `<methodResponse><params><param><value><int>1</int></value></param><param><value><int>2</int></value></param></params></methodResponse>`},
		{"mixed_content_value", `<methodResponse><params><param><value>text<int>1</int></value></param></params></methodResponse>`},
		{"truncated_mid_declaration", `<?xml version="1.`},
		{"truncated_mid_tag", `<methodResponse><params><para`},
		{"truncated_mid_value", `<methodResponse><params><param><value><string>hun`},
		{"truncated_mid_cdata", `<methodResponse><params><param><value><![CDATA[hun`},
		{"depth_limit", `<methodResponse><params><param>` + deepValue + `</param></params></methodResponse>`},
		{"container_item_limit", `<methodResponse><params><param><value><array><data>` + manyItems + `</data></array></value></param></params></methodResponse>`},
		{"token_limit", `<methodResponse><params><param><value><array><data>` + manyTokens + `</data></array></value></param></params></methodResponse>`},
		{"output_limit", `<methodResponse><params><param><value><array><data>` + outValues + `</data></array></value></param></params></methodResponse>`},
		{"name_length_limit", `<methodResponse><params><param><value><struct><member><name>` + longName + `</name><value><int>1</int></value></member></struct></value></param></params></methodResponse>`},
		{"unsupported_encoding_declaration", `<?xml version="1.0" encoding="ISO-8859-1"?><methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"xhtml_as_xml_grammar_fails", `<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body><p>hi</p></body></html>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, redactions, ok := redactXMLRPC([]byte(tc.body), true)
			if ok {
				t.Fatalf("expected fail-closed rejection, got preview %q", out)
			}
			if out != "" || redactions != 0 {
				t.Errorf("failed parse leaked output: out=%q redactions=%d", out, redactions)
			}
		})
	}
}

func TestRedactXMLRPC_InputRequirements(t *testing.T) {
	for _, f := range wpFaults {
		t.Run(f.name, func(t *testing.T) {
			// Body incomplete flag → fail even for a valid document.
			if _, _, ok := redactXMLRPC([]byte(f.body), false); ok {
				t.Errorf("incomplete body accepted - completeness flag is required")
			}

			// Over 2048 input bytes → fail; a valid document padded to EXACTLY
			// 2048 bytes is accepted.
			padded := strings.Replace(f.body, f.secret,
				strings.Repeat("p", 2048-len(f.body)+len(f.secret)), 1)
			if len(padded) != 2048 {
				t.Fatalf("fixture padding wrong: %d bytes, want 2048", len(padded))
			}
			if _, _, ok := redactXMLRPC([]byte(padded), true); !ok {
				t.Errorf("exact-2048-byte valid body rejected")
			}
			if _, _, ok := redactXMLRPC([]byte(padded+" "), true); ok {
				t.Errorf("2049-byte body accepted, want input-size rejection")
			}

			// Depth exactly at the limit is fine (captured fault is depth 7).
			if _, _, ok := redactXMLRPC([]byte(f.body), true); !ok {
				t.Errorf("captured body rejected")
			}
		})
	}
}

func TestRedactXMLRPC_AcceptedVariants(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"missing_xml_declaration", `<methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"utf8_bom", "\xEF\xBB\xBF" + wpFaultBody},
		{"utf8_bom_unknown_method", "\xEF\xBB\xBF" + wpUnknownMethodBody},
		{"leading_whitespace", "\n  " + wpFaultBody},
		{"leading_whitespace_unknown_method", "\n  " + wpUnknownMethodBody},
		{"numeric_character_references", `<methodResponse><params><param><value><string>a&#65;&#x42;</string></value></param></params></methodResponse>`},
		{"builtin_entities", `<methodResponse><params><param><value><string>&lt;&gt;&amp;&apos;&quot;</string></value></param></params></methodResponse>`},
		{"utf8_encoding_declared", `<?xml version="1.0" encoding="utf-8"?><methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`},
		{"pretty_printed_whitespace", "<methodResponse>\n  <params>\n    <param>\n      <value><int>1</int></value>\n    </param>\n  </params>\n</methodResponse>"},
		{"empty_implicit_string", `<methodResponse><params><param><value></value></param></params></methodResponse>`},
		{"container_exactly_at_item_cap", `<methodResponse><params><param><value><array><data>` + strings.Repeat("<value/>", 64) + `</data></array></value></param></params></methodResponse>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, ok := redactXMLRPC([]byte(tc.body), true)
			if !ok {
				t.Fatalf("expected accept, got fail-closed")
			}
			if out == "" {
				t.Errorf("accepted document produced empty preview")
			}
		})
	}
}

func TestRedactXMLRPC_FaultCodeValueValidation(t *testing.T) {
	build := func(codeValue string) string {
		return `<methodResponse><fault><value><struct><member><name>faultCode</name>` + codeValue +
			`</member><member><name>faultString</name><value><string>msg</string></value></member></struct></value></fault></methodResponse>`
	}
	// Valid int32 → preserved (canonically re-emitted).
	out, _, ok := redactXMLRPC([]byte(build(`<value><int>-32601</int></value>`)), true)
	if !ok || !strings.Contains(out, "<value><int>-32601</int></value>") {
		t.Errorf("valid int32 faultCode not preserved: ok=%v out=%q", ok, out)
	}
	// Out of int32 range → redacted like any scalar, type tag kept.
	out, _, ok = redactXMLRPC([]byte(build(`<value><int>4294967296</int></value>`)), true)
	if !ok || !strings.Contains(out, "<value><int>[INT]</int></value>") {
		t.Errorf("overflowing faultCode not redacted: ok=%v out=%q", ok, out)
	}
	// Non-int scalar → redacted, type tag kept.
	out, _, ok = redactXMLRPC([]byte(build(`<value><string>403</string></value>`)), true)
	if !ok || !strings.Contains(out, "<value><string>[STRING]</string></value>") {
		t.Errorf("string faultCode not redacted: ok=%v out=%q", ok, out)
	}
}

func TestRedactXMLRPC_DifferentSecretsSameSanitizedPreview(t *testing.T) {
	// Two documents with DIFFERENT secret values yield IDENTICAL sanitized
	// previews. This is EXPECTED - the preview is a shape, not a transcript.
	// NOTE for Part 3 (interning): storage sharing of identical sanitized
	// previews must never imply transaction equality - identical shapes can
	// have different outcomes, and nothing may transfer one response's
	// verdict to a different response.
	for _, f := range wpFaults {
		t.Run(f.name, func(t *testing.T) {
			a := strings.Replace(f.body, f.secret, "secret-one-aaaaaaaaaaaaaaaaaaaa", 1)
			b := strings.Replace(f.body, f.secret, "secret-two-bbbbbbbbbbbbbbbbbbbb", 1)
			aOut, _, aOK := redactXMLRPC([]byte(a), true)
			bOut, _, bOK := redactXMLRPC([]byte(b), true)
			if !aOK || !bOK {
				t.Fatalf("parse failed: a=%v b=%v", aOK, bOK)
			}
			if aOut != bOut {
				t.Errorf("sanitized previews differ for same-shape documents:\n  a=%q\n  b=%q", aOut, bOut)
			}
		})
	}
}

func TestClassifyAndRedact_XMLArms(t *testing.T) {
	// Misleading MIME: text/html content type with a valid XML-RPC body must
	// still classify FormatXML, parse, and grant a high-confidence preview.
	for _, f := range wpFaults {
		t.Run(f.name, func(t *testing.T) {
			a := classifyAndRedact([]byte(f.body), "text/html", true)
			if a.Format != FormatXML {
				t.Fatalf("Format = %q, want %q (misleading MIME must not win)", a.Format, FormatXML)
			}
			if a.RedactionConfidence != ConfidenceHigh {
				t.Errorf("RedactionConfidence = %q, want %q", a.RedactionConfidence, ConfidenceHigh)
			}
			if a.RedactedPreview() != f.redacted {
				t.Errorf("preview = %q, want canonical redaction", a.RedactedPreview())
			}
			if a.SensitiveRedactions != 1 {
				t.Errorf("SensitiveRedactions = %d, want 1", a.SensitiveRedactions)
			}
			if a.DisclosureSummary != "XML-RPC RESPONSE STRUCTURE DETECTED" {
				t.Errorf("DisclosureSummary = %q", a.DisclosureSummary)
			}

			// Incomplete body: format recognized, parse refused, fail closed.
			inc := classifyAndRedact([]byte(f.body), "text/xml", false)
			if inc.Format != FormatXML || inc.RedactedPreview() != "" || inc.RedactionConfidence != ConfidenceNone {
				t.Errorf("incomplete XML body not fail-closed: format=%q preview=%q conf=%q",
					inc.Format, inc.RedactedPreview(), inc.RedactionConfidence)
			}
		})
	}

	// XHTML served as text/html starting with <?xml: FormatXML, grammar
	// fails, preview withheld. Documented accepted fail-closed behavior.
	xhtml := `<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body><p>welcome</p></body></html>`
	x := classifyAndRedact([]byte(xhtml), "text/html", true)
	if x.Format != FormatXML {
		t.Fatalf("XHTML Format = %q, want %q", x.Format, FormatXML)
	}
	if x.RedactedPreview() != "" || x.RedactionConfidence != ConfidenceNone {
		t.Errorf("XHTML preview not withheld: preview=%q conf=%q", x.RedactedPreview(), x.RedactionConfidence)
	}
	if x.DisclosureSummary != "XML CONTENT DETECTED - METADATA ONLY" {
		t.Errorf("XHTML DisclosureSummary = %q", x.DisclosureSummary)
	}
}
