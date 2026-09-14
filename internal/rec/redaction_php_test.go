// internal/rec/redaction_php_test.go
package rec

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestLooksLikePHPSource(t *testing.T) {
	yes := []string{
		"<?php\necho 'hi';",
		"<?php echo getenv('DB_PASSWORD');",
		"<?php/* comment */",
		"<?php", // end-of-preview directly after the marker
		"  \n\t<?php echo 1;",
		"\xEF\xBB\xBF<?php echo 1;", // UTF-8 BOM
	}
	for _, b := range yes {
		if !LooksLikePHPSource([]byte(b)) {
			t.Errorf("LooksLikePHPSource(%q) = false, want true", b)
		}
	}

	no := []string{
		`<?xml version="1.0"?><methodResponse></methodResponse>`, // <?xml is not <?php
		"<? echo 1;",   // short tag must NOT match
		"<?phpinfo();", // marker not followed by whitespace / '/' / EOF
		"<?ph",         // truncated before the full marker
		"<html><body><?php in docs</body></html>", // anchored at body start only
		"Use <?php to open a PHP block.",          // escaped/quoted in prose
		"<html><h1>Welcome</h1></html>",           // executed-PHP HTML output
		"",
	}
	for _, b := range no {
		if LooksLikePHPSource([]byte(b)) {
			t.Errorf("LooksLikePHPSource(%q) = true, want false", b)
		}
	}
}

func TestDetectFormat_PHPAndXMLPrecedeContentType(t *testing.T) {
	// PHP source served as text/html must NOT take the HTML fast path -
	// redactHTML would expose source as visible text.
	format, conf := detectFormat([]byte("<?php echo $dbPassword;"), "text/html")
	if format != FormatPHP {
		t.Fatalf("detectFormat(php, text/html) = %q, want %q", format, FormatPHP)
	}
	if conf != ConfidenceHigh {
		t.Errorf("confidence = %q, want %q (high confidence in the FORMAT)", conf, ConfidenceHigh)
	}

	// Valid XML-RPC served as text/html (misleading MIME) must classify XML.
	format, _ = detectFormat([]byte(wpFaultBody), "text/html")
	if format != FormatXML {
		t.Fatalf("detectFormat(xmlrpc, text/html) = %q, want %q", format, FormatXML)
	}

	// Declaration-less document whose first element is <methodResponse>.
	format, _ = detectFormat([]byte("<methodResponse><params></params></methodResponse>"), "")
	if format != FormatXML {
		t.Errorf("declaration-less methodResponse = %q, want %q", format, FormatXML)
	}

	// PEM stays first overall: a PHP file leaking an embedded private key is
	// PEM (key material outranks source-code identity).
	pem := "<?php $key = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB';"
	format, _ = detectFormat([]byte(pem), "")
	if format != FormatPEM {
		t.Errorf("embedded PEM in PHP source = %q, want %q", format, FormatPEM)
	}

	// Generic HTML fall-through unchanged.
	format, conf = detectFormat([]byte("<div>hello</div>"), "")
	if format != FormatHTML || conf != ConfidenceLow {
		t.Errorf("generic tag = %q/%q, want html/low", format, conf)
	}
}

func TestClassifyAndRedact_PHPFailClosed(t *testing.T) {
	for _, ct := range []string{"", "text/html", "application/octet-stream"} {
		a := classifyAndRedact([]byte("<?php echo getenv('SECRET');"), ct, true)
		if a.Format != FormatPHP {
			t.Fatalf("ct=%q: Format = %q, want %q", ct, a.Format, FormatPHP)
		}
		if a.RedactedPreview() != "" {
			t.Errorf("ct=%q: PHP body produced a preview: %q", ct, a.RedactedPreview())
		}
		if a.RedactionConfidence != ConfidenceNone {
			t.Errorf("ct=%q: RedactionConfidence = %q, want %q", ct, a.RedactionConfidence, ConfidenceNone)
		}
		if a.SensitiveRedactions != 1 {
			t.Errorf("ct=%q: SensitiveRedactions = %d, want 1 (Lane A gate)", ct, a.SensitiveRedactions)
		}
		if a.DisclosureSummary != "PHP SOURCE CODE DETECTED - METADATA ONLY" {
			t.Errorf("ct=%q: DisclosureSummary = %q", ct, a.DisclosureSummary)
		}
	}
}

// =============================================================================
// readBodyPreview completeness flag (Part 1e)
// =============================================================================

// errAfterReader yields its payload then a non-EOF error.
type errAfterReader struct {
	data []byte
	pos  int
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if r.pos < len(r.data) {
		n := copy(p, r.data[r.pos:])
		r.pos += n
		return n, nil
	}
	return 0, errors.New("connection reset")
}

func TestReadBodyPreview_Completeness(t *testing.T) {
	const maxBody = 16

	t.Run("clean_short_body_complete", func(t *testing.T) {
		body, complete := readBodyPreview(bytes.NewReader([]byte("hello")), maxBody)
		if string(body) != "hello" || !complete {
			t.Errorf("got body=%q complete=%v, want hello/true", body, complete)
		}
	})

	t.Run("exactly_maxbody_complete", func(t *testing.T) {
		in := strings.Repeat("x", maxBody)
		body, complete := readBodyPreview(strings.NewReader(in), maxBody)
		if len(body) != maxBody || !complete {
			t.Errorf("got len=%d complete=%v, want %d/true (exact fit is complete)", len(body), complete, maxBody)
		}
	})

	t.Run("one_byte_over_incomplete", func(t *testing.T) {
		in := strings.Repeat("x", maxBody+1)
		body, complete := readBodyPreview(strings.NewReader(in), maxBody)
		if len(body) != maxBody {
			t.Errorf("preview len = %d, want %d (never retain past the cap)", len(body), maxBody)
		}
		if complete {
			t.Errorf("complete = true for oversized body, want false")
		}
	})

	t.Run("read_error_incomplete", func(t *testing.T) {
		body, complete := readBodyPreview(&errAfterReader{data: []byte("part")}, maxBody)
		if string(body) != "part" {
			t.Errorf("preview = %q, want the bytes read before the error", body)
		}
		if complete {
			t.Errorf("complete = true after a mid-body read error, want false")
		}
	})

	t.Run("drain_error_incomplete", func(t *testing.T) {
		// Error surfaces only in the drain (past maxBody+1 bytes read).
		r := &errAfterReader{data: []byte(strings.Repeat("y", maxBody+5))}
		body, complete := readBodyPreview(r, maxBody)
		if len(body) != maxBody || complete {
			t.Errorf("got len=%d complete=%v, want %d/false", len(body), complete, maxBody)
		}
	})
}
