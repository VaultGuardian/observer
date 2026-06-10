package rec

import (
	"strings"
	"testing"
)

// =============================================================================
// redactHTMLAttributes Tests
// =============================================================================

func TestRedactHTMLAttributes_PositionalAttrs(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want string
	}{
		{
			name: "input value",
			tag:  `<input type="text" value="secret123">`,
			want: `<input type="text" value="[REDACTED]">`,
		},
		{
			name: "textarea value",
			tag:  `<textarea name="bio" value="private notes">`,
			want: `<textarea name="bio" value="[REDACTED]">`,
		},
		{
			name: "meta content",
			tag:  `<meta name="csrf-token" content="abc123">`,
			want: `<meta name="csrf-token" content="[REDACTED]">`,
		},
		{
			name: "form action",
			tag:  `<form action="/login?return=/home" method="POST">`,
			want: `<form action="[REDACTED]" method="POST">`,
		},
		{
			name: "anchor href",
			tag:  `<a href="/reset?token=abc" class="btn">`,
			want: `<a href="[REDACTED]" class="btn">`,
		},
		{
			name: "link href",
			tag:  `<link rel="stylesheet" href="/styles?v=1">`,
			want: `<link rel="stylesheet" href="[REDACTED]">`,
		},
		{
			name: "img src",
			tag:  `<img src="/avatar?key=secret" alt="user">`,
			want: `<img src="[REDACTED]" alt="user">`,
		},
		{
			name: "iframe src",
			tag:  `<iframe src="/embed?token=abc">`,
			want: `<iframe src="[REDACTED]">`,
		},
		{
			name: "button formaction",
			tag:  `<button formaction="/submit?api_key=xxx">Save</button>`,
			want: `<button formaction="[REDACTED]">Save</button>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := redactHTMLAttributes(tt.tag)
			if got != tt.want {
				t.Errorf("redactHTMLAttributes(%q)\n  got:  %q\n  want: %q", tt.tag, got, tt.want)
			}
		})
	}
}

func TestRedactHTMLAttributes_SecretNamedAttrs(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want string
	}{
		{
			name: "data-api-key",
			tag:  `<div data-api-key="abc123" class="widget">`,
			want: `<div data-api-key="[REDACTED]" class="widget">`,
		},
		{
			name: "x-csrf-token",
			tag:  `<form x-csrf-token="abc" method="POST">`,
			want: `<form x-csrf-token="[REDACTED]" method="POST">`,
		},
		{
			name: "sessionToken (camelCase)",
			tag:  `<span sessionToken="abc">user</span>`,
			want: `<span sessionToken="[REDACTED]">user</span>`,
		},
		{
			name: "bearer attribute",
			tag:  `<div data-bearer="eyJxxx" class="auth">`,
			want: `<div data-bearer="[REDACTED]" class="auth">`,
		},
		{
			name: "password attribute name",
			// The NAME "type" doesn't match secret tokens. The NAME
			// "data-default-password" contains "password" → redact.
			tag:  `<input type="password" data-default-password="changeme">`,
			want: `<input type="password" data-default-password="[REDACTED]">`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := redactHTMLAttributes(tt.tag)
			if got != tt.want {
				t.Errorf("redactHTMLAttributes(%q)\n  got:  %q\n  want: %q", tt.tag, got, tt.want)
			}
		})
	}
}

func TestRedactHTMLAttributes_DoesNotRedactBenign(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want string
	}{
		{
			name: "plain div with class",
			tag:  `<div class="container" id="main">`,
			want: `<div class="container" id="main">`,
		},
		{
			name: "span with style",
			tag:  `<span style="color: red">`,
			want: `<span style="color: red">`,
		},
		{
			name: "closing tag",
			tag:  `</div>`,
			want: `</div>`,
		},
		{
			name: "comment-like",
			tag:  `<!doctype html>`,
			want: `<!doctype html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := redactHTMLAttributes(tt.tag)
			if got != tt.want {
				t.Errorf("redactHTMLAttributes(%q)\n  got:  %q\n  want: %q", tt.tag, got, tt.want)
			}
		})
	}
}

func TestRedactHTMLAttributes_EdgeCases(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		want string
	}{
		{
			name: "unquoted value",
			tag:  `<input value=plain>`,
			want: `<input value="[REDACTED]">`,
		},
		{
			name: "single-quoted value",
			tag:  `<input value='secret'>`,
			want: `<input value="[REDACTED]">`,
		},
		{
			name: "spaces around equals",
			tag:  `<input value = "secret">`,
			want: `<input value = "[REDACTED]">`,
		},
		{
			name: "boolean attribute",
			tag:  `<input type="checkbox" checked value="on">`,
			want: `<input type="checkbox" checked value="[REDACTED]">`,
		},
		{
			name: "value preceded by similar-named attr (no substring match)",
			// 'formvalue' contains 'value' as a substring. The old code
			// would have wrongly redacted formvalue's value. The walker
			// treats them as distinct attributes.
			tag:  `<input formvalue="keep-this" value="redact-this">`,
			want: `<input formvalue="keep-this" value="[REDACTED]">`,
		},
		{
			name: "data-href is not href",
			// data-href contains 'href' as a substring. The old code
			// would have wrongly redacted data-href when looking for href.
			tag:  `<a data-href="keep-this" href="/page?token=x">`,
			want: `<a data-href="keep-this" href="[REDACTED]">`,
		},
		{
			name: "malformed: unclosed quote on secret attr fails closed",
			// Truncation at the preview boundary is common. For a
			// positional-secret attr like value on <input>, fail closed:
			// drop the raw bytes and stamp [REDACTED].
			tag:  `<input value="unterminated`,
			want: `<input value="[REDACTED]"`,
		},
		{
			name: "malformed: unclosed quote on secret-named attr fails closed",
			tag:  `<div data-api-key="SECRET`,
			want: `<div data-api-key="[REDACTED]"`,
		},
		{
			name: "malformed: unclosed quote on benign attr leaves partial",
			// Non-secret attrs keep the partial bytes — over-redacting
			// benign structure costs LLM signal without security benefit.
			tag:  `<div class="container`,
			want: `<div class="container`,
		},
		{
			name: "self-closing tag",
			tag:  `<img src="/x" />`,
			want: `<img src="[REDACTED]" />`,
		},
		{
			name: "mixed case tag name",
			tag:  `<INPUT VALUE="secret">`,
			want: `<INPUT VALUE="[REDACTED]">`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := redactHTMLAttributes(tt.tag)
			if got != tt.want {
				t.Errorf("redactHTMLAttributes(%q)\n  got:  %q\n  want: %q", tt.tag, got, tt.want)
			}
		})
	}
}

func TestAttrNameLooksSecret(t *testing.T) {
	yes := []string{
		"token", "csrf-token", "api_token", "apitoken",
		"secret", "client-secret",
		"key", "api-key", "apikey", "accesskey", "data-key",
		"auth", "authorization", "x-auth-token",
		"password", "passwd",
		"credential", "credentials",
		"session", "sessionid", "session-token",
		"bearer",
		"csrf",
	}
	for _, n := range yes {
		if !attrNameLooksSecret(strings.ToLower(n)) {
			t.Errorf("attrNameLooksSecret(%q) = false, want true", n)
		}
	}

	no := []string{
		"class", "id", "style", "name", "type", "method",
		"role", "title", "alt", "lang", "rel", "target",
		"data-toggle", "data-target", "aria-label",
	}
	for _, n := range no {
		if attrNameLooksSecret(strings.ToLower(n)) {
			t.Errorf("attrNameLooksSecret(%q) = true, want false", n)
		}
	}
}

// =============================================================================
// SensitiveRedactions counting (Session A plumbing)
// =============================================================================
//
// The count is a side-channel over EXISTING redaction behavior — the golden
// preview assertions pin the redacted output strings byte-for-byte so the
// counter can never drift the redaction itself.

func TestClassifyAndRedact_SensitiveRedactionCounts(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		wantFormat  DetectedFormat
		wantCount   int
		wantPreview string // golden — exact pre-existing redaction output
	}{
		{
			name:        "json with secret-bearing key",
			body:        `{"password":"hunter2","status":"ok"}`,
			contentType: "application/json",
			wantFormat:  FormatJSON,
			wantCount:   1,
			wantPreview: "{\n  \"password\": \"[REDACTED]\",\n  \"status\": \"ok\"\n}",
		},
		{
			name:        "dotenv body",
			body:        "DB_PASSWORD=hunter2\nAPI_KEY=abc123",
			contentType: "",
			wantFormat:  FormatDotenv,
			wantCount:   2,
			wantPreview: "DB_PASSWORD=[REDACTED]\nAPI_KEY=[REDACTED]",
		},
		{
			name:        "clean short json",
			body:        `{"status":"ok"}`,
			contentType: "application/json",
			wantFormat:  FormatJSON,
			wantCount:   0,
			wantPreview: "{\n  \"status\": \"ok\"\n}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := classifyAndRedact([]byte(tt.body), tt.contentType)
			if a.Format != tt.wantFormat {
				t.Fatalf("Format = %q, want %q", a.Format, tt.wantFormat)
			}
			if a.SensitiveRedactions != tt.wantCount {
				t.Errorf("SensitiveRedactions = %d, want %d", a.SensitiveRedactions, tt.wantCount)
			}
			if a.redactedPreview != tt.wantPreview {
				t.Errorf("redacted preview changed:\n  got:  %q\n  want: %q", a.redactedPreview, tt.wantPreview)
			}
		})
	}
}

func TestClassifyAndRedact_FailClosedPathsCountZero(t *testing.T) {
	// Empty body, binary body, unknown format — redaction never runs,
	// SensitiveRedactions stays 0.
	for _, tc := range []struct {
		name        string
		body        []byte
		contentType string
	}{
		{"empty body", nil, ""},
		{"binary body", []byte{0x7f, 'E', 'L', 'F', 0x00, 0x01}, ""},
		{"unknown format", []byte("just some plain text with no structure"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := classifyAndRedact(tc.body, tc.contentType)
			if a.SensitiveRedactions != 0 {
				t.Errorf("SensitiveRedactions = %d, want 0", a.SensitiveRedactions)
			}
			if a.redactedPreview != "" {
				t.Errorf("fail-closed path produced a preview: %q", a.redactedPreview)
			}
		})
	}
}
