package rec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
)

// =============================================================================
// Format Detection
// =============================================================================
//
// Detects the format of a response body preview for redaction routing.
// Operates on TRUNCATED preview (max 2KB) — format detection confidence
// accounts for the possibility that we're seeing partial content.
//
// Priority:
//   1. Content-Type header (highest signal)
//   2. Body pattern sniffing (when Content-Type missing/ambiguous)
//   3. Unknown → fail closed (no preview)

func detectFormat(body []byte, contentType string) (DetectedFormat, Confidence) {
	ct := strings.ToLower(strings.TrimSpace(contentType))

	// Strip parameters (e.g., "text/html; charset=utf-8" → "text/html")
	if idx := strings.Index(ct, ";"); idx > 0 {
		ct = strings.TrimSpace(ct[:idx])
	}

	// --- Content-Type header (highest signal) ---
	switch {
	case ct == "application/json" || ct == "text/json":
		return FormatJSON, ConfidenceHigh
	case ct == "text/html" || ct == "application/xhtml+xml":
		return FormatHTML, ConfidenceHigh
	}

	// --- Body pattern sniffing ---
	if len(body) == 0 {
		return FormatUnknown, ConfidenceNone
	}

	// Check for binary content (null bytes in first 64 bytes)
	checkLen := 64
	if len(body) < checkLen {
		checkLen = len(body)
	}
	for _, b := range body[:checkLen] {
		if b == 0 {
			return FormatBinary, ConfidenceHigh
		}
	}

	trimmed := bytes.TrimLeftFunc(body, unicode.IsSpace)

	// Passwd format: lines matching user:x:uid:gid:...
	if looksLikePasswd(trimmed) {
		return FormatPasswd, ConfidenceHigh
	}

	// Dotenv format: lines matching KEY=VALUE
	if looksLikeDotenv(trimmed) {
		return FormatDotenv, ConfidenceHigh
	}

	// JSON: starts with { or [
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		// Validate it's actual JSON by attempting a partial parse
		var js json.RawMessage
		if json.Unmarshal(trimmed, &js) == nil {
			return FormatJSON, ConfidenceHigh
		}
		// Might be truncated JSON (we only have 2KB preview)
		return FormatJSON, ConfidenceLow
	}

	// HTML: starts with <, <!DOCTYPE, <html
	if len(trimmed) > 0 && trimmed[0] == '<' {
		lower := strings.ToLower(string(trimmed[:min(100, len(trimmed))]))
		if strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html") {
			return FormatHTML, ConfidenceHigh
		}
		// Some other XML/HTML tag
		return FormatHTML, ConfidenceLow
	}

	// text/plain Content-Type — try body sniffing for dotenv/passwd
	if strings.HasPrefix(ct, "text/plain") {
		if looksLikePasswd(trimmed) {
			return FormatPasswd, ConfidenceHigh
		}
		if looksLikeDotenv(trimmed) {
			return FormatDotenv, ConfidenceHigh
		}
	}

	return FormatUnknown, ConfidenceNone
}

// looksLikePasswd checks if the content appears to be a Unix passwd/shadow file.
// Looks for lines with colon-separated fields where field 3+ are numeric (UID/GID).
func looksLikePasswd(body []byte) bool {
	lines := bytes.SplitN(body, []byte("\n"), 4) // check first 3 lines
	passwdLines := 0
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		fields := bytes.Split(line, []byte(":"))
		// passwd format: user:pass:uid:gid:gecos:home:shell (7 fields)
		// shadow format: user:hash:lastchanged:min:max:warn:inactive:expire:reserved (9 fields)
		if len(fields) >= 7 {
			// Check that field 3 and 4 look numeric (UID and GID)
			if isNumericBytes(fields[2]) && isNumericBytes(fields[3]) {
				passwdLines++
			}
		}
	}
	return passwdLines >= 1
}

// looksLikeDotenv checks if the content appears to be a dotenv/config file.
// Looks for lines matching KEY=VALUE where KEY is uppercase with underscores.
func looksLikeDotenv(body []byte) bool {
	lines := bytes.SplitN(body, []byte("\n"), 6) // check first 5 lines
	kvLines := 0
	totalLines := 0
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		totalLines++
		// Match: optional "export ", then KEY= where KEY is [A-Z0-9_]+
		l := line
		if bytes.HasPrefix(l, []byte("export ")) {
			l = l[7:]
		}
		eqIdx := bytes.IndexByte(l, '=')
		if eqIdx > 0 && isEnvKey(l[:eqIdx]) {
			kvLines++
		}
	}
	return totalLines > 0 && kvLines >= 2
}

func isNumericBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isEnvKey(b []byte) bool {
	for _, c := range b {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return len(b) > 0
}

// =============================================================================
// HTML Redaction
// =============================================================================
//
// DESIGN PRINCIPLE: Keep visible text for re-classification.
//
// The LLM needs to see "Laravel v11.36.1" and "Documentation" to know
// a response is a welcome page, not a data dump. We strip SECRETS
// (script blocks, style blocks, input values, meta content) but keep
// the visible text that tells the story.
//
// This is a simple state-machine parser, not a full HTML parser.
// It's good enough for 2KB previews of typical web responses.
// No external dependencies (no golang.org/x/net/html).
//
// What we KEEP:
//   - Tag names and structure (<html>, <body>, <p>, <h1>, etc.)
//   - Visible text content between tags
//   - href/src attribute values (they're URLs, not secrets)
//
// What we STRIP:
//   - <script>...</script> blocks entirely → <script>[STRIPPED]</script>
//   - <style>...</style> blocks entirely → <style>[STRIPPED]</style>
//   - value="..." on <input>, <textarea> → value="[REDACTED]"
//   - content="..." on <meta> → content="[REDACTED]"
//   - Any attribute value matching secret patterns (token, key, session, etc.)

func redactHTML(body []byte) string {
	s := string(body)
	var out strings.Builder
	out.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] == '<' {
			// Find end of tag
			tagEnd := strings.IndexByte(s[i:], '>')
			if tagEnd < 0 {
				// Unclosed tag at end of preview — write remainder and stop
				out.WriteString(s[i:])
				break
			}
			tagEnd += i + 1 // absolute position after '>'
			tag := s[i:tagEnd]
			tagLower := strings.ToLower(tag)

			// Check for script/style blocks — strip content entirely
			if strings.HasPrefix(tagLower, "<script") {
				out.WriteString("<script>[STRIPPED]</script>")
				// Skip past closing </script>
				closeIdx := strings.Index(strings.ToLower(s[tagEnd:]), "</script>")
				if closeIdx >= 0 {
					i = tagEnd + closeIdx + len("</script>")
				} else {
					i = len(s) // no closing tag, skip rest
				}
				continue
			}
			if strings.HasPrefix(tagLower, "<style") {
				out.WriteString("<style>[STRIPPED]</style>")
				closeIdx := strings.Index(strings.ToLower(s[tagEnd:]), "</style>")
				if closeIdx >= 0 {
					i = tagEnd + closeIdx + len("</style>")
				} else {
					i = len(s)
				}
				continue
			}

			// Redact sensitive attributes in the tag
			redactedTag := redactHTMLAttributes(tag)
			out.WriteString(redactedTag)
			i = tagEnd
		} else {
			// Text content — keep it (visible text helps re-classification)
			nextTag := strings.IndexByte(s[i:], '<')
			if nextTag < 0 {
				out.WriteString(s[i:])
				break
			}
			out.WriteString(s[i : i+nextTag])
			i += nextTag
		}
	}

	result := out.String()
	// Cap output length
	if len(result) > 2048 {
		result = result[:2048] + "...[TRUNCATED]"
	}
	return result
}

// redactHTMLAttributes redacts sensitive attribute values in a single HTML tag.
//
// Two rule sets, both applied in one pass:
//
//  1. Position-based: certain attributes on certain tags always hold secrets
//     or URL-borne tokens (value on input/textarea, content on meta,
//     href on anchors, src on media, action on forms).
//  2. Name-based: any attribute whose name contains a secret-shaped token
//     (token, key, auth, password, secret, credential, session, bearer,
//     csrf, apikey) is redacted regardless of tag — catches data-api-key,
//     x-csrf-token, sessionToken, etc.
//
// URL attributes (href/src/action) are redacted wholesale rather than
// parsing query strings for token-shaped parameters. Loses some URL
// structure for LLM classification but prevents query-param leakage
// without a brittle URL parser running over potentially malformed bytes.
func redactHTMLAttributes(tag string) string {
	if len(tag) < 2 || tag[0] != '<' {
		return tag
	}
	if tag[1] == '/' || tag[1] == '!' {
		return tag // closing tag, comment, or doctype — nothing to redact
	}

	// Walk past tag name.
	i := 1
	for i < len(tag) && !isAttrBoundary(tag[i]) {
		i++
	}
	tagName := strings.ToLower(tag[1:i])
	positional := positionalSecretAttrsFor(tagName)

	var b strings.Builder
	b.Grow(len(tag) + 16)
	b.WriteString(tag[:i])

	for i < len(tag) {
		// Whitespace between attrs (or before '>').
		wsStart := i
		for i < len(tag) && isHTMLSpace(tag[i]) {
			i++
		}
		b.WriteString(tag[wsStart:i])

		if i >= len(tag) || tag[i] == '>' || tag[i] == '/' {
			b.WriteString(tag[i:])
			return b.String()
		}

		// Attribute name.
		nameStart := i
		for i < len(tag) && tag[i] != '=' && !isAttrBoundary(tag[i]) {
			i++
		}
		name := tag[nameStart:i]
		nameLower := strings.ToLower(name)
		b.WriteString(name)

		// Whitespace before '='.
		for i < len(tag) && isHTMLSpace(tag[i]) {
			b.WriteByte(tag[i])
			i++
		}

		if i >= len(tag) || tag[i] != '=' {
			// Boolean attribute (e.g. disabled, checked) — no value.
			continue
		}
		b.WriteByte('=')
		i++

		// Whitespace after '='.
		for i < len(tag) && isHTMLSpace(tag[i]) {
			b.WriteByte(tag[i])
			i++
		}
		if i >= len(tag) {
			return b.String()
		}

		// Value: quoted or unquoted.
		isSecret := positional[nameLower] || attrNameLooksSecret(nameLower)
		valStart := i
		if tag[i] == '"' || tag[i] == '\'' {
			quote := tag[i]
			i++
			closeIdx := strings.IndexByte(tag[i:], quote)
			if closeIdx < 0 {
				// Unterminated quoted value (common at preview truncation
				// boundaries). Fail closed for secrets: if this attribute
				// was going to be redacted anyway, drop the raw bytes and
				// stamp [REDACTED]. For non-secret attrs we still leave
				// the partial value, since over-redacting structure costs
				// us LLM signal.
				if isSecret {
					b.WriteString(`"[REDACTED]"`)
				} else {
					b.WriteString(tag[valStart:])
				}
				return b.String()
			}
			i = i + closeIdx + 1 // past closing quote
		} else {
			for i < len(tag) && tag[i] != '>' && !isHTMLSpace(tag[i]) {
				i++
			}
		}
		valEnd := i

		if isSecret {
			b.WriteString(`"[REDACTED]"`)
		} else {
			b.WriteString(tag[valStart:valEnd])
		}
	}

	return b.String()
}

// isHTMLSpace reports whether b is HTML whitespace as defined by the parser
// (space, tab, LF, CR, FF). We use this everywhere the spec calls for
// "ASCII whitespace" — between attributes, around '=', etc.
func isHTMLSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

// isAttrBoundary reports whether b terminates an attribute name or tag name.
func isAttrBoundary(b byte) bool {
	return isHTMLSpace(b) || b == '>' || b == '/'
}

// positionalSecretAttrsFor returns the set of attribute names that are
// considered dangerous-by-position for the given tag. URL-bearing
// attributes (href, src, action, formaction) are included because
// query parameters routinely carry tokens (?token=, ?key=, &apikey=)
// and the safest answer is to redact the value entirely.
func positionalSecretAttrsFor(tagName string) map[string]bool {
	switch tagName {
	case "input", "textarea":
		return map[string]bool{"value": true}
	case "meta":
		return map[string]bool{"content": true}
	case "form":
		return map[string]bool{"action": true}
	case "a", "link", "area", "base":
		return map[string]bool{"href": true}
	case "img", "iframe", "source", "embed", "track", "audio", "video":
		return map[string]bool{"src": true}
	case "button":
		return map[string]bool{"formaction": true}
	}
	return nil
}

// attrNameLooksSecret reports whether the attribute name (already lowercased)
// contains any token strongly associated with secrets. The match is a plain
// substring scan: "data-api-key", "x-csrf-token", "sessionToken", and
// "accessKey" all hit. Some false positives are acceptable — over-redacting
// a benign attribute value costs the LLM minor structural context, while
// under-redaction leaks credentials.
func attrNameLooksSecret(nameLower string) bool {
	for _, t := range secretAttrNameTokens {
		if strings.Contains(nameLower, t) {
			return true
		}
	}
	return false
}

var secretAttrNameTokens = []string{
	"token", "secret", "key", "auth", "password", "passwd",
	"credential", "session", "bearer", "csrf", "apikey",
}

// =============================================================================
// JSON Redaction
// =============================================================================
//
// DESIGN PRINCIPLE: Keep keys and non-sensitive values for re-classification.
//
// The LLM needs to see {"status": "ok", "framework": "Laravel"} to know
// a response is an API status check, not a data dump. We strip values that
// look like secrets (long strings, base64, emails, values under sensitive keys)
// but keep short, non-sensitive values.
//
// What we KEEP:
//   - All keys (structure is the signal)
//   - Numbers, booleans, nulls (rarely secrets)
//   - Short string values (<50 chars) under non-sensitive keys
//
// What we REDACT:
//   - Values under keys matching: password, secret, token, key, auth,
//     credential, session, cookie, authorization, api_key, private
//   - String values >50 characters (likely base64, JWTs, long secrets)
//   - Strings containing @ (emails)
//   - Strings that look like base64 (mostly alphanumeric + /+=, >20 chars)

func redactJSON(body []byte) string {
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "" // malformed JSON → fail closed
	}

	redacted := redactJSONValue(parsed, "", 0)

	out, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return ""
	}

	result := string(out)
	if len(result) > 2048 {
		result = result[:2048] + "\n...[TRUNCATED]"
	}
	return result
}

func redactJSONValue(v interface{}, parentKey string, depth int) interface{} {
	if depth > 10 {
		return "[MAX_DEPTH]"
	}

	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, child := range val {
			out[k] = redactJSONValue(child, k, depth+1)
		}
		return out

	case []interface{}:
		out := make([]interface{}, len(val))
		for i, child := range val {
			out[i] = redactJSONValue(child, parentKey, depth+1)
		}
		return out

	case string:
		if isSensitiveKey(parentKey) {
			return "[REDACTED]"
		}
		if len(val) > 50 {
			return "[REDACTED:long_string]"
		}
		if strings.Contains(val, "@") && strings.Contains(val, ".") {
			return "[REDACTED:email]"
		}
		if looksLikeBase64(val) {
			return "[REDACTED:encoded]"
		}
		// Keep short, non-sensitive string values
		return val

	case float64, bool, nil:
		// Numbers, booleans, nulls are rarely secrets — keep them
		return val

	default:
		return val
	}
}

// isSensitiveKey checks if a JSON key name suggests the value is a secret.
func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, sensitive := range []string{
		"password", "passwd", "secret", "token", "key", "auth",
		"credential", "session", "cookie", "authorization",
		"api_key", "apikey", "private", "access_token",
		"refresh_token", "jwt", "bearer", "hash", "salt",
		"ssn", "credit_card", "card_number",
	} {
		if strings.Contains(k, sensitive) {
			return true
		}
	}
	return false
}

// looksLikeBase64 checks if a string looks like base64-encoded data.
//
// v0.48.x hotfix (2026-05-11): false-positive trigger on English sentences.
// Before: ratio threshold 0.85 with no whitespace check. A 41-char string
// like "This captain instance only accepts API v2" scored 35/41 ≈ 0.854 —
// just above 0.85 — and got `[REDACTED:encoded]`, which then poisoned the
// body preview, hashed differently than the actual response, and surfaced
// as a false positive in the Option-4 investigation (kovicloud.com upload
// log line, May 8 2026).
//
// Two changes:
//  1. Early-out if `s` contains any whitespace. In the contexts this
//     function actually runs (HTTP response bodies as JSON string values,
//     header values, query parameters), base64 payloads are contiguous
//     tokens — no spaces, tabs, or embedded newlines. Whitespace is the
//     strongest signal that the string is human text masquerading as a
//     high-density alphabet. Note: MIME/PEM-style base64 IS line-wrapped
//     with newlines (76-char chunks), but those forms travel as document
//     bodies rather than inline string values; we don't see them in the
//     contexts this check runs against. If that ever changes, we'd want a
//     context-aware variant rather than relaxing this check.
//  2. Tighten ratio 0.85 → 0.95. Defense-in-depth for whitespace-free
//     false positives (URL slugs, long identifiers, hex IDs). Real base64
//     strings are essentially 100% alphabet-valid; any meaningful gap
//     below that means it's something else.
//
// Known limitation (not fixed here): pure-alphanumeric English words
// ("hello123world") still score 100%. The proper fix is entropy-based
// detection, which is scope creep for a hotfix. Whitespace + 0.95 catches
// the documented false-positive class. Entropy-based detection is v1.x.
func looksLikeBase64(s string) bool {
	if len(s) < 20 {
		return false
	}
	// Whitespace early-out — in the contexts this runs (inline JSON values,
	// header values), real base64 payloads are contiguous tokens. MIME/PEM
	// line-wrapped base64 is a different shape we don't encounter here.
	if strings.ContainsAny(s, " \t\n\r\v\f") {
		return false
	}
	b64Chars := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			b64Chars++
		}
	}
	return float64(b64Chars)/float64(len(s)) > 0.95
}

// =============================================================================
// Dotenv Redaction
// =============================================================================
//
// Pure secrets — always redact ALL values. The key names tell the story:
// "DB_PASSWORD=<REDACTED>" is enough for the LLM to know this is a config leak.

func redactDotenv(body []byte) string {
	var out strings.Builder
	lines := strings.Split(string(body), "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Empty lines and comments pass through
		if trimmed == "" || trimmed[0] == '#' {
			out.WriteString(line)
			if i < len(lines)-1 {
				out.WriteByte('\n')
			}
			continue
		}

		// Handle "export KEY=VALUE"
		l := trimmed
		prefix := ""
		if strings.HasPrefix(l, "export ") {
			prefix = "export "
			l = l[7:]
		}

		eqIdx := strings.IndexByte(l, '=')
		if eqIdx > 0 {
			key := l[:eqIdx]
			out.WriteString(prefix)
			out.WriteString(key)
			out.WriteString("=[REDACTED]")
		} else {
			// Not a KEY=VALUE line — pass through (could be a comment variant)
			out.WriteString(line)
		}

		if i < len(lines)-1 {
			out.WriteByte('\n')
		}
	}

	return out.String()
}

// =============================================================================
// Passwd/Shadow Redaction
// =============================================================================
//
// Keep: username (field 0), UID (field 2), GID (field 3), shell (field 6)
// Redact: password hash (field 1), GECOS (field 4), home dir (field 5)
//
// For /etc/shadow: keep username (field 0), redact everything else.

func redactPasswd(body []byte) string {
	var out strings.Builder
	lines := strings.Split(string(body), "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if i < len(lines)-1 {
				out.WriteByte('\n')
			}
			continue
		}

		fields := strings.Split(trimmed, ":")
		if len(fields) >= 7 {
			// passwd format: user:pass:uid:gid:gecos:home:shell
			out.WriteString(fmt.Sprintf("%s:[REDACTED]:%s:%s:[REDACTED]:[REDACTED]:%s",
				fields[0], // username — keep
				fields[2], // UID — keep
				fields[3], // GID — keep
				fields[6], // shell — keep
			))
		} else if len(fields) >= 2 && strings.Contains(fields[1], "$") {
			// shadow format: user:$hash$...:... — keep only username
			out.WriteString(fields[0])
			for j := 1; j < len(fields); j++ {
				out.WriteString(":[REDACTED]")
			}
		} else {
			// Unknown format — redact entire line
			out.WriteString("[REDACTED]")
		}

		if i < len(lines)-1 {
			out.WriteByte('\n')
		}
	}

	return out.String()
}

// =============================================================================
// Helpers — note: min() is built-in as of Go 1.21
// =============================================================================

// =============================================================================
// Format Classifier + Structural Redaction
// =============================================================================
//
// ClassifyAndRedact detects the format of a response body and produces a
// redacted preview safe for LLM re-classification. Exported for use by
// the catch-all verification pipeline.
//
// IMPORTANT: operates on the TRUNCATED body preview
func ClassifyAndRedact(bodyPreview []byte, contentType string) *DisclosureAnalysis {
	return classifyAndRedact(bodyPreview, contentType)
}

// IMPORTANT: classifyAndRedact operates on the TRUNCATED body preview
// (max 2KB), not the full response body. Format detection and redaction
// confidence are based on partial content. This is acceptable for Phase 1
// but should be documented in any API that exposes these fields.
//
// FAIL-CLOSED RULE:
//   If format is unknown, no body preview at all. Only transport metadata.
//   Content-Length: 45032 on a 404 path IS the evidence.

func classifyAndRedact(bodyPreview []byte, contentType string) *DisclosureAnalysis {
	if len(bodyPreview) == 0 {
		return &DisclosureAnalysis{
			Format:              FormatUnknown,
			RedactionConfidence: ConfidenceNone,
			DisclosureSummary:   "NO RESPONSE BODY CAPTURED",
		}
	}

	format, confidence := detectFormat(bodyPreview, contentType)

	analysis := &DisclosureAnalysis{
		Format:              format,
		RedactionConfidence: confidence,
	}

	switch format {
	case FormatDotenv:
		analysis.redactedPreview = redactDotenv(bodyPreview)
		analysis.DisclosureSummary = "DOTENV/CONFIG STRUCTURE DETECTED"
	case FormatPasswd:
		analysis.redactedPreview = redactPasswd(bodyPreview)
		analysis.DisclosureSummary = "PASSWD FILE STRUCTURE DETECTED"
	case FormatJSON:
		analysis.redactedPreview = redactJSON(bodyPreview)
		analysis.DisclosureSummary = "JSON STRUCTURE DETECTED"
	case FormatHTML:
		analysis.redactedPreview = redactHTML(bodyPreview)
		analysis.DisclosureSummary = "HTML CONTENT DETECTED"
	case FormatBinary:
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.DisclosureSummary = "BINARY CONTENT DETECTED — METADATA ONLY"
	default:
		// FAIL-CLOSED: unknown format = no body preview.
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.DisclosureSummary = "UNKNOWN FORMAT — METADATA ONLY"
	}

	return analysis
}
