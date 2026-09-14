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
// Operates on TRUNCATED preview (max 2KB) - format detection confidence
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

	// --- PEM private-key material (checked BEFORE the Content-Type paths) ---
	// Keys are routinely embedded in error dumps served as text/html or
	// text/plain. If the Content-Type fast path claimed such a body first,
	// redactHTML would keep the armor block as "visible text" and leak key
	// material into the preview. The armor header alone is conclusive, so
	// this scan pre-empts every other classification.
	if pemKeyType(body) != "" {
		return FormatPEM, ConfidenceHigh
	}

	// --- Served PHP source (checked BEFORE the Content-Type paths) ---
	// Same rationale as PEM: PHP source served as text/html would take the
	// ct == "text/html" fast path below and redactHTML would keep the source
	// as "visible text" - leaking credentials, connection strings, and logic
	// into the preview. The predicate anchors at body start only (see
	// LooksLikePHPSource); high confidence is in the FORMAT identity - the
	// preview is still withheld fail-closed in classifyAndRedact.
	if LooksLikePHPSource(body) {
		return FormatPHP, ConfidenceHigh
	}

	// --- Markup-prologue three-way dispatch (checked BEFORE the
	// Content-Type paths; FIX 3, fix round v3) ---
	// WordPress serves xmlrpc.php fault bodies as text/html; misleading MIME
	// is a required capture, so this must pre-empt the Content-Type switch.
	// XML rejection must never fall back to permissive HTML: anything
	// XML-ish - declarations, comments, non-html DOCTYPEs, malformed or
	// oversized prologues - classifies FormatXML and stays withheld unless
	// the XML-RPC redactor (the sole acceptance authority) accepts it. Only
	// the token-bounded HTML doctype takes the HTML path here.
	switch classifyMarkupPrologue(body) {
	case prologueHTMLDoctype:
		return FormatHTML, ConfidenceHigh
	case prologueXML:
		return FormatXML, ConfidenceHigh
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

	// text/plain Content-Type - try body sniffing for dotenv/passwd
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

// pemPrivateKeyHeaders maps PEM armor headers to a short key-type label for
// the disclosure summary. Only PRIVATE key armor counts - "BEGIN CERTIFICATE"
// is public material and must NOT classify as FormatPEM. More specific
// headers precede the generic "BEGIN PRIVATE KEY" so the label is accurate.
var pemPrivateKeyHeaders = []struct {
	header string // uppercase; matched case-insensitively
	label  string
}{
	{"BEGIN RSA PRIVATE KEY", "RSA"},
	{"BEGIN ECDSA PRIVATE KEY", "ECDSA"}, // nonstandard, but emitted by some libraries
	{"BEGIN EC PRIVATE KEY", "EC"},
	{"BEGIN DSA PRIVATE KEY", "DSA"},
	{"BEGIN OPENSSH PRIVATE KEY", "OPENSSH"},
	{"BEGIN SSH2 ENCRYPTED PRIVATE KEY", "SSH2"}, // ssh.com/Tectia export (also PuTTY export)
	{"BEGIN ENCRYPTED PRIVATE KEY", "ENCRYPTED PKCS#8"},
	{"BEGIN PGP PRIVATE KEY BLOCK", "PGP"},
	{"BEGIN PRIVATE KEY", "PKCS#8"},
}

// pemKeyType scans the whole body preview (not just offset zero - keys are
// often embedded mid-dump) for a private-key armor header, case-insensitively.
// Returns the key-type label, or "" if none found.
func pemKeyType(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	upper := strings.ToUpper(string(body))
	for _, h := range pemPrivateKeyHeaders {
		if strings.Contains(upper, h.header) {
			return h.label
		}
	}
	return ""
}

// redactorVersion identifies the redaction ruleset revision. The Part 3 body
// store keys interned disclosure analyses on it so an analysis produced under
// old rules can never be reused after the rules change. Bump on EVERY change
// to detection or redaction behavior in this package.
//
// v2 (fix round v3): the FIX 3 three-way prologue dispatch reroutes
// DOCTYPE/comment-led bodies from FormatHTML to FormatXML, changing what a
// cached analysis would say for the same bytes.
const redactorVersion = 2

// redactorMaxOutputBytes is the maximum retained redacted-preview size of
// the CAPPED redactors, used for worst-case budget ADMISSION estimates (it
// is an OUTPUT cap - MaxBodyBytes caps input, not output). Derivation:
//   - redactXMLRPC:  xmlrpcMaxOutputBytes            = 2048
//   - redactHTML:    2048 + len("...[TRUNCATED]")    = 2062
//   - redactJSON:    2048 + len("\n...[TRUNCATED]")  = 2063  ← max
//   - fail-closed formats (PEM/PHP/binary/unknown, rejected XML): 0
//
// redactDotenv and redactPasswd have NO output cap and can EXPAND
// pathological input (many tiny lines each growing a "[REDACTED]" marker)
// past this constant, so admission estimates built on it can UNDERSTATE for
// such bodies. That is safe: the ACTUAL retained preview length is always
// charged exactly (internedBody.byteCharge), and the post-eviction
// admission recheck in Insert compares real totals, so any underestimate is
// caught there rather than breaching the budget.
const redactorMaxOutputBytes = 2063

// utf8BOM is the UTF-8 byte-order mark, optionally present at body start.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// trimBOMAndSpace strips an optional leading UTF-8 BOM and leading whitespace.
// Shared by the PHP and XML body-start predicates and the XML-RPC redactor so
// all three anchor at the same "start of document" position.
func trimBOMAndSpace(body []byte) []byte {
	body = bytes.TrimPrefix(body, utf8BOM)
	return bytes.TrimLeftFunc(body, unicode.IsSpace)
}

// LooksLikePHPSource reports whether the body preview is served (unexecuted)
// PHP source: after an optional UTF-8 BOM and leading whitespace, the body
// starts with the exact marker "<?php" followed by whitespace, '/', or
// end-of-preview. NOT any "<?" short tag, NOT keyed on the URL ending in
// .php, and NOT matched anywhere but the anchored body start - a normal HTML
// page produced by EXECUTED PHP, or documentation quoting "<?php" mid-page,
// must not classify as PHP source.
//
// Exported as the single shared definition of the predicate (used by format
// detection here and available to callers outside the package) - one
// definition, no copies.
func LooksLikePHPSource(body []byte) bool {
	b := trimBOMAndSpace(body)
	const marker = "<?php"
	if !bytes.HasPrefix(b, []byte(marker)) {
		return false
	}
	if len(b) == len(marker) {
		return true // end-of-preview directly after the marker
	}
	switch b[len(marker)] {
	case ' ', '\t', '\r', '\n', '\v', '\f', '/':
		return true
	}
	return false
}

// =============================================================================
// Markup-prologue three-way dispatch (FIX 3, fix round v3)
// =============================================================================
//
// Governing rule: an XML rejection must never be undone by HTML fallback.
// Suspicious or unsupported XML prologue = FormatXML = withheld unless the
// XML-RPC redactor (unchanged, the sole acceptance authority) accepts it.

type markupPrologue int

const (
	// prologueNone: not XML-ish and not an HTML doctype - the caller falls
	// through to the existing behavior (Content-Type switch, sniffs, the
	// generic '<' branch).
	prologueNone markupPrologue = iota
	// prologueHTMLDoctype: token-bounded "<!doctype html" - the existing
	// FormatHTML/ConfidenceHigh path.
	prologueHTMLDoctype
	// prologueXML: XML-ish - FormatXML, ALWAYS, regardless of what follows.
	prologueXML
)

// markupPrologueScanBytes bounds how far the dispatcher examines the
// prologue. A prologue construct still unresolved at this bound is treated
// as XML (fail closed), never scanned further.
const markupPrologueScanBytes = 512

// classifyMarkupPrologue dispatches a body's leading markup, after an
// optional UTF-8 BOM and leading whitespace, within a bounded scan:
//
//	(i)   "<!doctype" + whitespace + "html" + boundary, case-insensitive,
//	      AND the remainder of the declaration closes cleanly with '>'
//	      (quote-aware scan, see htmlDoctypeTail) → prologueHTMLDoctype.
//	      "htmlfoo" does NOT qualify; neither does an internal subset
//	      ('[' before '>'), an unclosed/truncated declaration ("<!DOCTYPE
//	      html" at end of preview), or one exceeding the scan bound - all
//	      of those are (ii).
//	(ii)  XML-ish → prologueXML, always: an "<?xml" declaration (case-
//	      insensitive - "<?XML" is a reserved/invalid PI name, fail closed);
//	      a leading XML comment "<!--" (comment-led documents route to the
//	      redactor whatever follows, and it rejects comments); any OTHER
//	      "<!doctype ..." (non-html name, internal subset '[', no
//	      whitespace, truncated, unclosed); a prologue construct cut off by
//	      the preview or the scan bound. Also the declaration-less XML-RPC
//	      root "<methodResponse" - retained from the Part 1 locked spec
//	      ("the first element token is <methodResponse"): dropping it would
//	      regress the required declaration-less XML-RPC acceptance.
//	(iii) anything else → prologueNone (existing behavior).
func classifyMarkupPrologue(body []byte) markupPrologue {
	b := trimBOMAndSpace(body)
	if len(b) > markupPrologueScanBytes {
		b = b[:markupPrologueScanBytes]
	}
	if len(b) == 0 || b[0] != '<' {
		return prologueNone
	}

	// XML declaration (case-insensitive: the canonical decl is lowercase,
	// and a "<?XML"-style reserved PI is fail-closed XML, not HTML).
	if hasFoldPrefix(b, "<?xml") {
		return prologueXML
	}
	// Leading XML comment - closed or unclosed, whatever follows.
	if bytes.HasPrefix(b, []byte("<!--")) {
		return prologueXML
	}
	// Declaration-less XML-RPC root (Part 1 route, retained).
	if hasElementTokenPrefix(b, "<methodResponse") {
		return prologueXML
	}

	if len(b) >= 2 && b[1] == '!' {
		if hasFoldPrefix(b, "<!doctype") {
			rest := b[len("<!doctype"):]
			// (i) requires whitespace, then the name "html", then a clean
			// token boundary, AND (FIX A, fix round v4) a well-formed
			// remainder of the SAME declaration: scanned to its closing
			// '>' with quoted literals respected. An unquoted '[' (internal
			// subset - the DTD-smuggling shape), an unclosed declaration,
			// or one running past the scan bound is XML, fail closed.
			// Everything else - other names, "htmlfoo", missing whitespace
			// - is (ii).
			j := 0
			for j < len(rest) && isMarkupSpace(rest[j]) {
				j++
			}
			if j > 0 && len(rest[j:]) >= 4 && foldEqualASCII(rest[j:j+4], "html") {
				after := rest[j+4:]
				if len(after) > 0 && (after[0] == '>' || isMarkupSpace(after[0])) {
					return htmlDoctypeTail(after)
				}
				// Truncated right after the name: unclosed declaration.
			}
			return prologueXML
		}
		// The preview ends mid-token in a way that could still become a
		// doctype or comment: an unclosed prologue → XML (fail closed).
		if isWholeTruncatedPrefixOf(b, "<!doctype") || isWholeTruncatedPrefixOf(b, "<!--") {
			return prologueXML
		}
		// Other "<!" constructs (e.g. "<![CDATA[") keep existing behavior.
		return prologueNone
	}

	return prologueNone
}

// htmlDoctypeTail (FIX A, fix round v4) scans the remainder of an
// "<!doctype html"-led declaration - tail starts at the byte after the name
// token, already bounded by markupPrologueScanBytes - for its closing '>',
// respecting single- and double-quoted literals: a '>' or '[' INSIDE quotes
// neither terminates the declaration nor trips the subset check, so legacy
// PUBLIC/SYSTEM doctypes with quoted identifiers keep the HTML path.
//
//   - unquoted '[' before the closing '>' → prologueXML (internal subset:
//     the "<!DOCTYPE html [<!ENTITY ...>]>" DTD-smuggling shape must never
//     reach the permissive HTML redactor),
//   - no closing '>' within the bound (unclosed, truncated, over-limit, or
//     an unterminated quote) → prologueXML,
//   - clean unquoted '>' → prologueHTMLDoctype.
func htmlDoctypeTail(tail []byte) markupPrologue {
	var quote byte // 0 = not inside a quoted literal
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '[':
			return prologueXML
		case '>':
			return prologueHTMLDoctype
		}
	}
	return prologueXML
}

// hasElementTokenPrefix reports whether b starts with the element token tok
// (e.g. "<methodResponse") at a clean token boundary or end-of-preview.
func hasElementTokenPrefix(b []byte, tok string) bool {
	if !bytes.HasPrefix(b, []byte(tok)) {
		return false
	}
	if len(b) == len(tok) {
		return true // truncated right after the element name
	}
	switch b[len(tok)] {
	case '>', ' ', '\t', '\r', '\n', '/':
		return true
	}
	return false
}

// hasFoldPrefix reports whether b starts with prefix, ASCII case-insensitive.
func hasFoldPrefix(b []byte, prefix string) bool {
	return len(b) >= len(prefix) && foldEqualASCII(b[:len(prefix)], prefix)
}

// isWholeTruncatedPrefixOf reports whether b is the ENTIRE (scan-bounded)
// input and a proper case-insensitive prefix of tok - i.e. the preview ended
// mid-token.
func isWholeTruncatedPrefixOf(b []byte, tok string) bool {
	return len(b) < len(tok) && foldEqualASCII(b, tok[:len(b)])
}

// foldEqualASCII compares b to s, ASCII case-insensitive.
func foldEqualASCII(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c, d := b[i], s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if 'A' <= d && d <= 'Z' {
			d += 'a' - 'A'
		}
		if c != d {
			return false
		}
	}
	return true
}

// isMarkupSpace reports ASCII markup whitespace.
func isMarkupSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
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

func redactHTML(body []byte) (string, int) {
	s := string(body)
	var out strings.Builder
	out.Grow(len(s))
	redactions := 0

	i := 0
	for i < len(s) {
		if s[i] == '<' {
			// Find end of tag
			tagEnd := strings.IndexByte(s[i:], '>')
			if tagEnd < 0 {
				// Unclosed tag at end of preview - write remainder and stop
				out.WriteString(s[i:])
				break
			}
			tagEnd += i + 1 // absolute position after '>'
			tag := s[i:tagEnd]
			tagLower := strings.ToLower(tag)

			// Check for script/style blocks - strip content entirely
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
			redactedTag, n := redactHTMLAttributes(tag)
			redactions += n
			out.WriteString(redactedTag)
			i = tagEnd
		} else {
			// Text content - keep it (visible text helps re-classification)
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
	return result, redactions
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
//     csrf, apikey) is redacted regardless of tag - catches data-api-key,
//     x-csrf-token, sessionToken, etc.
//
// URL attributes (href/src/action) are redacted wholesale rather than
// parsing query strings for token-shaped parameters. Loses some URL
// structure for LLM classification but prevents query-param leakage
// without a brittle URL parser running over potentially malformed bytes.
func redactHTMLAttributes(tag string) (string, int) {
	if len(tag) < 2 || tag[0] != '<' {
		return tag, 0
	}
	if tag[1] == '/' || tag[1] == '!' {
		return tag, 0 // closing tag, comment, or doctype - nothing to redact
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
	redactions := 0

	for i < len(tag) {
		// Whitespace between attrs (or before '>').
		wsStart := i
		for i < len(tag) && isHTMLSpace(tag[i]) {
			i++
		}
		b.WriteString(tag[wsStart:i])

		if i >= len(tag) || tag[i] == '>' || tag[i] == '/' {
			b.WriteString(tag[i:])
			return b.String(), redactions
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
			// Boolean attribute (e.g. disabled, checked) - no value.
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
			return b.String(), redactions
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
					redactions++
				} else {
					b.WriteString(tag[valStart:])
				}
				return b.String(), redactions
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
			redactions++
		} else {
			b.WriteString(tag[valStart:valEnd])
		}
	}

	return b.String(), redactions
}

// isHTMLSpace reports whether b is HTML whitespace as defined by the parser
// (space, tab, LF, CR, FF). We use this everywhere the spec calls for
// "ASCII whitespace" - between attributes, around '=', etc.
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
// "accessKey" all hit. Some false positives are acceptable - over-redacting
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

func redactJSON(body []byte) (string, int) {
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0 // malformed JSON → fail closed
	}

	redactions := 0
	redacted := redactJSONValue(parsed, "", 0, &redactions)

	out, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		return "", 0
	}

	result := string(out)
	if len(result) > 2048 {
		result = result[:2048] + "\n...[TRUNCATED]"
	}
	return result, redactions
}

func redactJSONValue(v interface{}, parentKey string, depth int, redactions *int) interface{} {
	if depth > 10 {
		return "[MAX_DEPTH]"
	}

	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, child := range val {
			out[k] = redactJSONValue(child, k, depth+1, redactions)
		}
		return out

	case []interface{}:
		out := make([]interface{}, len(val))
		for i, child := range val {
			out[i] = redactJSONValue(child, parentKey, depth+1, redactions)
		}
		return out

	case string:
		if isSensitiveKey(parentKey) {
			*redactions++
			return "[REDACTED]"
		}
		if len(val) > 50 {
			*redactions++
			return "[REDACTED:long_string]"
		}
		if strings.Contains(val, "@") && strings.Contains(val, ".") {
			*redactions++
			return "[REDACTED:email]"
		}
		if looksLikeBase64(val) {
			*redactions++
			return "[REDACTED:encoded]"
		}
		// Keep short, non-sensitive string values
		return val

	case float64, bool, nil:
		// Numbers, booleans, nulls are rarely secrets - keep them
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
// like "This captain instance only accepts API v2" scored 35/41 ≈ 0.854 -
// just above 0.85 - and got `[REDACTED:encoded]`, which then poisoned the
// body preview, hashed differently than the actual response, and surfaced
// as a false positive in the Option-4 investigation (kovicloud.com upload
// log line, May 8 2026).
//
// Two changes:
//  1. Early-out if `s` contains any whitespace. In the contexts this
//     function actually runs (HTTP response bodies as JSON string values,
//     header values, query parameters), base64 payloads are contiguous
//     tokens - no spaces, tabs, or embedded newlines. Whitespace is the
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
	// Whitespace early-out - in the contexts this runs (inline JSON values,
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
// Pure secrets - always redact ALL values. The key names tell the story:
// "DB_PASSWORD=<REDACTED>" is enough for the LLM to know this is a config leak.

func redactDotenv(body []byte) (string, int) {
	var out strings.Builder
	lines := strings.Split(string(body), "\n")
	redactions := 0

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
			redactions++
		} else {
			// Not a KEY=VALUE line - pass through (could be a comment variant)
			out.WriteString(line)
		}

		if i < len(lines)-1 {
			out.WriteByte('\n')
		}
	}

	return out.String(), redactions
}

// =============================================================================
// Passwd/Shadow Redaction
// =============================================================================
//
// Keep: username (field 0), UID (field 2), GID (field 3), shell (field 6)
// Redact: password hash (field 1), GECOS (field 4), home dir (field 5)
//
// For /etc/shadow: keep username (field 0), redact everything else.

func redactPasswd(body []byte) (string, int) {
	var out strings.Builder
	lines := strings.Split(string(body), "\n")
	redactions := 0

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
				fields[0], // username - keep
				fields[2], // UID - keep
				fields[3], // GID - keep
				fields[6], // shell - keep
			))
			redactions += 3 // hash, GECOS, home - the three markers written above
		} else if len(fields) >= 2 && strings.Contains(fields[1], "$") {
			// shadow format: user:$hash$...:... - keep only username
			out.WriteString(fields[0])
			for j := 1; j < len(fields); j++ {
				out.WriteString(":[REDACTED]")
				redactions++
			}
		} else {
			// Unknown format - redact entire line
			out.WriteString("[REDACTED]")
			redactions++
		}

		if i < len(lines)-1 {
			out.WriteByte('\n')
		}
	}

	return out.String(), redactions
}

// =============================================================================
// Helpers - note: min() is built-in as of Go 1.21
// =============================================================================

// =============================================================================
// Format Classifier + Structural Redaction
// =============================================================================
//
// ClassifyAndRedact detects the format of a response body and produces a
// redacted preview safe for LLM re-classification. Exported for use by
// the catch-all verification pipeline.
//
// IMPORTANT: operates on the TRUNCATED body preview. bodyComplete reports
// whether the preview covers the ENTIRE HTTP body (clean end-of-body read,
// nothing truncated) - required by the XML-RPC redactor; len(preview) and
// Content-Length are NOT proof of completeness.
func ClassifyAndRedact(bodyPreview []byte, contentType string, bodyComplete bool) *DisclosureAnalysis {
	return classifyAndRedact(bodyPreview, contentType, bodyComplete)
}

// IMPORTANT: classifyAndRedact operates on the TRUNCATED body preview
// (max 2KB), not the full response body. Format detection and redaction
// confidence are based on partial content. This is acceptable for Phase 1
// but should be documented in any API that exposes these fields.
//
// FAIL-CLOSED RULE:
//   If format is unknown, no body preview at all. Only transport metadata.
//   Content-Length: 45032 on a 404 path IS the evidence.

func classifyAndRedact(bodyPreview []byte, contentType string, bodyComplete bool) *DisclosureAnalysis {
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
		analysis.redactedPreview, analysis.SensitiveRedactions = redactDotenv(bodyPreview)
		analysis.DisclosureSummary = "DOTENV/CONFIG STRUCTURE DETECTED"
	case FormatPasswd:
		analysis.redactedPreview, analysis.SensitiveRedactions = redactPasswd(bodyPreview)
		analysis.DisclosureSummary = "PASSWD FILE STRUCTURE DETECTED"
	case FormatJSON:
		analysis.redactedPreview, analysis.SensitiveRedactions = redactJSON(bodyPreview)
		analysis.DisclosureSummary = "JSON STRUCTURE DETECTED"
	case FormatHTML:
		analysis.redactedPreview, analysis.SensitiveRedactions = redactHTML(bodyPreview)
		analysis.DisclosureSummary = "HTML CONTENT DETECTED"
	case FormatXML:
		// Narrow XML-RPC redactor. Success grants high confidence; ANY
		// failure fails closed - recognizing XML does not grant confidence.
		if preview, count, ok := redactXMLRPC(bodyPreview, bodyComplete); ok {
			analysis.redactedPreview = preview
			analysis.SensitiveRedactions = count
			analysis.RedactionConfidence = ConfidenceHigh
			analysis.DisclosureSummary = "XML-RPC RESPONSE STRUCTURE DETECTED"
		} else {
			analysis.redactedPreview = ""
			analysis.RedactionConfidence = ConfidenceNone
			analysis.SensitiveRedactions = 0
			analysis.DisclosureSummary = "XML CONTENT DETECTED - METADATA ONLY"
		}
	case FormatPHP:
		// Fail closed, PEM-style: served PHP source IS the disclosure, so no
		// preview is ever emitted - escalation keys off Format identity.
		// SensitiveRedactions is forced to 1 so count-based logic (the Lane A
		// benign-cache gate) treats this body as disclosing.
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.SensitiveRedactions = 1
		analysis.DisclosureSummary = "PHP SOURCE CODE DETECTED - METADATA ONLY"
	case FormatPEM:
		// Fail closed: never preview key material, not even redacted - the
		// armor header alone is the disclosure. SensitiveRedactions is
		// forced to at least 1 so count-based logic (the Lane A benign-cache
		// gate) treats this body as disclosing; escalation itself keys off
		// Format, not the count.
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.SensitiveRedactions = 1
		analysis.DisclosureSummary = fmt.Sprintf("PEM PRIVATE KEY DETECTED (%s) - METADATA ONLY", pemKeyType(bodyPreview))
	case FormatBinary:
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.DisclosureSummary = "BINARY CONTENT DETECTED - METADATA ONLY"
	default:
		// FAIL-CLOSED: unknown format = no body preview.
		analysis.redactedPreview = ""
		analysis.RedactionConfidence = ConfidenceNone
		analysis.DisclosureSummary = "UNKNOWN FORMAT - METADATA ONLY"
	}

	return analysis
}
