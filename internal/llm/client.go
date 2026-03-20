package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Verdict is the LLM's assessment of a log line, now with pattern learning
// and normalization hints.
type Verdict struct {
	// Classification: "safe", "suspicious", "malicious", "noise"
	Classification string `json:"classification"`

	// Confidence: 0.0 - 1.0
	Confidence float64 `json:"confidence"`

	// Reason: human-readable explanation
	Reason string `json:"reason"`

	// Action: "allow", "deny", "suppress", "alert"
	//   allow    → whitelist as known-good
	//   deny     → blacklist as known-bad, alert immediately
	//   suppress → known-noise, don't alert, don't re-analyze
	//   alert    → suspicious but don't learn a permanent pattern yet
	Action string `json:"action"`

	// PatternType: "prefix", "regex", "contains", or "" (no pattern learned).
	// Only returned when Action is "allow" or "suppress".
	// Deny patterns are suggested but not auto-promoted.
	PatternType string `json:"pattern_type,omitempty"`

	// Pattern: the actual match string/expression.
	// For prefix: a literal string prefix (e.g. "Connected to database in")
	// For regex: an anchored regex (e.g. "^Connected to database in \\d+ms$")
	// For contains: a substring (e.g. "health check passed")
	Pattern string `json:"pattern,omitempty"`

	// SourceHint: the LLM's guess at which service produced this log.
	// Used to cross-check that we're filing the pattern in the right scope.
	SourceHint string `json:"source_hint,omitempty"`

	// VariableFields: the LLM's identification of which parts of the raw log
	// line are variable (change between structurally identical lines).
	// Used to discover normalization rules for unknown services.
	VariableFields []VariableField `json:"variable_fields,omitempty"`
}

// VariableField identifies a token in the raw log line that the LLM believes
// is variable content (changes between structurally identical log lines).
type VariableField struct {
	// Token: the actual variable content from this specific line (e.g. "31#31:")
	Token string `json:"token"`

	// Type: what kind of variable this is (e.g. "pid", "timestamp", "ip",
	// "connection_id", "request_id", "duration", "byte_count", "user_agent")
	Type string `json:"type"`

	// Replacement: what the normalizer should replace this with (e.g. "<PID>:", "<TS>", "<IP>")
	Replacement string `json:"replacement"`
}

// Client handles communication with an LLM inference server (local or cloud).
type Client struct {
	baseURL    string
	httpClient *http.Client
	model      string
	apiKey     string
}

func NewClient(baseURL, model, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		model:   model,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// AnalyzeLog sends a log entry to the LLM and gets back a structured verdict
// with optional learned pattern.
func (c *Client) AnalyzeLog(ctx context.Context, sourceType, sourceName, logLine, normalizedLine string) (*Verdict, error) {
	systemPrompt := `You are a security log analyzer for a Linux server infrastructure.
Your job is to classify log lines and teach the system to recognize similar lines in the future.

Respond ONLY with a JSON object in this exact format:
{
  "classification": "safe" | "suspicious" | "malicious" | "noise" | "recon_failed" | "recon_success",
  "confidence": 0.0 to 1.0,
  "reason": "brief explanation",
  "action": "allow" | "deny" | "suppress" | "alert",
  "pattern_type": "prefix" | "regex" | "contains" | "",
  "pattern": "the pattern string or empty",
  "source_hint": "service name guess",
  "variable_fields": [
    {"token": "the exact variable text", "type": "pid|timestamp|ip|connection_id|duration|byte_count|port|user_agent|request_id", "replacement": "<PLACEHOLDER>"}
  ]
}

CLASSIFICATION + ACTION RULES:

INTENT × OUTCOME IS EVERYTHING. The request path tells you what the attacker WANTED. The status code tells you what HAPPENED. You must consider both.

- "safe" + "allow": Normal operational logs (app startup, health checks, routine requests from legitimate clients, crawler/bot traffic with normal responses)
- "noise" + "suppress": Uninteresting output (debug spam, metric dumps, heartbeats, routine status). NOT the same as "safe" — suppress means "not worth caring about ever."

- "recon_failed" + "suppress": An attacker or scanner probed for something and GOT NOTHING. Examples:
  * ANY request to a sensitive path (.env, wp-admin, phpunit, /etc/passwd, autodiscover, etc.) that returned 404, 403, 405, or 400
  * Port scans, path enumeration, CMS probes, vulnerability scanners — all with error responses
  * TLS handshake failures, malformed requests returning 400
  * This is the most common type of "attack" on any internet-facing server. It is background noise.
  * The attacker FAILED. There is nothing to investigate. Suppress it.

- "recon_success" + "alert": An attacker or scanner probed for something sensitive and GOT A REAL RESPONSE. Examples:
  * Request to /.env, /config.yml, /api/.env, /.git/HEAD, etc. that returned 200 or 301/302 to a content page
  * Sensitive path that returned actual content instead of an error
  * This is URGENT — it means something is exposed that should not be.

- "suspicious" + "alert": Unusual activity that is NOT a simple failed probe. Examples:
  * Successful authentication from an unexpected source
  * Unusual response sizes or patterns
  * Legitimate paths but abnormal behavior
  * Do NOT use "suspicious" for scanner traffic that returned error codes — that is "recon_failed"

- "malicious" + "deny": Confirmed attack payloads in the request itself, regardless of status code. Examples:
  * Shell injection (;ls, | cat /etc/passwd, etc.) in URL or parameters
  * SQL injection (UNION SELECT, OR 1=1) in URL or parameters
  * PHP wrapper attacks (php://input, allow_url_include)
  * Encoded exploit payloads
  * The payload IS the evidence — the status code doesn't matter here

CRITICAL RULES FOR HTTP ACCESS LOGS:
- ALWAYS look at the HTTP status code (200, 301, 302, 400, 403, 404, 405, 500, etc.)
- Status 404/403/405/400 on a suspicious path = recon_failed = suppress
- Status 200 on a suspicious path = recon_success = alert (something is exposed!)
- Status 302 on a suspicious path = check context. Redirect to a login page = recon_failed. Redirect to content = recon_success.
- A scanner hitting 50 paths and getting 404 on all of them is NOT 50 alerts. It is noise. Suppress it.
- A single 200 on /.env is worth more than 1000 failed probes. Alert on it.

CRITICAL RULES FOR ERROR LOGS:
- nginx "open() failed (2: No such file or directory)" = the file does not exist = recon_failed = suppress
- Application errors from normal operation = safe or noise
- Errors triggered by malicious input = check the request content for payloads

PATTERN RULES (critical — read carefully):
- Only return a pattern when action is "allow" or "suppress". Never for "alert" or "deny".
- PREFER "prefix" when the log line starts with a recognizable fixed string. This is the fastest and safest option.
- Use "regex" only when the line has variable content in the MIDDLE that a prefix can't skip. Always anchor with ^ and use \d+ for numbers, \S+ for non-space tokens. Be specific.
- Use "contains" only as a last resort. Minimum 10 characters.
- Return empty pattern_type and pattern ("") if you are not confident.

PATTERN MUST match the normalized version of the log line, not the raw version.
The normalized line has timestamps replaced with <TS>, IPs with <IP>, durations with <DUR>,
numbers (4+ digits) with <NUM>, UUIDs with <UUID>.

VARIABLE FIELDS RULES:
- Identify parts of the RAW log line that change between structurally identical lines.
- Common variable types: timestamp, pid, ip, connection_id, duration, byte_count, port, user_agent, request_id, session_id
- The "token" must be the EXACT text from the raw line.
- The "replacement" should be a placeholder like <PID>, <TS>, <IP>, <CONN>, <DUR>, <BYTES>, <PORT>, <UA>, <REQ_ID>
- Only include fields you are confident about. Empty array is fine if unsure.

EXAMPLES:
Line: "GET /.env HTTP/1.1 404 0"
→ classification: "recon_failed", action: "suppress", reason: "Probe for .env file returned 404 — attacker found nothing"

Line: "GET /.env HTTP/1.1 200 1534"
→ classification: "recon_success", action: "alert", reason: ".env file returned 200 with 1534 bytes — configuration file is exposed"

Line: "GET /wp-admin/install.php HTTP/1.1 404 0"
→ classification: "recon_failed", action: "suppress", reason: "WordPress install probe returned 404"

Line: "POST /?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1 405 150"
→ classification: "malicious", action: "deny", reason: "PHP wrapper injection attempt in query string"

Line: "open() /usr/share/nginx/default/tool.php failed (2: No such file or directory)"
→ classification: "recon_failed", action: "suppress", reason: "Nginx file-not-found for probed PHP path"

Line: "Connected to database in 47ms"
Normalized: "Connected to database in <DUR>"
→ classification: "safe", action: "allow", pattern_type: "prefix", pattern: "Connected to database in"

CRITICAL JSON RULES:
- Your response MUST be valid JSON. Do NOT use regex-style escapes inside JSON strings.
- In JSON, the ONLY valid escape sequences are: \" \\ \/ \b \f \n \r \t \uXXXX
- WRONG: \; \+ \( \) \[ \] \- \. — these are NOT valid JSON escapes and will break parsing.
- If your pattern contains special regex characters like ; + ( ) [ ] put them as-is WITHOUT a backslash, OR double-escape with \\\\ for literal backslashes.
- When in doubt, use a simpler prefix pattern WITHOUT regex characters.`

	userPrompt := fmt.Sprintf("Source: %s:%s\nRaw log line: %s\nNormalized line: %s",
		sourceType, sourceName, logLine, normalizedLine)

	reqBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"max_completion_tokens": 4096,
		"reasoning_effort":     "low",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/v1/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LLM returned %d: %s", resp.StatusCode, string(body))
	}

	rawBody, _ := io.ReadAll(resp.Body)

	// Parse OpenAI-compatible response
	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(rawBody, &chatResp); err != nil {
		return nil, fmt.Errorf("decoding LLM response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("LLM returned no choices")
	}

	// Parse the structured verdict from the LLM's response
	content := chatResp.Choices[0].Message.Content
	if content == "" {
		// Log the raw response to understand why content is empty.
		// Common causes: reasoning tokens consumed entire budget,
		// content filter, or model returned content in a different field.
		log.Printf("[llm] Empty content from LLM. Raw response (first 500 bytes): %s", truncateStr(string(rawBody), 500))
		return nil, fmt.Errorf("LLM returned empty content")
	}
	var verdict Verdict
	if err := json.Unmarshal([]byte(content), &verdict); err != nil {
		// LLM sometimes wraps JSON in markdown code blocks
		content = stripCodeBlock(content)
		if err := json.Unmarshal([]byte(content), &verdict); err != nil {
			// LLM sometimes uses invalid JSON escapes like \; \+ \( etc.
			// Try sanitizing those before giving up.
			sanitized := sanitizeJSON(content)
			if err := json.Unmarshal([]byte(sanitized), &verdict); err != nil {
				log.Printf("[llm] Failed to parse verdict from: %s", content)
				return nil, fmt.Errorf("parsing verdict: %w", err)
			}
		}
	}

	// Sanitize: don't trust deny patterns from the LLM.
	// They can be suggested but should not be auto-learned.
	if verdict.Action == "deny" {
		verdict.PatternType = ""
		verdict.Pattern = ""
	}

	// Sanitize: alert shouldn't have patterns either —
	// suspicious lines need continued scrutiny, not auto-classification.
	if verdict.Action == "alert" {
		verdict.PatternType = ""
		verdict.Pattern = ""
	}

	// Consistency check: if the LLM says classification=safe but action=deny/alert,
	// or classification=malicious but action=allow, override the action to match
	// the classification. GPT-5 nano hallucinations can produce contradictory fields.
	verdict.Action = reconcileClassificationAction(verdict.Classification, verdict.Action, verdict.Reason)

	return &verdict, nil
}

// reconcileClassificationAction ensures the action matches the classification.
// When they contradict, classification wins because it's the simpler, more
// constrained field (less room for hallucination).
func reconcileClassificationAction(classification, action, reason string) string {
	switch classification {
	case "safe":
		if action != "allow" {
			log.Printf("[llm] Contradiction: classification=%q but action=%q reason=%q — overriding to allow",
				classification, action, reason)
			return "allow"
		}
	case "noise", "recon_failed":
		if action != "suppress" {
			log.Printf("[llm] Contradiction: classification=%q but action=%q — overriding to suppress",
				classification, action)
			return "suppress"
		}
	case "recon_success", "suspicious":
		if action != "alert" {
			log.Printf("[llm] Contradiction: classification=%q but action=%q — overriding to alert",
				classification, action)
			return "alert"
		}
	case "malicious":
		if action != "deny" {
			log.Printf("[llm] Contradiction: classification=%q but action=%q — overriding to deny",
				classification, action)
			return "deny"
		}
	}
	return action
}

// HealthCheck verifies the LLM inference server is reachable.
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/v1/models", nil)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("LLM unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("LLM health check returned %d", resp.StatusCode)
	}
	return nil
}

func stripCodeBlock(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```json") {
		s = s[7:]
	} else if strings.HasPrefix(s, "```") {
		s = s[3:]
	}
	if strings.HasSuffix(s, "```") {
		s = s[:len(s)-3]
	}
	return strings.TrimSpace(s)
}

// sanitizeJSON fixes common invalid JSON escape sequences produced by LLMs.
// LLMs frequently generate regex-style escapes like \; \+ \( \) inside JSON
// strings, which are not valid JSON. This function:
//   - Preserves valid JSON escapes: \" \\ \/ \b \f \n \r \t \uXXXX
//   - Converts regex metachar escapes (\d \w \s \S \D \W) to double-escaped (\\d etc.)
//     so the JSON is valid AND the regex meaning is preserved
//   - Strips backslash from everything else (\; \+ \( etc.) — junk escapes
func sanitizeJSON(s string) string {
	var result strings.Builder
	result.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			// Valid JSON escapes — keep as-is
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u':
				result.WriteByte(s[i])
				result.WriteByte(next)
				i++
			// Regex metacharacter escapes — the LLM meant \d, \w, \s etc.
			// but wrote it as a raw \d which is invalid JSON.
			// Double the backslash so JSON sees \\d → which decodes to \d in the string.
			case 'd', 'w', 's', 'S', 'D', 'W':
				result.WriteString("\\\\")
				result.WriteByte(next)
				i++
			// Everything else: \; \+ \( \) \[ \] \- \. \* \? \^ \$ \| \!
			// Strip the backslash, keep the character.
			default:
				result.WriteByte(next)
				i++
			}
		} else {
			result.WriteByte(s[i])
		}
	}

	return result.String()
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}