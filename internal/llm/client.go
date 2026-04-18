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

	// Action: "allow", "malicious", "suppress", "alert"
	//   allow    → whitelist as known-good
	//   malicious    → blacklist as known-bad, alert immediately
	//   suppress → known-noise, don't alert, don't re-analyze
	//   alert    → suspicious but don't learn a permanent pattern yet
	Action string `json:"action"`

	// PatternType: "prefix", "regex", "contains", or "" (no pattern learned).
	// Only returned when Action is "allow" or "suppress".
	// Malicious patterns are suggested but not auto-promoted.
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

	// Call metadata (populated by the client, not the LLM)
	PromptTokens     int    `json:"-"` // excluded from LLM JSON parse
	CompletionTokens int    `json:"-"`
	LatencyMs        int64  `json:"-"`
	ResponseRaw      string `json:"-"` // full LLM JSON response for audit trail
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
	baseURL      string
	httpClient   *http.Client
	model        string
	apiKey       string
	tier1Effort  string // reasoning_effort for Tier 1 (AnalyzeLog) — "low", "medium", "high"
	tier2Effort  string // reasoning_effort for Tier 2 (ReclassifyWithEvidence)
}

func NewClient(baseURL, model, apiKey, tier1Effort, tier2Effort string) *Client {
	if tier1Effort == "" {
		tier1Effort = "low"
	}
	if tier2Effort == "" {
		tier2Effort = "medium"
	}
	return &Client{
		baseURL:     baseURL,
		model:       model,
		apiKey:      apiKey,
		tier1Effort: tier1Effort,
		tier2Effort: tier2Effort,
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
  "action": "allow" | "malicious" | "suppress" | "alert",
  "pattern_type": "prefix" | "regex" | "contains" | "",
  "pattern": "the pattern string or empty",
  "source_hint": "service name guess",
  "variable_fields": [
    {"token": "the exact variable text", "type": "pid|timestamp|ip|connection_id|duration|byte_count|port|user_agent|request_id", "replacement": "<PLACEHOLDER>"}
  ]
}

CLASSIFICATION + ACTION RULES:

INTENT × OUTCOME IS EVERYTHING. The request path tells you what the attacker WANTED. The status code tells you what HAPPENED. You must consider both.

- "safe" + "allow": Normal operational logs (app startup, health checks, routine requests, crawler/bot traffic with normal responses)
- "noise" + "suppress": Uninteresting output (debug spam, metric dumps, heartbeats, routine status)
- "recon_failed" + "suppress": Attacker probed and GOT NOTHING (error response codes on suspicious paths)
- "recon_success" + "alert": Attacker probed something sensitive and GOT A REAL RESPONSE (200 on /.env, /.git, /config, etc.) — this is URGENT
- "suspicious" + "alert": Unusual activity that is NOT a simple failed probe (unexpected auth, abnormal response sizes, legitimate paths with abnormal behavior)
- "malicious" + "malicious": Confirmed attack payloads in the request itself, regardless of status code (SQL injection, shell injection, PHP wrappers, encoded exploits)

KEY RULES:
- ALWAYS look at the HTTP status code
- Status 200 on a sensitive path = recon_success = alert
- Status 302 to login = recon_failed. Status 302 to content = recon_success
- Attack payloads in the URL (UNION SELECT, ;ls, php://) = malicious regardless of status code

EXPLICIT EDGE CASES — THESE HAVE BEEN INCORRECTLY CLASSIFIED BEFORE:

Protocol mismatch on port 80 (ALWAYS noise + suppress):
- TLS handshake bytes (\x16\x03) in the request line + status 400 = noise + suppress. This is an HTTPS client hitting an HTTP port. Not an attack. Not suspicious. Just wrong protocol.
- SSH banner (SSH-2.0-*) in the request line + status 400 = noise + suppress. SSH client hitting an HTTP port. Not an attack.
- Any binary/hex payload in the request line + status 400 = noise + suppress. The server rejected garbage input.

Failed file probes (ALWAYS recon_failed + suppress):
- "open() failed" or "No such file or directory" in nginx error logs = recon_failed + suppress. The file does not exist. The probe failed. Period.
- Status 302 on ANY path (including sensitive paths like .env, .git, /admin) = recon_failed + suppress. A 302 redirect means the server sent the attacker to a login page or default page. The attacker got NOTHING from the original path.
- Status 400 on any path = recon_failed + suppress. The server rejected the request entirely.
- Status 403 on any path = recon_failed + suppress. The server blocked access.
- Status 404 on any path = recon_failed + suppress. The resource does not exist.
- Status 405 on any path = recon_failed + suppress. Wrong HTTP method, request rejected.

DO NOT contradict yourself:
- If your reason says the probe "failed", "was rejected", "got nothing", "did not disclose", or "no sensitive data was exposed" — then your classification MUST be recon_failed, NOT alert or suspicious.
- If your reason says "open() failed" or "No such file or directory" — that is ALWAYS recon_failed + suppress. No exceptions.
- A failed probe is not suspicious. A failed probe is a FAILED probe. Classify it as such.

Status 200 is the ONLY ambiguous case:
- Status 200 on a sensitive path (.env, .git, /config, /admin, /wp-admin) = recon_success + alert. The server served SOMETHING. We need evidence to know what.
- Status 200 on a normal path with attack payload in query = malicious + malicious. The payload is the attack, regardless of what the server returned.

NOTE: Stack traces, failed 404/403/405 probes, nginx file-not-found errors, and framework noise are pre-filtered before reaching you. You will NOT see these. Focus on genuinely ambiguous lines.

SYSTEM LOG RULES (sshd, sudo, systemd, kernel):
These logs come from the host OS, not web applications. Different rules apply.

SSH BRUTE FORCE (ALWAYS recon_failed + suppress):
Every public Linux server gets thousands of failed SSH attempts per day. This is background internet noise, not a security event. These are ALWAYS recon_failed + suppress with confidence 0.95.
- "Failed password for root from <IP> port <PORT> ssh2" = recon_failed + suppress
- "Failed password for invalid user admin from <IP> port <PORT> ssh2" = recon_failed + suppress
- "Invalid user admin from <IP> port <PORT>" = recon_failed + suppress
- "Connection closed by <IP> port <PORT> [preauth]" = recon_failed + suppress
- "Connection reset by <IP> port <PORT> [preauth]" = recon_failed + suppress
- "Disconnected from invalid user admin <IP> port <PORT> [preauth]" = recon_failed + suppress
- "Received disconnect from <IP> port <PORT>" + [preauth] = recon_failed + suppress
- "maximum authentication attempts exceeded" = recon_failed + suppress
- "pam_unix(sshd:auth): authentication failure" = recon_failed + suppress
- "Unable to negotiate" / "no matching key exchange" = recon_failed + suppress
- "banner exchange: Connection from" = recon_failed + suppress
- "PAM X more authentication failure" = recon_failed + suppress
Do NOT classify failed SSH as "suspicious" or "alert". A failed login is a FAILED login. The attacker did not get in. This is recon_failed, exactly like a 404 probe on a web server. Use prefix pattern "Failed password for" or "Invalid user" for suppress patterns.

SSH SUCCESS (suspicious + alert — DIFFERENT from brute force):
- "Accepted password for" or "Accepted publickey for" = suspicious + alert. This means someone actually logged in. Worth flagging.

OTHER SYSTEM LOG RULES:
- Failed sudo attempt = suspicious + alert. Already inside the perimeter, trying to escalate.
- Successful sudo by root = safe + allow. Normal administration.
- UFW/iptables BLOCK from external IP = recon_failed + suppress. Firewall handled it. Confidence 0.95.
- New user creation (useradd, groupadd, usermod) = suspicious + alert. Potential persistence.
- Kernel module load (insmod, modprobe) = suspicious + alert. Could indicate rootkit.
- Systemd service restarts, reloads, timer events = noise + suppress. Routine. Confidence 0.95.
- Connection closed/reset [preauth] = recon_failed + suppress. Handshake terminated before auth. Confidence 0.95.

IMPORTANT: For system logs, be confident. These patterns are well-understood. Use confidence 0.90+ for clear-cut cases. Do NOT hedge with 0.60-0.75 on failed SSH — you will poison the pattern cache with wrong classifications that persist forever.

PATTERN RULES:
- Only return a pattern when action is "allow" or "suppress". Never for "alert" or "malicious".
- PREFER "prefix" — fastest and safest.
- Use "regex" only when variable content is in the MIDDLE. Always anchor with ^. Be specific.
- Use "contains" only as last resort. Minimum 10 characters.
- PATTERN MUST match the NORMALIZED version (timestamps=<TS>, IPs=<IP>, numbers=<NUM>, UUIDs=<UUID>).

VARIABLE FIELDS:
- Identify parts of the RAW log line that change between structurally identical lines.
- Types: timestamp, pid, ip, connection_id, duration, byte_count, port, user_agent, request_id
- "token" = exact text from raw line. "replacement" = placeholder like <PID>, <TS>, <IP>
- Empty array is fine if unsure.

CRITICAL JSON RULES:
- Response MUST be valid JSON. Do NOT use regex-style escapes inside JSON strings.
- Only valid escapes: \" \\ \/ \b \f \n \r \t \uXXXX
- Put regex characters like ; + ( ) [ ] as-is WITHOUT backslash, or double-escape with \\\\
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
		"reasoning_effort":     c.tier1Effort,
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

	llmStart := time.Now()
	resp, err := c.httpClient.Do(req)
	llmLatency := time.Since(llmStart)
	if err != nil {
		return nil, fmt.Errorf("LLM request failed (after %s): %w", llmLatency.Round(time.Millisecond), err)
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
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(rawBody, &chatResp); err != nil {
		return nil, fmt.Errorf("decoding LLM response: %w", err)
	}

	log.Printf("[llm] AnalyzeLog tokens: prompt=%d completion=%d total=%d effort=%s latency=%s",
		chatResp.Usage.PromptTokens, chatResp.Usage.CompletionTokens, chatResp.Usage.TotalTokens,
		c.tier1Effort, llmLatency.Round(time.Millisecond))

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

	// Sanitize: don't trust malicious patterns from the LLM.
	// They can be suggested but should not be auto-learned.
	if verdict.Action == "malicious" {
		verdict.PatternType = ""
		verdict.Pattern = ""
	}

	// Sanitize: alert shouldn't have patterns either —
	// suspicious lines need continued scrutiny, not auto-classification.
	if verdict.Action == "alert" {
		verdict.PatternType = ""
		verdict.Pattern = ""
	}

	// Consistency check: if the LLM says classification=safe but action=malicious/alert,
	// or classification=malicious but action=allow, override the action to match
	// the classification. GPT-5 nano hallucinations can produce contradictory fields.
	verdict.Action = reconcileClassificationAction(verdict.Classification, verdict.Action, verdict.Reason)

	// Attach call metadata for the audit trail
	verdict.PromptTokens = chatResp.Usage.PromptTokens
	verdict.CompletionTokens = chatResp.Usage.CompletionTokens
	verdict.LatencyMs = llmLatency.Milliseconds()
	verdict.ResponseRaw = content

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
		if action != "malicious" {
			log.Printf("[llm] Contradiction: classification=%q but action=%q — overriding to malicious",
				classification, action)
			return "malicious"
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

// =============================================================================
// Evidence-Aware Re-Classification
// =============================================================================
//
// When Observer captures the server's HTTP response via REC, we can ask the
// LLM to re-evaluate its initial verdict with the actual evidence.
//
// The initial classification only sees the log line: "GET /?q=UNION+SELECT 200"
// The LLM assumes 200 + big body = "attack succeeded."
//
// Re-classification sees the log line PLUS the redacted response body:
// "<!DOCTYPE html>...Laravel v11.36.1..." — clearly a welcome page, not a
// database dump. The attack was ignored by the app.
//
// This is the difference between "someone tried something" and
// "someone tried something and HERE'S WHAT THEY GOT."

// ReclassifyVerdict is the simplified result of evidence-aware re-classification.
type ReclassifyVerdict struct {
	Classification string  `json:"classification"`
	Confidence     float64 `json:"confidence"`
	Reason         string  `json:"reason"`
	Action         string  `json:"action"`
	Downgraded     bool    `json:"downgraded"` // true if severity was reduced
	Escalated      bool    `json:"escalated"`  // true if severity was increased (e.g. suspicious → malicious)

	// Call metadata (populated by the client, not the LLM)
	PromptTokens     int    `json:"-"`
	CompletionTokens int    `json:"-"`
	LatencyMs        int64  `json:"-"`
	ResponseRaw      string `json:"-"`
}

// ReclassifyWithEvidence asks the LLM to re-evaluate a verdict given captured
// response evidence. Only called when:
//   1. Initial verdict was malicious/alert (suspicious/malicious)
//   2. REC captured the response with high correlation confidence
//   3. Redaction passed (SafeBodyPreview is populated)
//
// Returns the updated verdict. If the LLM confirms the original severity,
// Downgraded=false. If it reduces severity, Downgraded=true.
func (c *Client) ReclassifyWithEvidence(
	ctx context.Context,
	originalClassification string,
	originalReason string,
	logLine string,
	statusCode int,
	contentType string,
	contentLength int64,
	safeBodyPreview string,
) (*ReclassifyVerdict, error) {

	systemPrompt := `You are a security response analyzer. You previously classified a log line as suspicious or malicious. Now you have the server's actual HTTP response.

Your job: determine if the attack actually SUCCEEDED (server returned sensitive data) or FAILED (server returned its normal response and ignored the attack payload).

Respond ONLY with a JSON object:
{
  "classification": "safe" | "suspicious" | "malicious" | "recon_failed" | "recon_success",
  "confidence": 0.0 to 1.0,
  "reason": "brief explanation of what the response evidence shows",
  "action": "allow" | "malicious" | "suppress" | "alert"
}

RULES:
- If the response body is a standard framework page (Laravel, Rails, Django, Express, etc.), error page, login page, or API status — the attack FAILED. The application ignored the malicious input. Classify as "recon_failed" + "suppress" with a reason explaining it's a normal response.
- If the response body contains database records, user data, configuration values, system files, or any data that should not be exposed — the attack SUCCEEDED. Keep or upgrade the severity.
- If the response body is an API error message revealing stack traces, database errors, or internal paths — classify as "recon_success" + "alert" (information disclosure even if not the intended exploit).
- The attack payload in the REQUEST still happened. You are judging the OUTCOME based on the RESPONSE.
- A 200 status code does NOT mean the attack succeeded. Many apps return 200 for their default page regardless of query parameters.
- A 403/404 with a large body could be a custom error page — check the content.

ESCALATION RULES — when to UPGRADE severity:
- If the response body contains KEY=VALUE pairs with credentials (passwords, API keys, secret keys, tokens) → classify as "malicious" + "malicious". This is confirmed credential exposure.
- If the response body contains /etc/passwd or /etc/shadow formatted output → "malicious" + "malicious". System file exfiltration confirmed.
- If the response body contains SQL query results, database dumps, or table data → "malicious" + "malicious". Data exfiltration confirmed.
- If the response body contains JSON with user records, emails, or PII → "malicious" + "malicious". Data breach confirmed.

DOWNGRADE RULES — when to REDUCE severity:
- Generic HTML page (framework welcome page, admin login, redirect landing) → "recon_failed" + "suppress"
- Nginx default pages (302 Found, 404 Not Found, standard error HTML) → "recon_failed" + "suppress"
- MinIO Console HTML (login page served for any unknown path) → "recon_failed" + "suppress"
- Empty or trivial response (short UUID, "ok", status JSON) → "recon_failed" + "suppress"
- CapRover dashboard HTML (UI app shell with static assets) → "recon_failed" + "suppress"

CRITICAL: Look at the actual body content, not just the status code. The body tells the truth.`

	userPrompt := fmt.Sprintf(`ORIGINAL CLASSIFICATION: %s
ORIGINAL REASON: %s

LOG LINE: %s

SERVER RESPONSE:
  Status Code: %d
  Content-Type: %s
  Content-Length: %d

RESPONSE BODY (redacted preview):
%s

Based on this response evidence, did the attack succeed or did the server ignore it?`,
		originalClassification,
		originalReason,
		logLine,
		statusCode,
		contentType,
		contentLength,
		safeBodyPreview,
	)

	reqBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"max_completion_tokens": 4096,
		"reasoning_effort":     c.tier2Effort,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshalling reclassify request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/v1/chat/completions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating reclassify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	reclassStart := time.Now()
	resp, err := c.httpClient.Do(req)
	reclassLatency := time.Since(reclassStart)
	if err != nil {
		return nil, fmt.Errorf("reclassify request failed (after %s): %w", reclassLatency.Round(time.Millisecond), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("reclassify returned %d: %s", resp.StatusCode, string(body))
	}

	rawBody, _ := io.ReadAll(resp.Body)

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(rawBody, &chatResp); err != nil {
		return nil, fmt.Errorf("decoding reclassify response: %w", err)
	}

	log.Printf("[llm] ReclassifyWithEvidence tokens: prompt=%d completion=%d total=%d effort=%s latency=%s",
		chatResp.Usage.PromptTokens, chatResp.Usage.CompletionTokens, chatResp.Usage.TotalTokens,
		c.tier2Effort, reclassLatency.Round(time.Millisecond))

	if len(chatResp.Choices) == 0 || chatResp.Choices[0].Message.Content == "" {
		return nil, fmt.Errorf("reclassify returned empty content")
	}

	content := chatResp.Choices[0].Message.Content
	content = stripCodeBlock(content)

	var result ReclassifyVerdict
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		sanitized := sanitizeJSON(content)
		if err := json.Unmarshal([]byte(sanitized), &result); err != nil {
			return nil, fmt.Errorf("parsing reclassify verdict: %w (content: %s)", err, truncateStr(content, 200))
		}
	}

	// Reconcile classification and action
	result.Action = reconcileClassificationAction(result.Classification, result.Action, result.Reason)

	// Determine if this is a downgrade or escalation
	result.Downgraded = isDowngrade(originalClassification, result.Classification)
	result.Escalated = isEscalation(originalClassification, result.Classification)

	// Attach call metadata for the audit trail
	result.PromptTokens = chatResp.Usage.PromptTokens
	result.CompletionTokens = chatResp.Usage.CompletionTokens
	result.LatencyMs = reclassLatency.Milliseconds()
	result.ResponseRaw = content

	return &result, nil
}

// isDowngrade returns true if the new classification is less severe than the original.
func isDowngrade(original, updated string) bool {
	severity := map[string]int{
		"safe":          0,
		"noise":         0,
		"recon_failed":  1,
		"recon_success": 3,
		"suspicious":    4,
		"malicious":     5,
	}
	return severity[updated] < severity[original]
}

// isEscalation returns true if the new classification is MORE severe than the original.
// This happens when evidence confirms real data exposure (e.g., suspicious → malicious
// because the response body contained actual credentials).
func isEscalation(original, updated string) bool {
	severity := map[string]int{
		"safe":          0,
		"noise":         0,
		"recon_failed":  1,
		"recon_success": 3,
		"suspicious":    4,
		"malicious":     5,
	}
	return severity[updated] > severity[original]
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