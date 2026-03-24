package analyzer

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/patternstore"
)

// AnalysisResult is the output of the full analysis pipeline.
type AnalysisResult struct {
	Event   *event.Event             `json:"event"`
	Verdict patternstore.Verdict     `json:"verdict"`
	Tier    patternstore.PatternType `json:"tier,omitempty"`   // Which tier matched
	Reason  string                   `json:"reason,omitempty"` // Why this verdict
	Source  string                   `json:"source,omitempty"` // "pattern", "llm", "seeded"

	// LLM-specific fields (only set when the LLM was consulted)
	LLMClassification string  `json:"llm_classification,omitempty"`
	LLMConfidence     float64 `json:"llm_confidence,omitempty"`
	LLMPatternLearned bool    `json:"llm_pattern_learned,omitempty"`
}

// Analyzer is the core analysis pipeline.
// It orchestrates: normalize → pattern match → LLM classify → learn.
type Analyzer struct {
	normalizers *normalizer.Registry
	patterns    *patternstore.Store
	llmClient   *llm.Client
	hints       *normalizer.HintCollector

	// llmSem limits concurrent LLM calls to prevent flooding the
	// inference server when a burst of unknown logs arrives (e.g. startup).
	llmSem chan struct{}

	// stats uses atomic counters — safe for concurrent goroutines.
	stats Stats
}

// Stats tracks pipeline performance metrics.
// All fields use atomic operations for thread safety.
type Stats struct {
	TotalProcessed  atomic.Int64 `json:"total_processed"`
	PatternHits     atomic.Int64 `json:"pattern_hits"`
	NoiseSuppressed atomic.Int64 `json:"noise_suppressed"` // deterministic stack trace / framework noise
	LLMCalls        atomic.Int64 `json:"llm_calls"`
	LLMErrors       atomic.Int64 `json:"llm_errors"`
	LLMDropped      atomic.Int64 `json:"llm_dropped"` // dropped due to semaphore full
	PatternsLearned atomic.Int64 `json:"patterns_learned"`
}

// StatsSnapshot is a plain copy for logging/serialization.
type StatsSnapshot struct {
	TotalProcessed  int64 `json:"total_processed"`
	PatternHits     int64 `json:"pattern_hits"`
	NoiseSuppressed int64 `json:"noise_suppressed"`
	LLMCalls        int64 `json:"llm_calls"`
	LLMErrors       int64 `json:"llm_errors"`
	LLMDropped      int64 `json:"llm_dropped"`
	PatternsLearned int64 `json:"patterns_learned"`
}

// New creates an Analyzer with the given components.
// maxConcurrentLLM controls how many LLM calls can run in parallel.
// Recommended: 2-4 for local Ollama, 10+ for cloud APIs.
func New(normalizers *normalizer.Registry, patterns *patternstore.Store, llmClient *llm.Client, maxConcurrentLLM int) *Analyzer {
	if maxConcurrentLLM < 1 {
		maxConcurrentLLM = 2
	}
	return &Analyzer{
		normalizers: normalizers,
		patterns:    patterns,
		llmClient:   llmClient,
		hints:       normalizer.NewHintCollector(),
		llmSem:      make(chan struct{}, maxConcurrentLLM),
	}
}

// Analyze runs the full pipeline on an event:
//
//  1. Normalize the line (source-family-aware)
//  2. Check pattern store (hash → prefix → regex → contains)
//  3. If unknown: consult the LLM (with concurrency limit)
//  4. Learn from the LLM's response (if confident enough)
//
// Returns the analysis result. The caller decides what to do with it
// (alert, suppress, log, etc.).
func (a *Analyzer) Analyze(ctx context.Context, evt *event.Event) AnalysisResult {
	a.stats.TotalProcessed.Add(1)

	// --- Step 1: Normalize ---
	a.normalizers.NormalizeEvent(evt)

	// --- Step 1.5: Deterministic noise suppression ---
	// Cheap regex-free detection of obvious application noise.
	// These patterns are structural (not content-dependent) and should
	// NEVER hit the LLM or pattern store. Zero cost, zero ambiguity.
	//
	// DESIGN DECISION (v0.15, 2026-03-24): Deterministic suppression
	// for stack traces agreed by the team, code review, , .
	// The LLM already proved it can cache the WRONG answer for these
	// (Remix stack trace classified as "alert" → 25 emails overnight).
	if isOperationalNoise(evt.Line) {
		a.stats.NoiseSuppressed.Add(1)
		return AnalysisResult{
			Event:   evt,
			Verdict: patternstore.VerdictSuppress,
			Reason:  "Deterministic: application stack trace or framework noise",
			Source:  "noise_filter",
		}
	}

	// --- Step 1.6: Deterministic failed-probe suppression ---
	// If the normalized line shows a 404/403/405/400 HTTP response AND the
	// request path has no attack payload, this is recon_failed. Period.
	// The LLM gets this right ~90% of the time but occasionally hedges and
	// says "alert" for a clean 404 probe. One bad call, cached forever, 70 emails.
	// Same lesson as stack traces: don't let the LLM vote on structural facts.
	//
	// SAFETY: If the path or query string contains attack indicators (encoded
	// payloads, SQL injection, path traversal), we let the LLM classify it.
	// The payload is evidence regardless of status code.
	if reason, ok := isFailedProbe(evt.NormalizedLine); ok {
		a.stats.NoiseSuppressed.Add(1)
		return AnalysisResult{
			Event:   evt,
			Verdict: patternstore.VerdictSuppress,
			Reason:  reason,
			Source:  "noise_filter",
		}
	}

	// --- Step 2: Pattern store check ---
	result := a.patterns.Match(evt.ScopeKey(), evt.Hash, evt.NormalizedLine)
	if result != nil {
		a.stats.PatternHits.Add(1)

		return AnalysisResult{
			Event:   evt,
			Verdict: result.Verdict,
			Tier:    result.Tier,
			Reason:  result.Pattern.Reason,
			Source:  result.Pattern.Source,
		}
	}

	// --- Step 3: Unknown → consult LLM (with backpressure) ---

	// Try to acquire semaphore. If full, don't block — log as unknown.
	// This prevents 30 startup logs from creating 30 concurrent LLM calls.
	select {
	case a.llmSem <- struct{}{}:
		// Acquired slot
		defer func() { <-a.llmSem }()
	default:
		// Semaphore full — skip LLM, return unknown
		a.stats.LLMDropped.Add(1)
		return AnalysisResult{
			Event:   evt,
			Verdict: patternstore.VerdictUnknown,
			Reason:  "LLM concurrency limit reached",
			Source:  "backpressure",
		}
	}

	a.stats.LLMCalls.Add(1)

	verdict, err := a.llmClient.AnalyzeLog(
		ctx,
		evt.SourceType,
		evt.SourceName,
		evt.Line,
		evt.NormalizedLine,
	)
	if err != nil {
		a.stats.LLMErrors.Add(1)
		log.Printf("[analyzer] LLM error for %s: %v", evt.ScopeKey(), err)

		// On LLM failure, return unknown — don't auto-allow or auto-deny
		return AnalysisResult{
			Event:   evt,
			Verdict: patternstore.VerdictUnknown,
			Reason:  fmt.Sprintf("LLM error: %v", err),
			Source:  "error",
		}
	}

	log.Printf("[analyzer] LLM verdict for %s: classification=%s confidence=%.2f action=%s pattern_type=%s",
		evt.ScopeKey(), verdict.Classification, verdict.Confidence, verdict.Action, verdict.PatternType)

	// --- Step 3b: Collect normalization hints ---
	// The LLM already read the log line. If it identified variable fields,
	// feed them to the hint collector for consensus analysis.
	if len(verdict.VariableFields) > 0 {
		hints := make([]normalizer.VariableHint, len(verdict.VariableFields))
		for i, vf := range verdict.VariableFields {
			hints[i] = normalizer.VariableHint{
				Token:       vf.Token,
				Type:        vf.Type,
				Replacement: vf.Replacement,
			}
		}
		a.hints.Add(evt.ScopeKey(), hints)
	}

	// --- Step 4: Learn from the LLM's response ---
	patternLearned := a.learnFromVerdict(evt, verdict)

	// Map LLM action to our verdict type
	v := mapActionToVerdict(verdict.Action)

	return AnalysisResult{
		Event:             evt,
		Verdict:           v,
		Reason:            verdict.Reason,
		Source:            "llm",
		LLMClassification: verdict.Classification,
		LLMConfidence:     verdict.Confidence,
		LLMPatternLearned: patternLearned,
	}
}

// learnFromVerdict processes the LLM's response and adds learned patterns
// to the pattern store. Returns true if a pattern was learned.
func (a *Analyzer) learnFromVerdict(evt *event.Event, verdict *llm.Verdict) bool {
	scopeKey := evt.ScopeKey()
	v := mapActionToVerdict(verdict.Action)

	// Always learn the exact hash for allow/suppress (fast path for exact repeats)
	if v == patternstore.VerdictAllow || v == patternstore.VerdictSuppress {
		a.patterns.LearnHash(scopeKey, v, evt.Hash, verdict.Reason, evt.NormalizedLine)
	}

	// For deny, learn the hash but NOT patterns (conservative trust model)
	if v == patternstore.VerdictDeny {
		a.patterns.LearnHash(scopeKey, v, evt.Hash, verdict.Reason, evt.NormalizedLine)
		return false
	}

	// For alert, learn the exact hash so identical suspicious lines get instant
	// alerts without burning another LLM call. Stored as VerdictAlert — semantically
	// distinct from VerdictDeny (suspicious vs confirmed-bad). Hash-only, no patterns,
	// no generalization. The conservative trust model is preserved.
	if verdict.Action == "alert" {
		a.patterns.LearnHash(scopeKey, patternstore.VerdictAlert, evt.Hash, verdict.Reason, evt.NormalizedLine)
		return false
	}

	// If the LLM returned a pattern, validate and learn it
	if verdict.Pattern == "" || verdict.PatternType == "" {
		return false
	}

	// SOURCE HINT CHECK — REMOVED (v0.12)
	//
	// Previously, we asked the LLM to tell us what service the log came from,
	// then verified its guess against the actual source. This was backwards:
	// we ALREADY KNOW the source from the Event struct (SourceName, ScopeKey).
	// The pattern is already scoped to evt.ScopeKey(). The LLM's verbose hints
	// ("nginx access logs in docker container") didn't match CapRover's Swarm
	// names ("srv-captain--website.1.abc123"), causing learned=0 on production.
	//
	// The fix: stop asking the LLM what we already know. Scope patterns to the
	// known source directly. The sourceHintMatches() function is preserved below
	// for reference but no longer gates pattern learning.
	//
	// If source_hint is still in the LLM prompt, it's harmless — we just ignore it.

	// Confidence gate: only learn patterns from high-confidence verdicts
	if verdict.Confidence < 0.85 {
		log.Printf("[analyzer] Confidence %.2f too low for pattern learning (need 0.85+)", verdict.Confidence)
		return false
	}

	// Map pattern type
	var pt patternstore.PatternType
	switch verdict.PatternType {
	case "prefix":
		pt = patternstore.PatternPrefix
	case "regex":
		pt = patternstore.PatternRegex
	case "contains":
		pt = patternstore.PatternContains
	default:
		log.Printf("[analyzer] Unknown pattern type from LLM: %q", verdict.PatternType)
		return false
	}

	pattern := patternstore.LearnedPattern{
		Type:         pt,
		Value:        verdict.Pattern,
		Source:       "llm",
		Reason:       verdict.Reason,
		OriginalLine: evt.NormalizedLine,
		CreatedAt:    time.Now(),
	}

	if err := a.patterns.Learn(scopeKey, v, pattern); err != nil {
		log.Printf("[analyzer] Failed to learn pattern: %v", err)
		return false
	}

	a.stats.PatternsLearned.Add(1)
	log.Printf("[analyzer] Learned %s pattern for %s [%s]: %q",
		verdict.PatternType, scopeKey, v, verdict.Pattern)
	return true
}

func mapActionToVerdict(action string) patternstore.Verdict {
	switch action {
	case "allow":
		return patternstore.VerdictAllow
	case "deny":
		return patternstore.VerdictDeny
	case "alert":
		return patternstore.VerdictAlert
	case "suppress":
		return patternstore.VerdictSuppress
	default:
		return patternstore.VerdictUnknown
	}
}

// GetStats returns a snapshot of current pipeline statistics.
func (a *Analyzer) GetStats() StatsSnapshot {
	return StatsSnapshot{
		TotalProcessed:  a.stats.TotalProcessed.Load(),
		PatternHits:     a.stats.PatternHits.Load(),
		NoiseSuppressed: a.stats.NoiseSuppressed.Load(),
		LLMCalls:        a.stats.LLMCalls.Load(),
		LLMErrors:       a.stats.LLMErrors.Load(),
		LLMDropped:      a.stats.LLMDropped.Load(),
		PatternsLearned: a.stats.PatternsLearned.Load(),
	}
}

// Persist saves the pattern store to disk.
func (a *Analyzer) Persist() error {
	return a.patterns.Persist()
}

// =============================================================================
// Deterministic Noise Detection
// =============================================================================
//
// Cheap, regex-free detection of application noise that should never reach
// the LLM or pattern store. These are structural patterns — the shape of
// the line tells you it's noise, not the content.
//
// WHY THIS EXISTS:
//   The LLM classified a Remix stack trace as "suspicious/alert" on first
//   encounter. The hash got cached. Every identical stack trace fired the
//   cached alert verdict: 25+ emails overnight from application errors.
//   Deterministic suppression prevents the LLM from ever making this
//   mistake in the first place.
//
// SAFETY RULE (code review's catch):
//   These checks run on the RAW line, not the normalized line. They look
//   for structural patterns (indentation + "at", "Traceback", etc.) that
//   are unambiguous. If a stack trace also contains an exploit payload,
//   the LLM prompt improvements will catch it when the non-stack-trace
//   log line (the request line) comes through separately.

func isOperationalNoise(line string) bool {
	// Strip Docker timestamp prefix for pattern matching
	trimmed := line
	if len(trimmed) > 30 && trimmed[4] == '-' && trimmed[7] == '-' && trimmed[10] == 'T' {
		if idx := strings.IndexByte(trimmed, ' '); idx > 0 && idx < 40 {
			trimmed = trimmed[idx+1:]
		}
	}

	if len(trimmed) == 0 {
		return false
	}

	// --- Node.js / JavaScript stack frames ---
	// "    at handleDocumentRequest (/app/node_modules/@remix-run/server-runtime/dist/server.js:275:35)"
	// "    at async Object.requestHandler (/app/node_modules/...)"
	// CHECK BEFORE TrimSpace — the leading whitespace IS the signal.
	// TrimSpace would eat the indentation that distinguishes a stack frame
	// from a normal log line starting with "at".
	if len(trimmed) > 4 && (trimmed[0] == ' ' || trimmed[0] == '\t') {
		inner := strings.TrimLeft(trimmed, " \t")
		if strings.HasPrefix(inner, "at ") {
			return true
		}
	}

	// Now TrimSpace for the remaining checks
	trimmed = strings.TrimSpace(trimmed)

	if len(trimmed) == 0 {
		return false
	}

	// --- Python tracebacks ---
	// "Traceback (most recent call last):"
	// "  File "/app/main.py", line 42, in handle"
	if strings.HasPrefix(trimmed, "Traceback (most recent call last)") {
		return true
	}
	if strings.HasPrefix(trimmed, "File \"") && strings.Contains(trimmed, ", line ") {
		return true
	}

	// --- Go panics (the stack dump lines, not the panic message itself) ---
	// "goroutine 1 [running]:"
	// "/usr/local/go/src/runtime/panic.go:1234 +0x1a0"
	if strings.HasPrefix(trimmed, "goroutine ") && strings.Contains(trimmed, " [") {
		return true
	}

	// --- Java/JVM stack frames ---
	// "	at com.example.MyClass.method(MyClass.java:42)"
	// "Caused by: java.lang.NullPointerException"
	if strings.HasPrefix(trimmed, "at ") && strings.Contains(trimmed, "(") && strings.Contains(trimmed, ".java:") {
		return true
	}
	if strings.HasPrefix(trimmed, "Caused by: ") {
		return true
	}

	return false
}

// =============================================================================
// Deterministic Failed-Probe Detection
// =============================================================================
//
// HTTP probes that returned 404/403/405/400 with no attack payload in the
// request are recon_failed. The attacker found nothing. The LLM gets this
// right ~90% of the time but occasionally says "alert" for a clean 404.
// One bad call → cached forever → emails every time that hash repeats.
//
// This runs on the NORMALIZED line (not raw) because the normalizer preserves
// the HTTP status code. Checks all three normalized formats.
//
// SAFETY: Requests with attack indicators in the path or query string are
// NOT suppressed here. Those go to the LLM because the payload is evidence
// regardless of status code.

// Regex patterns for extracting status codes from normalized lines.
// These mirror the formats in httpparse.go but extract just what we need.
var (
	reStatusHosted = regexp.MustCompile(`HTTP/\S+\s+(\d{3})`)
	reStatusQuoted = regexp.MustCompile(`HTTP/\S+"\s+(\d{3})`)
)

// failedStatusCodes are HTTP status codes that indicate a probe found nothing.
// NOTE: 401 (Unauthorized) is deliberately excluded. A 401 means "this endpoint
// exists and requires auth" — that's surface discovery, not pure nothing.
// code review's catch: /admin returning 401 is a meaningful finding.
var failedStatusCodes = map[string]bool{
	"400": true, // Bad request
	"403": true, // Forbidden
	"404": true, // Not found
	"405": true, // Method not allowed
	"410": true, // Gone
}

// attackIndicators are substrings that suggest the request itself contains
// an attack payload. If any of these appear in the path/query, we let the
// LLM classify it even if the status code is 404.
var attackIndicators = []string{
	"UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE",  // SQL
	"../", "..\\",                                              // path traversal
	"%00", "%0a", "%0d", "%27", "%22",                         // null/injection encoding
	"<script", "javascript:",                                   // XSS
	";ls", ";cat", ";rm", ";wget", ";curl",                    // command injection (specific)
	"|", "`", "$(", "${",                                       // command injection (operators)
	"php://", "data://", "file://",                             // PHP wrappers
	"eval(", "exec(", "system(",                                // code execution
}

func isFailedProbe(normalizedLine string) (string, bool) {
	if normalizedLine == "" {
		return "", false
	}

	// Extract status code from normalized line
	var statusCode string
	var requestPart string

	if m := reStatusHosted.FindStringSubmatch(normalizedLine); m != nil {
		statusCode = m[1]
		requestPart = normalizedLine
	} else if m := reStatusQuoted.FindStringSubmatch(normalizedLine); m != nil {
		statusCode = m[1]
		requestPart = normalizedLine
	} else {
		return "", false // not an HTTP access log line
	}

	// Is this a failed status code?
	if !failedStatusCodes[statusCode] {
		return "", false
	}

	// Check for attack payloads in the request — if present, let the LLM decide
	upper := strings.ToUpper(requestPart)
	for _, indicator := range attackIndicators {
		if strings.Contains(upper, strings.ToUpper(indicator)) {
			return "", false // has payload, LLM should classify
		}
	}

	reason := fmt.Sprintf("Deterministic: HTTP %s response — probe found nothing, no attack payload in request", statusCode)
	return reason, true
}