package analyzer

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vaultguardian/logwatch/internal/event"
	"github.com/vaultguardian/logwatch/internal/llm"
	"github.com/vaultguardian/logwatch/internal/normalizer"
	"github.com/vaultguardian/logwatch/internal/patternstore"
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
	LLMCalls        atomic.Int64 `json:"llm_calls"`
	LLMErrors       atomic.Int64 `json:"llm_errors"`
	LLMDropped      atomic.Int64 `json:"llm_dropped"` // dropped due to semaphore full
	PatternsLearned atomic.Int64 `json:"patterns_learned"`
}

// StatsSnapshot is a plain copy for logging/serialization.
type StatsSnapshot struct {
	TotalProcessed  int64 `json:"total_processed"`
	PatternHits     int64 `json:"pattern_hits"`
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

	// Source hint cross-check (fuzzy): if the LLM thinks this is from a
	// completely unrelated service, don't trust the pattern.
	// Docker Swarm names look like "captain-nginx.1.hjfscqq05nqt..." — we extract
	// the short service name (before first ".") for comparison.
	// LLM hints are verbose like "nginx access logs in docker container" — we check
	// if any significant word from the hint appears in the source name, or vice versa.
	if verdict.SourceHint != "" && !sourceHintMatches(evt.SourceName, verdict.SourceHint) {
		log.Printf("[analyzer] Source hint mismatch: LLM says %q, actual is %q — skipping pattern",
			verdict.SourceHint, evt.SourceName)
		return false
	}

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

// sourceHintMatches checks whether the LLM's source hint plausibly refers to
// the same service as the actual source name.
//
// Docker Swarm names look like "captain-nginx.1.hjfscqq05nqtarebk0ps5xsgo".
// The LLM returns verbose hints like "nginx access logs in docker container".
//
// Strategy:
//  1. Extract the short name from the source (before first ".") → "captain-nginx"
//  2. Check if the short name appears in the hint, or vice versa
//  3. Tokenize both and look for any shared word of 4+ chars that isn't
//     a common filler word (docker, container, log, access, service, etc.)
func sourceHintMatches(sourceName, sourceHint string) bool {
	nameLower := strings.ToLower(sourceName)
	hintLower := strings.ToLower(sourceHint)

	// Direct containment (handles simple cases like "nginx" / "demo-nginx")
	if strings.Contains(nameLower, hintLower) || strings.Contains(hintLower, nameLower) {
		return true
	}

	// Extract short name: "captain-nginx.1.hjfsc..." → "captain-nginx"
	shortName := nameLower
	if dotIdx := strings.Index(nameLower, "."); dotIdx > 0 {
		shortName = nameLower[:dotIdx]
	}

	// Check short name against hint
	if strings.Contains(hintLower, shortName) {
		return true
	}

	// Check if hint contains any segment of the short name split by "-"
	// "captain-nginx" → check "captain", "nginx" against hint
	// "srv-captain--api" → check "srv", "captain", "api"
	segments := strings.FieldsFunc(shortName, func(r rune) bool { return r == '-' })
	for _, seg := range segments {
		if len(seg) < 4 {
			continue // skip short segments like "srv"
		}
		if isFillerWord(seg) {
			continue
		}
		if strings.Contains(hintLower, seg) {
			return true
		}
	}

	// Reverse: check if any significant word from the hint appears in the source name
	hintWords := strings.FieldsFunc(hintLower, func(r rune) bool {
		return r == ' ' || r == '/' || r == '(' || r == ')' || r == ':'
	})
	for _, word := range hintWords {
		if len(word) < 4 {
			continue
		}
		if isFillerWord(word) {
			continue
		}
		if strings.Contains(nameLower, word) {
			return true
		}
	}

	return false
}

// isFillerWord returns true for common words that appear in LLM source hints
// but don't actually identify a specific service.
func isFillerWord(word string) bool {
	switch word {
	case "docker", "container", "containerized", "containers",
		"logs", "logging", "access", "error", "service",
		"server", "running", "inside", "from", "with",
		"http", "https", "application", "startup", "message",
		"messages", "info", "build", "script", "system",
		"entry", "entrypoint", "daemon", "process":
		return true
	}
	return false
}

// GetStats returns a snapshot of current pipeline statistics.
func (a *Analyzer) GetStats() StatsSnapshot {
	return StatsSnapshot{
		TotalProcessed:  a.stats.TotalProcessed.Load(),
		PatternHits:     a.stats.PatternHits.Load(),
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