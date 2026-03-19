package normalizer

import (
	"log"
	"sync"
)

// VariableHint is a single observation from the LLM about a variable field
// in a log line. Mirrors llm.VariableField but lives in the normalizer package
// to avoid circular imports.
type VariableHint struct {
	Token       string // The exact variable text observed (e.g. "31#31:")
	Type        string // What kind of variable (e.g. "pid", "timestamp", "ip")
	Replacement string // Suggested placeholder (e.g. "<PID>:")
}

// typeCount tracks how many times a particular variable type was seen
// at this position, and an example of the replacement suggested.
type typeCount struct {
	Count       int
	Replacement string // Most recent suggestion
	Example     string // Most recent token example
}

// sourceHints accumulates hints for a single source key.
type sourceHints struct {
	// totalLines is how many lines we've collected hints for.
	totalLines int

	// typeCounts maps variable type → count of observations.
	// If 15 out of 20 lines agree that there's a "pid" field, that's strong.
	typeCounts map[string]*typeCount

	// reported tracks which types we've already logged suggestions for,
	// so we don't spam the same suggestion every time the threshold is hit.
	reported map[string]bool
}

// HintCollector accumulates variable field hints from LLM responses
// and logs consensus suggestions when enough data has been collected.
//
// This is Phase 2 of the normalizer improvement plan:
// - We're already paying for the LLM call
// - The model is already reading the log line
// - We just ask one more question and collect the answers
// - After enough observations, we log what the LLM thinks the normalizer should strip
//
// This does NOT auto-generate normalizers. It produces log lines like:
//
//	[hints] Suggestion for docker:my-app: field type "pid" seen in 17/20 lines,
//	        example: "31#31:" → "<PID>:"
//
// A developer can then use these suggestions to write or improve normalizers.
type HintCollector struct {
	mu sync.Mutex

	// hints maps source key (e.g. "docker:demo-nginx") → accumulated hints
	hints map[string]*sourceHints

	// minSamples is how many lines we need before logging a suggestion.
	minSamples int

	// consensusRatio is the fraction of lines that must agree on a variable
	// type before we consider it a strong signal. 0.6 = 60%.
	consensusRatio float64
}

// NewHintCollector creates a collector with sensible defaults.
// minSamples=20 means we wait for 20 LLM responses before suggesting.
// consensusRatio=0.6 means 60% of lines must agree on a variable type.
func NewHintCollector() *HintCollector {
	return &HintCollector{
		hints:          make(map[string]*sourceHints),
		minSamples:     20,
		consensusRatio: 0.6,
	}
}

// Add records variable field hints from a single LLM response.
// Called from the analyzer after every LLM call that returns hints.
func (hc *HintCollector) Add(scopeKey string, hints []VariableHint) {
	if len(hints) == 0 {
		return
	}

	hc.mu.Lock()
	defer hc.mu.Unlock()

	sh, ok := hc.hints[scopeKey]
	if !ok {
		sh = &sourceHints{
			typeCounts: make(map[string]*typeCount),
			reported:   make(map[string]bool),
		}
		hc.hints[scopeKey] = sh
	}

	sh.totalLines++

	for _, h := range hints {
		if h.Type == "" {
			continue
		}
		tc, ok := sh.typeCounts[h.Type]
		if !ok {
			tc = &typeCount{}
			sh.typeCounts[h.Type] = tc
		}
		tc.Count++
		tc.Replacement = h.Replacement
		tc.Example = h.Token
	}

	// Check for consensus after enough samples
	if sh.totalLines >= hc.minSamples {
		hc.checkConsensus(scopeKey, sh)
	}
}

// checkConsensus logs suggestions for variable types that have strong agreement.
func (hc *HintCollector) checkConsensus(scopeKey string, sh *sourceHints) {
	threshold := int(float64(sh.totalLines) * hc.consensusRatio)

	for varType, tc := range sh.typeCounts {
		if tc.Count >= threshold && !sh.reported[varType] {
			log.Printf("[hints] Suggestion for %s: field type %q seen in %d/%d lines, example: %q → %q",
				scopeKey, varType, tc.Count, sh.totalLines, tc.Example, tc.Replacement)
			sh.reported[varType] = true
		}
	}
}

// GetSuggestions returns the current state for a source key — for future
// dashboard/API use. Returns nil if no hints collected yet.
func (hc *HintCollector) GetSuggestions(scopeKey string) map[string]*TypeSuggestion {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	sh, ok := hc.hints[scopeKey]
	if !ok {
		return nil
	}

	result := make(map[string]*TypeSuggestion)
	for varType, tc := range sh.typeCounts {
		result[varType] = &TypeSuggestion{
			Type:        varType,
			Count:       tc.Count,
			TotalLines:  sh.totalLines,
			Ratio:       float64(tc.Count) / float64(sh.totalLines),
			Example:     tc.Example,
			Replacement: tc.Replacement,
		}
	}
	return result
}

// TypeSuggestion is the external representation of a hint consensus.
type TypeSuggestion struct {
	Type        string  `json:"type"`
	Count       int     `json:"count"`
	TotalLines  int     `json:"total_lines"`
	Ratio       float64 `json:"ratio"`
	Example     string  `json:"example"`
	Replacement string  `json:"replacement"`
}
