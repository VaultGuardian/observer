package patternstore

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Verdict is the outcome of pattern matching against an event.
type Verdict string

const (
	VerdictAllow     Verdict = "allow"     // Known-good, skip silently
	VerdictMalicious Verdict = "malicious" // Known-bad, alert with high severity
	VerdictAlert     Verdict = "alert"     // Suspicious, alert with lower severity, exact-hash memoized
	VerdictSuppress  Verdict = "suppress"  // Known-noise, don't alert, don't send to LLM
	VerdictUnknown   Verdict = "unknown"   // No match — forward to LLM
)

// PatternType controls which matching tier a learned pattern uses.
type PatternType string

const (
	PatternHash     PatternType = "hash"     // Exact normalized hash match
	PatternPrefix   PatternType = "prefix"   // strings.HasPrefix
	PatternRegex    PatternType = "regex"    // Pre-compiled regexp
	PatternContains PatternType = "contains" // strings.Contains (guarded, rare)
)

// =============================================================================
// Auto-Learning Safety Caps (v0.47, hardening item #2)
// =============================================================================
//
// Without these caps the hash bucket grows without bound. An attacker spraying
// novel-hash payloads through any path that reaches LLM classification (alerts,
// LLM-suppressed sensitive paths before F1 lands, encoded payloads bypassing
// deterministic gates) can fill memory until the OOM-killer drops Observer.
//
// Policy:
//   - "auto" (LLM-learned) and "llm" hashes are capped per bucket.
//   - "human", "human_validated", and "seeded" patterns are NEVER capped or
//     rejected. Operator intent always wins.
//   - When the cap is hit, new auto-learned hashes are rejected (logged once
//     per minute per bucket). Eviction is deferred to post-v1 — reject is
//     simpler, and a cap of 100K per bucket × 4 buckets × N scopes is plenty
//     of headroom for legitimate operation.
const (
	MaxAutoHashesPerBucket   = 100000
	MaxAutoPrefixesPerBucket = 1000
	MaxAutoRegexesPerBucket  = 1000
	MaxAutoContainsPerBucket = 500
)

// genericPrefixBlocklist holds the prefix values that LLM auto-learning is
// never allowed to use, even when length validation passes. These are tokens
// so common across log streams that suppressing/allowing them effectively
// blinds the analyzer for that scope. Human/seeded sources may use anything.
//
// Matching semantics (v0.47, code review): the candidate prefix is
// "stripped" — whitespace and normalizer placeholders (anything inside <...>
// like <TS>, <NUM>, <PID>, <UUID>) are removed — and the result is compared
// case-insensitively for EQUALITY against each blocklist entry.
//
// This means:
//
//	"ERROR"                         → blocked (stripped="ERROR")
//	"ERROR "                        → blocked (stripped="ERROR")
//	"ERROR <NUM>"                   → blocked (stripped="ERROR")
//	"ERROR <TS> <PID> <CONN>"       → blocked (stripped="ERROR")
//	"ERROR opening database conn"   → allowed (stripped has real content)
//	"Failed password for "          → allowed (no entry matches "Failedpasswordfor")
//
// "Failed" and "Exception" intentionally NOT listed — the Tier-1 prompt
// recommends prefixes like "Failed password for " for SSH brute-force
// suppression. Length+must-prefix-original kills the bare-word case.
var genericPrefixBlocklist = []string{
	"ERROR",
	"WARN",
	"WARNING",
	"INFO",
	"DEBUG",
	"TRACE",
	"NOTICE",
	"FATAL",
	"GET /",
	"POST /",
	"PUT /",
	"DELETE /",
	"HEAD /",
	"PATCH /",
	"OPTIONS /",
	"panic:",
}

// rePlaceholder matches normalizer placeholders like <TS>, <NUM>, <UUID>,
// <PID:1234>, etc. — any angle-bracketed token. Used to "strip" prefixes
// down to their meaningful structural content for blocklist comparison.
var rePlaceholder = regexp.MustCompile(`<[^>]*>`)

// stripPrefixForBlocklist removes whitespace and normalizer placeholders
// from a prefix value so the blocklist can compare meaningful content only.
func stripPrefixForBlocklist(value string) string {
	stripped := rePlaceholder.ReplaceAllString(value, "")
	return strings.Join(strings.Fields(stripped), "")
}

// isHumanOrSeededSource returns true for pattern sources that should bypass
// the auto-learning safety caps and stricter validation. Operator intent
// always wins over heuristics.
func isHumanOrSeededSource(source string) bool {
	switch source {
	case "human", "human_validated", "seeded":
		return true
	default:
		return false
	}
}

// LearnedPattern is a single pattern entry learned from the LLM or seeded manually.
type LearnedPattern struct {
	// Type determines which matching function to use.
	Type PatternType `json:"type"`

	// Value is the pattern string:
	//   hash     → the SHA-256 hex string
	//   prefix   → the literal prefix to match
	//   regex    → the regex source string
	//   contains → the substring to search for
	Value string `json:"value"`

	// Source is which LLM/admin/seed added this pattern.
	Source string `json:"source,omitempty"`

	// Reason is a human-readable explanation (from LLM or admin).
	Reason string `json:"reason,omitempty"`

	// OriginalLine is the first log line that triggered this pattern.
	OriginalLine string `json:"original_line,omitempty"`

	// CreatedAt is when the pattern was learned.
	CreatedAt time.Time `json:"created_at"`

	// CreatedFromEventID links back to the event that triggered this pattern's
	// creation. Powers the cache lineage feature: "Originally learned from evt_x".
	// Empty for seeded patterns and patterns learned before this field existed.
	CreatedFromEventID string `json:"created_from_event_id,omitempty"`

	// RevokedAt / RevokedBy support soft-disable of patterns (append-only
	// correction model). Revoked patterns are skipped by Match() but preserved
	// in the store for audit trail. Physical deletion remains available via
	// DeletePattern() for backward compatibility.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	RevokedBy string     `json:"revoked_by,omitempty"`

	// compiled is the pre-compiled regex (only for PatternRegex).
	// Not serialized — rebuilt on load.
	compiled *regexp.Regexp
}

// PatternBucket holds patterns for one verdict type (allow, malicious, or suppress)
// scoped to a single source key.
type PatternBucket struct {
	Hashes   map[string]*LearnedPattern `json:"hashes,omitempty"`   // hash → pattern
	Prefixes []*LearnedPattern          `json:"prefixes,omitempty"` // checked in order
	Regexes  []*LearnedPattern          `json:"regexes,omitempty"`  // checked in order
	Contains []*LearnedPattern          `json:"contains,omitempty"` // checked last, guarded
}

// ScopeEntry holds all four buckets for a single source scope key.
type ScopeEntry struct {
	Allow     PatternBucket `json:"allow"`
	Malicious PatternBucket `json:"malicious"`
	Alert     PatternBucket `json:"alert"`
	Suppress  PatternBucket `json:"suppress"`
}

// MatchResult is returned when a pattern matches, with context about what matched.
type MatchResult struct {
	Verdict Verdict
	Pattern *LearnedPattern
	Tier    PatternType // Which matching tier caught it
}

// Store is the tiered pattern store, scoped per source key.
// Thread-safe for concurrent use by multiple collectors.
type Store struct {
	mu sync.RWMutex

	// scopes maps "source_type:source_name" → ScopeEntry
	scopes map[string]*ScopeEntry

	// global holds patterns that apply to ALL sources.
	// Checked after source-scoped patterns.
	global *ScopeEntry

	// stats tracks matching performance.
	stats Stats

	// dataDir is where patterns are persisted to disk.
	dataDir string
}

// Stats tracks pattern matching statistics for monitoring.
// All fields use atomic operations for thread safety.
type Stats struct {
	TotalChecked  atomic.Int64
	HashHits      atomic.Int64
	PrefixHits    atomic.Int64
	RegexHits     atomic.Int64
	ContainsHits  atomic.Int64
	MaliciousHits atomic.Int64
	AlertHits     atomic.Int64
	SuppressHits  atomic.Int64
	Misses        atomic.Int64
	PatternCount  atomic.Int64

	// v0.47 — auto-learning safety caps
	AutoLearnRejected atomic.Int64 // bumped when cap hit or validation rejects auto pattern
	AutoLearnCapped   atomic.Int64 // bumped specifically on bucket-size cap (subset of Rejected)
}

// StatsSnapshot is a plain copy for logging/serialization.
type StatsSnapshot struct {
	TotalChecked  int64 `json:"total_checked"`
	HashHits      int64 `json:"hash_hits"`
	PrefixHits    int64 `json:"prefix_hits"`
	RegexHits     int64 `json:"regex_hits"`
	ContainsHits  int64 `json:"contains_hits"`
	MaliciousHits int64 `json:"malicious_hits"`
	AlertHits     int64 `json:"alert_hits"`
	SuppressHits  int64 `json:"suppress_hits"`
	Misses        int64 `json:"misses"`
	PatternCount  int64 `json:"pattern_count"`

	AutoLearnRejected int64 `json:"auto_learn_rejected"`
	AutoLearnCapped   int64 `json:"auto_learn_capped"`
}

// NewStore creates a pattern store with the given data directory for persistence.
func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		scopes:  make(map[string]*ScopeEntry),
		global:  &ScopeEntry{},
		dataDir: dataDir,
	}
	initBucket(&s.global.Allow)
	initBucket(&s.global.Malicious)
	initBucket(&s.global.Alert)
	initBucket(&s.global.Suppress)

	if err := s.load(); err != nil {
		return nil, fmt.Errorf("loading pattern store: %w", err)
	}

	return s, nil
}

func initBucket(b *PatternBucket) {
	if b.Hashes == nil {
		b.Hashes = make(map[string]*LearnedPattern)
	}
}

// Match checks an event against all pattern tiers.
// Order: malicious first (safety), then allow, then suppress.
// Within each verdict: source-scoped first, then global.
// Within each scope: hash → prefix → regex → contains.
func (s *Store) Match(scopeKey, hash, normalizedLine string) *MatchResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.stats.TotalChecked.Add(1)

	// --- DENY first (safety: known-bad takes priority) ---
	if r := s.matchBucket(scopeKey, hash, normalizedLine, VerdictMalicious); r != nil {
		s.stats.MaliciousHits.Add(1)
		s.trackTierHit(r.Tier)
		return r
	}

	// --- ALERT (suspicious, memoized exact hashes) ---
	if r := s.matchBucket(scopeKey, hash, normalizedLine, VerdictAlert); r != nil {
		s.stats.AlertHits.Add(1)
		s.trackTierHit(r.Tier)
		return r
	}

	// --- ALLOW (known-good, skip) ---
	if r := s.matchBucket(scopeKey, hash, normalizedLine, VerdictAllow); r != nil {
		s.trackTierHit(r.Tier)
		return r
	}

	// --- SUPPRESS (known-noise, skip) ---
	if r := s.matchBucket(scopeKey, hash, normalizedLine, VerdictSuppress); r != nil {
		s.stats.SuppressHits.Add(1)
		s.trackTierHit(r.Tier)
		return r
	}

	// --- No match: unknown ---
	s.stats.Misses.Add(1)
	return nil
}

// trackTierHit increments the counter for whichever matching tier caught the line.
func (s *Store) trackTierHit(tier PatternType) {
	switch tier {
	case PatternHash:
		s.stats.HashHits.Add(1)
	case PatternPrefix:
		s.stats.PrefixHits.Add(1)
	case PatternRegex:
		s.stats.RegexHits.Add(1)
	case PatternContains:
		s.stats.ContainsHits.Add(1)
	}
}

func (s *Store) matchBucket(scopeKey, hash, normalizedLine string, v Verdict) *MatchResult {
	// Check source-scoped patterns first
	if scope, ok := s.scopes[scopeKey]; ok {
		bucket := s.getBucket(scope, v)
		if r := matchTiers(bucket, hash, normalizedLine, v); r != nil {
			return r
		}
	}

	// Then check global patterns
	bucket := s.getBucket(s.global, v)
	return matchTiers(bucket, hash, normalizedLine, v)
}

func (s *Store) getBucket(scope *ScopeEntry, v Verdict) *PatternBucket {
	switch v {
	case VerdictAllow:
		return &scope.Allow
	case VerdictMalicious:
		return &scope.Malicious
	case VerdictAlert:
		return &scope.Alert
	case VerdictSuppress:
		return &scope.Suppress
	default:
		// v0.52: Unknown verdicts must NOT silently land in the allow bucket.
		// Prior to this fix, the default case returned &scope.Allow, so an
		// invalid LLM output could become a permanent allow pattern.
		log.Printf("[patternstore] BUG: getBucket called with unknown verdict %q — returning nil", v)
		return nil
	}
}

// matchTiers runs through the matching tiers in priority order.
// Revoked patterns are skipped — they remain in the store for audit trail
// but do not participate in matching. Future events matching a revoked
// pattern will fall through to fresh LLM classification.
func matchTiers(b *PatternBucket, hash, normalizedLine string, v Verdict) *MatchResult {
	if b == nil {
		return nil
	}
	// Tier 1: Exact hash (O(1), nanoseconds)
	if p, ok := b.Hashes[hash]; ok && p.RevokedAt == nil {
		return &MatchResult{Verdict: v, Pattern: p, Tier: PatternHash}
	}

	// Tier 2: Prefix (strings.HasPrefix, sub-nanosecond each)
	for _, p := range b.Prefixes {
		if p.RevokedAt == nil && strings.HasPrefix(normalizedLine, p.Value) {
			return &MatchResult{Verdict: v, Pattern: p, Tier: PatternPrefix}
		}
	}

	// Tier 3: Regex (pre-compiled, microseconds each)
	for _, p := range b.Regexes {
		if p.RevokedAt == nil && p.compiled != nil && p.compiled.MatchString(normalizedLine) {
			return &MatchResult{Verdict: v, Pattern: p, Tier: PatternRegex}
		}
	}

	// Tier 4: Contains (guarded, rare — checked last)
	for _, p := range b.Contains {
		if p.RevokedAt == nil && strings.Contains(normalizedLine, p.Value) {
			return &MatchResult{Verdict: v, Pattern: p, Tier: PatternContains}
		}
	}

	return nil
}

// Learn adds a new pattern to the store.
// The pattern is validated before insertion:
//   - regex patterns must compile
//   - regex patterns must match the original line
//   - contains patterns require minimum length (anti-overgeneralization)
//   - LLM-source patterns face stricter validation than human/seeded patterns
//
// v0.47: per-bucket caps prevent unbounded auto-hash growth.
// Human and seeded patterns bypass caps; only "auto"/"llm" sources are capped.
func (s *Store) Learn(scopeKey string, verdict Verdict, pattern LearnedPattern) error {
	// Validate (uses pattern.Source to apply LLM-stricter rules)
	if err := s.validatePattern(&pattern); err != nil {
		if !isHumanOrSeededSource(pattern.Source) {
			s.stats.AutoLearnRejected.Add(1)
		}
		return fmt.Errorf("invalid pattern: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	scope := s.getOrCreateScope(scopeKey)
	bucket := s.getBucket(scope, verdict)
	if bucket == nil {
		return fmt.Errorf("unknown verdict %q — refusing to learn", verdict)
	}

	// Cap check — only applies to non-human, non-seeded sources.
	// Operator-curated patterns are never capped.
	if !isHumanOrSeededSource(pattern.Source) {
		if reason, capped := s.bucketAtCap(bucket, pattern.Type); capped {
			s.stats.AutoLearnRejected.Add(1)
			s.stats.AutoLearnCapped.Add(1)
			return fmt.Errorf("auto-learn cap reached for %s/%s: %s", scopeKey, verdict, reason)
		}
	}

	switch pattern.Type {
	case PatternHash:
		bucket.Hashes[pattern.Value] = &pattern
	case PatternPrefix:
		bucket.Prefixes = append(bucket.Prefixes, &pattern)
	case PatternRegex:
		bucket.Regexes = append(bucket.Regexes, &pattern)
	case PatternContains:
		bucket.Contains = append(bucket.Contains, &pattern)
	default:
		return fmt.Errorf("unknown pattern type: %s", pattern.Type)
	}

	s.stats.PatternCount.Add(1)
	return nil
}

// bucketAtCap returns a non-empty reason and true when the relevant tier of
// the bucket has reached its auto-learn cap. Caller must hold s.mu.
func (s *Store) bucketAtCap(bucket *PatternBucket, pt PatternType) (string, bool) {
	switch pt {
	case PatternHash:
		if len(bucket.Hashes) >= MaxAutoHashesPerBucket {
			return fmt.Sprintf("hashes=%d >= %d", len(bucket.Hashes), MaxAutoHashesPerBucket), true
		}
	case PatternPrefix:
		if len(bucket.Prefixes) >= MaxAutoPrefixesPerBucket {
			return fmt.Sprintf("prefixes=%d >= %d", len(bucket.Prefixes), MaxAutoPrefixesPerBucket), true
		}
	case PatternRegex:
		if len(bucket.Regexes) >= MaxAutoRegexesPerBucket {
			return fmt.Sprintf("regexes=%d >= %d", len(bucket.Regexes), MaxAutoRegexesPerBucket), true
		}
	case PatternContains:
		if len(bucket.Contains) >= MaxAutoContainsPerBucket {
			return fmt.Sprintf("contains=%d >= %d", len(bucket.Contains), MaxAutoContainsPerBucket), true
		}
	}
	return "", false
}

// LearnHash is a convenience method for adding an exact hash match.
func (s *Store) LearnHash(scopeKey string, verdict Verdict, hash, reason, originalLine, eventID string) {
	_ = s.Learn(scopeKey, verdict, LearnedPattern{
		Type:               PatternHash,
		Value:              hash,
		Source:             "auto",
		Reason:             reason,
		OriginalLine:       originalLine,
		CreatedAt:          time.Now(),
		CreatedFromEventID: eventID,
	})
}

// validatePattern enforces structural and safety rules on patterns.
//
// Rules differ by source (v0.47, F3):
//
//   - human / human_validated / seeded sources are permissive — operator
//     intent always wins. Minimum lengths still apply (defends against
//     accidental empty values).
//
//   - "auto" / "llm" / anything else (LLM-driven auto-learning) faces
//     stricter rules:
//
//   - prefix length >= 20 chars
//
//   - prefix must be a literal prefix of OriginalLine
//
//   - prefix must not be on the generic-token blocklist (ERROR, GET /, etc.)
//
//   - regex must compile, must match OriginalLine, must be anchored with ^
//
//   - regex must not appear on the generic-pattern blocklist
//
//   - contains is forbidden (only human/seeded may use contains)
//
// The point of a strict validator is that "no" means no — there is no
// fallback to a softer pattern type. Callers that previously relied on a
// regex-fallback-to-prefix path (analyzer v0.19.1) must now learn the
// exact-hash only and return.
func (s *Store) validatePattern(p *LearnedPattern) error {
	human := isHumanOrSeededSource(p.Source)

	switch p.Type {
	case PatternHash:
		if len(p.Value) != 64 { // SHA-256 hex
			return fmt.Errorf("hash must be 64 hex characters, got %d", len(p.Value))
		}

	case PatternPrefix:
		// Length floor: human/seeded 5, auto 20.
		minLen := 20
		if human {
			minLen = 5
		}
		if len(p.Value) < minLen {
			return fmt.Errorf("prefix too short (%d chars), minimum %d for source=%q", len(p.Value), minLen, p.Source)
		}

		// Auto-learned prefixes must literally prefix OriginalLine. This
		// catches LLM hallucinations where the proposed prefix doesn't
		// correspond to the line that was just classified.
		if !human && p.OriginalLine != "" {
			if !strings.HasPrefix(p.OriginalLine, p.Value) {
				return fmt.Errorf("auto-learned prefix does not literally prefix the original line")
			}
		}

		// Generic-token blocklist (auto only). The prefix is "stripped" —
		// whitespace and <...> placeholders removed — and compared case-
		// insensitively for equality against each blocked token. This catches
		// "ERROR <TS> <PID>" (stripped to "ERROR") but allows specific
		// extensions like "ERROR opening database connection at" (stripped
		// to "ERRORopeningdatabaseconnectionat" — no match).
		if !human {
			stripped := stripPrefixForBlocklist(p.Value)
			lowerStripped := strings.ToLower(stripped)
			for _, banned := range genericPrefixBlocklist {
				lowerBanned := strings.ToLower(strings.Join(strings.Fields(banned), ""))
				if lowerStripped == lowerBanned {
					return fmt.Errorf("auto-learned prefix is structurally just generic token %q", banned)
				}
			}
		}

	case PatternRegex:
		compiled, err := regexp.Compile(p.Value)
		if err != nil {
			return fmt.Errorf("regex does not compile: %w", err)
		}
		p.compiled = compiled

		// Must match the line it was generated from
		if p.OriginalLine != "" && !compiled.MatchString(p.OriginalLine) {
			return fmt.Errorf("regex does not match the original line it was generated from")
		}

		// Reject overly broad literal patterns (always)
		if p.Value == ".*" || p.Value == ".+" || p.Value == "^.*$" {
			return fmt.Errorf("regex is too broad: %s", p.Value)
		}

		// Auto-learned regex must be anchored to ^.
		// Human/seeded regex may be anywhere.
		if !human {
			if !strings.HasPrefix(p.Value, "^") {
				return fmt.Errorf("auto-learned regex must be anchored with ^ (got %q)", p.Value)
			}
			// Reject patterns that begin with "^.*" (effectively unanchored)
			// or that are too short to carry useful structure.
			if strings.HasPrefix(p.Value, "^.*") {
				return fmt.Errorf("auto-learned regex begins with ^.* — effectively unanchored")
			}
			if len(p.Value) < 10 {
				return fmt.Errorf("auto-learned regex too short (%d chars), minimum 10", len(p.Value))
			}
		}

	case PatternContains:
		// Contains is the most dangerous type — substring match anywhere in
		// the line. LLM auto-learning is FORBIDDEN from creating these.
		// Human/seeded sources may create contains patterns (used by the
		// curated malicious seeds in seeds.go).
		if !human {
			return fmt.Errorf("auto-learned contains patterns are forbidden (source=%q); use prefix or regex", p.Source)
		}
		if len(p.Value) < 10 {
			return fmt.Errorf("contains pattern too short (%d chars), minimum 10 for safety", len(p.Value))
		}

	default:
		return fmt.Errorf("unknown pattern type: %s", p.Type)
	}

	return nil
}

func (s *Store) getOrCreateScope(key string) *ScopeEntry {
	if scope, ok := s.scopes[key]; ok {
		return scope
	}
	scope := &ScopeEntry{}
	initBucket(&scope.Allow)
	initBucket(&scope.Malicious)
	initBucket(&scope.Alert)
	initBucket(&scope.Suppress)
	s.scopes[key] = scope
	return scope
}

// SeedMaliciousPattern adds a seeded (manually curated) malicious pattern.
// Seeded patterns use the "seeded" source tag to distinguish from learned.
// Skips if a pattern with the same value already exists (prevents duplication on restart).
func (s *Store) SeedMaliciousPattern(pattern, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if this exact pattern already exists in global malicious contains
	for _, existing := range s.global.Malicious.Contains {
		if existing.Value == pattern {
			return // Already seeded, skip
		}
	}

	p := LearnedPattern{
		Type:      PatternContains,
		Value:     pattern,
		Source:    "seeded",
		Reason:    reason,
		CreatedAt: time.Now(),
	}

	// Seeded malicious patterns go into the global scope
	// so they apply to ALL sources.
	// For short seeded patterns, bypass the contains minimum length check
	// since these are manually curated and intentional.
	s.global.Malicious.Contains = append(s.global.Malicious.Contains, &p)
	s.stats.PatternCount.Add(1)
}

// GetStats returns a snapshot of current pattern store statistics.
func (s *Store) GetStats() StatsSnapshot {
	return StatsSnapshot{
		TotalChecked:  s.stats.TotalChecked.Load(),
		HashHits:      s.stats.HashHits.Load(),
		PrefixHits:    s.stats.PrefixHits.Load(),
		RegexHits:     s.stats.RegexHits.Load(),
		ContainsHits:  s.stats.ContainsHits.Load(),
		MaliciousHits: s.stats.MaliciousHits.Load(),
		AlertHits:     s.stats.AlertHits.Load(),
		SuppressHits:  s.stats.SuppressHits.Load(),
		Misses:        s.stats.Misses.Load(),
		PatternCount:  s.stats.PatternCount.Load(),

		AutoLearnRejected: s.stats.AutoLearnRejected.Load(),
		AutoLearnCapped:   s.stats.AutoLearnCapped.Load(),
	}
}

// ScopeCount returns the number of source scopes in the store.
func (s *Store) ScopeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.scopes)
}

// =============================================================================
// Dashboard API Read Methods
// =============================================================================

// ScopeSummary is a compact view of one scope for the dashboard.
type ScopeSummary struct {
	ScopeKey       string `json:"scope_key"`
	AllowCount     int    `json:"allow_count"`
	MaliciousCount int    `json:"malicious_count"`
	AlertCount     int    `json:"alert_count"`
	SuppressCount  int    `json:"suppress_count"`
}

// ListScopes returns a summary of every scope in the store.
func (s *Store) ListScopes() []ScopeSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summaries := make([]ScopeSummary, 0, len(s.scopes)+1)

	// Global scope
	summaries = append(summaries, ScopeSummary{
		ScopeKey:       "__global__",
		AllowCount:     bucketSize(&s.global.Allow),
		MaliciousCount: bucketSize(&s.global.Malicious),
		AlertCount:     bucketSize(&s.global.Alert),
		SuppressCount:  bucketSize(&s.global.Suppress),
	})

	for key, scope := range s.scopes {
		summaries = append(summaries, ScopeSummary{
			ScopeKey:       key,
			AllowCount:     bucketSize(&scope.Allow),
			MaliciousCount: bucketSize(&scope.Malicious),
			AlertCount:     bucketSize(&scope.Alert),
			SuppressCount:  bucketSize(&scope.Suppress),
		})
	}
	return summaries
}

// ListPatterns returns all patterns in a specific scope and verdict bucket.
// Returns nil if the scope doesn't exist.
func (s *Store) ListPatterns(scopeKey string, verdict Verdict) []LearnedPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var scope *ScopeEntry
	if scopeKey == "__global__" {
		scope = s.global
	} else {
		scope = s.scopes[scopeKey]
	}
	if scope == nil {
		return nil
	}

	bucket := s.getBucketReadOnly(scope, verdict)
	if bucket == nil {
		return nil
	}

	var patterns []LearnedPattern
	for _, p := range bucket.Hashes {
		patterns = append(patterns, *p)
	}
	for _, p := range bucket.Prefixes {
		patterns = append(patterns, *p)
	}
	for _, p := range bucket.Regexes {
		patterns = append(patterns, *p)
	}
	for _, p := range bucket.Contains {
		patterns = append(patterns, *p)
	}
	return patterns
}

// DeletePattern removes a pattern by its value from a scope/verdict bucket.
// Returns true if found and deleted.
func (s *Store) DeletePattern(scopeKey string, verdict Verdict, patternValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	var scope *ScopeEntry
	if scopeKey == "__global__" {
		scope = s.global
	} else {
		scope = s.scopes[scopeKey]
	}
	if scope == nil {
		return false
	}

	bucket := s.getBucket(scope, verdict)
	if bucket == nil {
		return false
	}

	// Try hash first
	if _, ok := bucket.Hashes[patternValue]; ok {
		delete(bucket.Hashes, patternValue)
		return true
	}

	// Try prefix/regex/contains lists
	for _, list := range []*[]*LearnedPattern{&bucket.Prefixes, &bucket.Regexes, &bucket.Contains} {
		for i, p := range *list {
			if p.Value == patternValue {
				*list = append((*list)[:i], (*list)[i+1:]...)
				return true
			}
		}
	}
	return false
}

// RevokePattern soft-disables a pattern by setting RevokedAt and RevokedBy.
// The pattern remains in the store for audit trail but is skipped by Match().
// This is the append-only correction model: the original decision is immutable
// history, the revocation is a new action layered on top.
//
// Returns true if the pattern was found and revoked.
// Use DeletePattern() for hard removal (backward-compatible, pre-revoke flow).
func (s *Store) RevokePattern(scopeKey string, verdict Verdict, patternValue, revokedBy string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	var scope *ScopeEntry
	if scopeKey == "__global__" {
		scope = s.global
	} else {
		scope = s.scopes[scopeKey]
	}
	if scope == nil {
		return false
	}

	bucket := s.getBucket(scope, verdict)
	if bucket == nil {
		return false
	}

	now := time.Now()

	// Try hash first
	if p, ok := bucket.Hashes[patternValue]; ok {
		p.RevokedAt = &now
		p.RevokedBy = revokedBy
		return true
	}

	// Try prefix/regex/contains lists
	for _, list := range []*[]*LearnedPattern{&bucket.Prefixes, &bucket.Regexes, &bucket.Contains} {
		for _, p := range *list {
			if p.Value == patternValue {
				p.RevokedAt = &now
				p.RevokedBy = revokedBy
				return true
			}
		}
	}
	return false
}

// MarkHumanValidated finds a hash pattern by its value across all buckets
// in a scope and marks it as human-validated. This protects the pattern from
// future pruning and signals to other humans that it was explicitly confirmed.
func (s *Store) MarkHumanValidated(scopeKey string, hashValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	var scope *ScopeEntry
	if scopeKey == "__global__" {
		scope = s.global
	} else {
		scope = s.scopes[scopeKey]
	}
	if scope == nil {
		return false
	}

	// Search all four buckets for this hash
	for _, bucket := range []*PatternBucket{&scope.Allow, &scope.Malicious, &scope.Alert, &scope.Suppress} {
		if p, ok := bucket.Hashes[hashValue]; ok {
			p.Source = "human_validated"
			return true
		}
	}
	return false
}

// MarkPatternValidated finds a pattern by its value in a specific bucket
// and marks it as human-validated. Works for any pattern type (hash, prefix,
// regex, contains), not just hashes.
func (s *Store) MarkPatternValidated(scopeKey string, verdict Verdict, patternValue string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	var scope *ScopeEntry
	if scopeKey == "__global__" {
		scope = s.global
	} else {
		scope = s.scopes[scopeKey]
	}
	if scope == nil {
		return false
	}

	bucket := s.getBucket(scope, verdict)
	if bucket == nil {
		return false
	}

	// Check hash first
	if p, ok := bucket.Hashes[patternValue]; ok {
		p.Source = "human_validated"
		return true
	}

	// Check prefix/regex/contains
	for _, list := range []*[]*LearnedPattern{&bucket.Prefixes, &bucket.Regexes, &bucket.Contains} {
		for _, p := range *list {
			if p.Value == patternValue {
				p.Source = "human_validated"
				return true
			}
		}
	}
	return false
}

// getBucketReadOnly returns the bucket for a verdict (read-only, no creation).
func (s *Store) getBucketReadOnly(scope *ScopeEntry, v Verdict) *PatternBucket {
	switch v {
	case VerdictAllow:
		return &scope.Allow
	case VerdictMalicious:
		return &scope.Malicious
	case VerdictAlert:
		return &scope.Alert
	case VerdictSuppress:
		return &scope.Suppress
	default:
		return nil
	}
}

func bucketSize(b *PatternBucket) int {
	return len(b.Hashes) + len(b.Prefixes) + len(b.Regexes) + len(b.Contains)
}

// --- Persistence ---

type persistedStore struct {
	Scopes map[string]*ScopeEntry `json:"scopes"`
	Global *ScopeEntry            `json:"global"`
}

// Persist saves the entire pattern store to disk.
func (s *Store) Persist() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := persistedStore{
		Scopes: s.scopes,
		Global: s.global,
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling pattern store: %w", err)
	}

	path := s.dataDir + "/patternstore.json"

	// Atomic write to avoid corruption from crashes mid-write. the design review raised
	// this and confirmed in review: a previous os.WriteFile could leave a
	// partially-written JSON file that fails to parse on next boot, taking
	// the entire pattern store down with it.
	//
	// 0600 because patterns include normalized payload prefixes, hashes, and
	// learned attack signatures — sensitive security state, not world-readable.
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, jsonBytes, 0600); err != nil {
		return fmt.Errorf("writing pattern store tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Best-effort cleanup of the tmp file if rename fails.
		_ = os.Remove(tmpPath)
		return fmt.Errorf("renaming pattern store: %w", err)
	}

	return nil
}

func (s *Store) load() error {
	path := s.dataDir + "/patternstore.json"
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Fresh start, no patterns yet
		}
		return err
	}

	var persisted persistedStore
	if err := json.Unmarshal(data, &persisted); err != nil {
		return fmt.Errorf("parsing pattern store: %w", err)
	}

	if persisted.Global != nil {
		s.global = persisted.Global
		initBucket(&s.global.Allow)
		initBucket(&s.global.Malicious)
		initBucket(&s.global.Alert)
		initBucket(&s.global.Suppress)
		// Deduplicate contains patterns (seeds were duplicated on every restart
		// in earlier versions). Keep only the first occurrence of each value.
		s.global.Malicious.Contains = deduplicateContains(s.global.Malicious.Contains)
	}

	for key, scope := range persisted.Scopes {
		initBucket(&scope.Allow)
		initBucket(&scope.Malicious)
		initBucket(&scope.Alert)
		initBucket(&scope.Suppress)
		s.scopes[key] = scope
	}

	// Recompile all regex patterns
	s.recompileAll()

	return nil
}

// deduplicateContains removes duplicate contains patterns, keeping the first
// occurrence of each unique Value. Fixes a bug where seeded patterns were
// appended on every restart without checking for existing entries.
func deduplicateContains(patterns []*LearnedPattern) []*LearnedPattern {
	seen := make(map[string]bool)
	result := make([]*LearnedPattern, 0, len(patterns))
	for _, p := range patterns {
		if !seen[p.Value] {
			seen[p.Value] = true
			result = append(result, p)
		}
	}
	if len(result) < len(patterns) {
		log.Printf("[patternstore] Deduplicated global malicious contains: %d → %d patterns", len(patterns), len(result))
	}
	return result
}

// recompileAll rebuilds the compiled regex objects after loading from disk.
func (s *Store) recompileAll() {
	recompileBucket := func(b *PatternBucket) {
		valid := make([]*LearnedPattern, 0, len(b.Regexes))
		for _, p := range b.Regexes {
			compiled, err := regexp.Compile(p.Value)
			if err != nil {
				// Skip patterns that no longer compile (shouldn't happen,
				// but defensive)
				continue
			}
			p.compiled = compiled
			valid = append(valid, p)
		}
		b.Regexes = valid
	}

	for _, scope := range s.scopes {
		recompileBucket(&scope.Allow)
		recompileBucket(&scope.Malicious)
		recompileBucket(&scope.Alert)
		recompileBucket(&scope.Suppress)
	}
	recompileBucket(&s.global.Allow)
	recompileBucket(&s.global.Malicious)
	recompileBucket(&s.global.Alert)
	recompileBucket(&s.global.Suppress)
}
