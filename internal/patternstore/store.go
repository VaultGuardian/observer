package patternstore

import (
	"encoding/json"
	"fmt"
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
	VerdictAllow    Verdict = "allow"    // Known-good, skip silently
	VerdictDeny     Verdict = "deny"     // Known-bad, alert with high severity
	VerdictAlert    Verdict = "alert"    // Suspicious, alert with lower severity, exact-hash memoized
	VerdictSuppress Verdict = "suppress" // Known-noise, don't alert, don't send to LLM
	VerdictUnknown  Verdict = "unknown"  // No match — forward to LLM
)

// PatternType controls which matching tier a learned pattern uses.
type PatternType string

const (
	PatternHash     PatternType = "hash"     // Exact normalized hash match
	PatternPrefix   PatternType = "prefix"   // strings.HasPrefix
	PatternRegex    PatternType = "regex"    // Pre-compiled regexp
	PatternContains PatternType = "contains" // strings.Contains (guarded, rare)
)

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

	// compiled is the pre-compiled regex (only for PatternRegex).
	// Not serialized — rebuilt on load.
	compiled *regexp.Regexp
}

// PatternBucket holds patterns for one verdict type (allow, deny, or suppress)
// scoped to a single source key.
type PatternBucket struct {
	Hashes   map[string]*LearnedPattern `json:"hashes,omitempty"`   // hash → pattern
	Prefixes []*LearnedPattern          `json:"prefixes,omitempty"` // checked in order
	Regexes  []*LearnedPattern          `json:"regexes,omitempty"`  // checked in order
	Contains []*LearnedPattern          `json:"contains,omitempty"` // checked last, guarded
}

// ScopeEntry holds all four buckets for a single source scope key.
type ScopeEntry struct {
	Allow    PatternBucket `json:"allow"`
	Deny     PatternBucket `json:"deny"`
	Alert    PatternBucket `json:"alert"`
	Suppress PatternBucket `json:"suppress"`
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
	TotalChecked atomic.Int64
	HashHits     atomic.Int64
	PrefixHits   atomic.Int64
	RegexHits    atomic.Int64
	ContainsHits atomic.Int64
	DenyHits     atomic.Int64
	AlertHits    atomic.Int64
	SuppressHits atomic.Int64
	Misses       atomic.Int64
	PatternCount atomic.Int64
}

// StatsSnapshot is a plain copy for logging/serialization.
type StatsSnapshot struct {
	TotalChecked int64 `json:"total_checked"`
	HashHits     int64 `json:"hash_hits"`
	PrefixHits   int64 `json:"prefix_hits"`
	RegexHits    int64 `json:"regex_hits"`
	ContainsHits int64 `json:"contains_hits"`
	DenyHits     int64 `json:"deny_hits"`
	AlertHits    int64 `json:"alert_hits"`
	SuppressHits int64 `json:"suppress_hits"`
	Misses       int64 `json:"misses"`
	PatternCount int64 `json:"pattern_count"`
}

// NewStore creates a pattern store with the given data directory for persistence.
func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		scopes:  make(map[string]*ScopeEntry),
		global:  &ScopeEntry{},
		dataDir: dataDir,
	}
	initBucket(&s.global.Allow)
	initBucket(&s.global.Deny)
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
// Order: deny first (safety), then allow, then suppress.
// Within each verdict: source-scoped first, then global.
// Within each scope: hash → prefix → regex → contains.
func (s *Store) Match(scopeKey, hash, normalizedLine string) *MatchResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.stats.TotalChecked.Add(1)

	// --- DENY first (safety: known-bad takes priority) ---
	if r := s.matchBucket(scopeKey, hash, normalizedLine, VerdictDeny); r != nil {
		s.stats.DenyHits.Add(1)
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
	case VerdictDeny:
		return &scope.Deny
	case VerdictAlert:
		return &scope.Alert
	case VerdictSuppress:
		return &scope.Suppress
	default:
		return &scope.Allow
	}
}

// matchTiers runs through the matching tiers in priority order.
func matchTiers(b *PatternBucket, hash, normalizedLine string, v Verdict) *MatchResult {
	// Tier 1: Exact hash (O(1), nanoseconds)
	if p, ok := b.Hashes[hash]; ok {
		return &MatchResult{Verdict: v, Pattern: p, Tier: PatternHash}
	}

	// Tier 2: Prefix (strings.HasPrefix, sub-nanosecond each)
	for _, p := range b.Prefixes {
		if strings.HasPrefix(normalizedLine, p.Value) {
			return &MatchResult{Verdict: v, Pattern: p, Tier: PatternPrefix}
		}
	}

	// Tier 3: Regex (pre-compiled, microseconds each)
	for _, p := range b.Regexes {
		if p.compiled != nil && p.compiled.MatchString(normalizedLine) {
			return &MatchResult{Verdict: v, Pattern: p, Tier: PatternRegex}
		}
	}

	// Tier 4: Contains (guarded, rare — checked last)
	for _, p := range b.Contains {
		if strings.Contains(normalizedLine, p.Value) {
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
func (s *Store) Learn(scopeKey string, verdict Verdict, pattern LearnedPattern) error {
	// Validate
	if err := s.validatePattern(&pattern); err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	scope := s.getOrCreateScope(scopeKey)
	bucket := s.getBucket(scope, verdict)

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

// LearnHash is a convenience method for adding an exact hash match.
func (s *Store) LearnHash(scopeKey string, verdict Verdict, hash, reason, originalLine string) {
	_ = s.Learn(scopeKey, verdict, LearnedPattern{
		Type:         PatternHash,
		Value:        hash,
		Source:       "auto",
		Reason:       reason,
		OriginalLine: originalLine,
		CreatedAt:    time.Now(),
	})
}

func (s *Store) validatePattern(p *LearnedPattern) error {
	switch p.Type {
	case PatternHash:
		if len(p.Value) != 64 { // SHA-256 hex
			return fmt.Errorf("hash must be 64 hex characters, got %d", len(p.Value))
		}

	case PatternPrefix:
		if len(p.Value) < 5 {
			return fmt.Errorf("prefix too short (%d chars), minimum 5", len(p.Value))
		}

	case PatternRegex:
		compiled, err := regexp.Compile(p.Value)
		if err != nil {
			return fmt.Errorf("regex does not compile: %w", err)
		}
		p.compiled = compiled

		// If we have the original line, verify the regex matches it
		if p.OriginalLine != "" && !compiled.MatchString(p.OriginalLine) {
			return fmt.Errorf("regex does not match the original line it was generated from")
		}

		// Reject overly broad patterns
		if p.Value == ".*" || p.Value == ".+" || p.Value == "^.*$" {
			return fmt.Errorf("regex is too broad: %s", p.Value)
		}

	case PatternContains:
		// Contains is the most dangerous — require minimum length
		if len(p.Value) < 10 {
			return fmt.Errorf("contains pattern too short (%d chars), minimum 10 for safety", len(p.Value))
		}
	}

	return nil
}

func (s *Store) getOrCreateScope(key string) *ScopeEntry {
	if scope, ok := s.scopes[key]; ok {
		return scope
	}
	scope := &ScopeEntry{}
	initBucket(&scope.Allow)
	initBucket(&scope.Deny)
	initBucket(&scope.Alert)
	initBucket(&scope.Suppress)
	s.scopes[key] = scope
	return scope
}

// SeedDenyPattern adds a seeded (manually curated) deny pattern.
// Seeded patterns use the "seeded" source tag to distinguish from learned.
func (s *Store) SeedDenyPattern(pattern, reason string) {
	p := LearnedPattern{
		Type:      PatternContains,
		Value:     pattern,
		Source:    "seeded",
		Reason:    reason,
		CreatedAt: time.Now(),
	}
	// Seeded deny patterns go into the global scope
	// so they apply to ALL sources.
	s.mu.Lock()
	defer s.mu.Unlock()

	// For short seeded patterns, bypass the contains minimum length check
	// since these are manually curated and intentional.
	s.global.Deny.Contains = append(s.global.Deny.Contains, &p)
	s.stats.PatternCount.Add(1)
}

// GetStats returns a snapshot of current pattern store statistics.
func (s *Store) GetStats() StatsSnapshot {
	return StatsSnapshot{
		TotalChecked: s.stats.TotalChecked.Load(),
		HashHits:     s.stats.HashHits.Load(),
		PrefixHits:   s.stats.PrefixHits.Load(),
		RegexHits:    s.stats.RegexHits.Load(),
		ContainsHits: s.stats.ContainsHits.Load(),
		DenyHits:     s.stats.DenyHits.Load(),
		AlertHits:    s.stats.AlertHits.Load(),
		SuppressHits: s.stats.SuppressHits.Load(),
		Misses:       s.stats.Misses.Load(),
		PatternCount: s.stats.PatternCount.Load(),
	}
}

// ScopeCount returns the number of source scopes in the store.
func (s *Store) ScopeCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.scopes)
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
	if err := os.WriteFile(path, jsonBytes, 0644); err != nil {
		return fmt.Errorf("writing pattern store: %w", err)
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
		initBucket(&s.global.Deny)
		initBucket(&s.global.Alert)
		initBucket(&s.global.Suppress)
	}

	for key, scope := range persisted.Scopes {
		initBucket(&scope.Allow)
		initBucket(&scope.Deny)
		initBucket(&scope.Alert)
		initBucket(&scope.Suppress)
		s.scopes[key] = scope
	}

	// Recompile all regex patterns
	s.recompileAll()

	return nil
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
		recompileBucket(&scope.Deny)
		recompileBucket(&scope.Alert)
		recompileBucket(&scope.Suppress)
	}
	recompileBucket(&s.global.Allow)
	recompileBucket(&s.global.Deny)
	recompileBucket(&s.global.Alert)
	recompileBucket(&s.global.Suppress)
}
