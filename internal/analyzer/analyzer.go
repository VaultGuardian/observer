package analyzer

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

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

	// Pattern match fields — populated on cache hits so the dashboard
	// can offer "Wrong — delete pattern" for cached events.
	PatternScope  string `json:"pattern_scope,omitempty"`
	PatternBucket string `json:"pattern_bucket,omitempty"` // allow, malicious, alert, suppress
	PatternValue  string `json:"pattern_value,omitempty"`

	// OriginEventID is the event that originally taught this pattern.
	// Populated on cache hits from LearnedPattern.CreatedFromEventID.
	// Powers cache lineage: "Originally learned from evt_abc123".
	OriginEventID string `json:"origin_event_id,omitempty"`

	// LLM-specific fields (only set when the LLM was consulted)
	LLMClassification string       `json:"llm_classification,omitempty"`
	LLMConfidence     float64      `json:"llm_confidence,omitempty"`
	LLMPatternLearned bool         `json:"llm_pattern_learned,omitempty"`
	LLMVerdict        *llm.Verdict `json:"-"` // full verdict with call metadata for audit trail

	// LLMClampedToAlert: the T1 LLM said action=malicious for an HTTP event,
	// and the applied verdict was capped to alert — outcome claims require
	// response evidence (T2). The LLMVerdict above keeps the model's original
	// action; the divergence is intentional and queryable (the audit row's
	// Action stays "malicious", FinalVerdict records "alert"). Set on leader
	// AND followers so routing records the truth for every coalesced event.
	LLMClampedToAlert bool `json:"llm_clamped_to_alert,omitempty"`
}

// LLMScheduler controls concurrent LLM access across all tiers.
// Provided by the caller so T1, T2, and catch-all share one pool.
type LLMScheduler interface {
	TryAcquire() (release func(), ok bool)
	AcquireBlocking(ctx context.Context) (release func(), ok bool)
}

// Analyzer is the core analysis pipeline.
// It orchestrates: normalize → pattern match → LLM classify → learn.
type Analyzer struct {
	normalizers *normalizer.Registry
	patterns    *patternstore.Store
	llmClient   *llm.Client
	hints       *normalizer.HintCollector

	// llmScheduler limits concurrent LLM calls globally.
	// Shared with T2 evidence and catch-all verification paths.
	llmScheduler LLMScheduler

	// prePinEvidence is called before an event enters the LLM path
	// (pattern store miss). Promotes any matching REC ring buffer entry
	// to VIP so evidence survives the LLM classification delay.
	// Optional — nil means no pre-pinning (REC disabled or not wired).
	prePinEvidence func(evt *event.Event)

	// classifyGroup coalesces concurrent Tier-1 classifications for the same
	// scope + normalized-line + disclosure-bit into a single in-flight LLM
	// call. A burst of identical events that all miss the pattern cache before
	// the first verdict is learned would otherwise each acquire a slot, call
	// the LLM, and re-learn the same pattern. One shared group covers BOTH
	// Analyze and AnalyzeRetry — see classifyDeduped. Zero value is ready to use.
	classifyGroup singleflight.Group

	// stats uses atomic counters — safe for concurrent goroutines.
	stats Stats
}

// classifyFlightResult is the shared outcome of one coalesced classification.
// It is deliberately NOT an AnalysisResult: AnalysisResult carries Event: evt,
// and sharing it would attach the leader's event/evidence to every follower.
// Each caller builds its own per-event AnalysisResult from this via buildResult.
type classifyFlightResult struct {
	Verdict        *llm.Verdict              // shared LLM verdict; nil for non-llm outcomes
	PatternLearned bool                      // whether the leader learned a pattern
	LeaderEventID  string                    // the leader's evt.ID — used to tell leader from followers
	Source         string                    // "llm" | "pattern" | "backpressure" | "retry_cancelled" | "error"
	Reason         string                    // populated for "error"
	Match          *patternstore.MatchResult // populated for "pattern" (in-flight re-check hit)
	Err            error                     // populated for "error" (currently informational)
	ClampedToAlert bool                      // T1 LLM said malicious on an HTTP event; effective action capped to alert
}

// SetPrePinFunc registers the REC evidence pre-pin callback.
// Called from main.go after the collector is created. The callback
// parses HTTP identity from the event and calls collector.PrePin().
func (a *Analyzer) SetPrePinFunc(fn func(evt *event.Event)) {
	a.prePinEvidence = fn
}

// Stats tracks pipeline performance metrics.
// All fields use atomic operations for thread safety.
type Stats struct {
	TotalProcessed    atomic.Int64 `json:"total_processed"`
	PatternHits       atomic.Int64 `json:"pattern_hits"`
	NoiseSuppressed   atomic.Int64 `json:"noise_suppressed"` // deterministic stack trace / framework noise
	LLMCalls          atomic.Int64 `json:"llm_calls"`
	LLMErrors         atomic.Int64 `json:"llm_errors"`
	LLMDropped        atomic.Int64 `json:"llm_dropped"` // deferred to retry queue (or dropped if queue full)
	PatternsLearned   atomic.Int64 `json:"patterns_learned"`
	Retried           atomic.Int64 `json:"retried"`             // events classified via retry queue
	RetriedPatternHit atomic.Int64 `json:"retried_pattern_hit"` // retries resolved by pattern store (no LLM needed)

	// v0.47 (review of F5): disclosure-protection events.
	// Increments when:
	//   - cached suppress/allow verdict rejected because line contains disclosure (Analyze, AnalyzeRetry)
	//   - LLM-proposed suppress/allow learning refused because line contains disclosure (learnFromVerdict)
	// A non-zero counter indicates either historically poisoned cache entries
	// being caught, or the LLM hedging on disclosure-bearing lines. Operators
	// should review the [analyzer] DISCLOSURE_OVERRIDE / DISCLOSURE_REFUSE_LEARN
	// log lines to identify offending patterns or LLM behavior to correct.
	DisclosureOverrides atomic.Int64 `json:"disclosure_overrides"`

	// T1 LLM "malicious" verdicts on HTTP events capped to "alert" —
	// outcome-claiming verdicts require response evidence (T2 escalation is
	// the legitimate path to malicious). Counted once per coalesced flight,
	// like LLMCalls. See the [clamp] log lines for the affected events.
	T1MaliciousClamped atomic.Int64 `json:"t1_malicious_clamped"`
}

// StatsSnapshot is a plain copy for logging/serialization.
type StatsSnapshot struct {
	TotalProcessed      int64 `json:"total_processed"`
	PatternHits         int64 `json:"pattern_hits"`
	NoiseSuppressed     int64 `json:"noise_suppressed"`
	LLMCalls            int64 `json:"llm_calls"`
	LLMErrors           int64 `json:"llm_errors"`
	LLMDropped          int64 `json:"llm_dropped"`
	PatternsLearned     int64 `json:"patterns_learned"`
	Retried             int64 `json:"retried"`
	RetriedPatternHit   int64 `json:"retried_pattern_hit"`
	DisclosureOverrides int64 `json:"disclosure_overrides"`
	T1MaliciousClamped  int64 `json:"t1_malicious_clamped"`
}

// New creates an Analyzer with the given components.
// The scheduler controls global LLM concurrency across all tiers.
func New(normalizers *normalizer.Registry, patterns *patternstore.Store, llmClient *llm.Client, scheduler LLMScheduler) *Analyzer {
	return &Analyzer{
		normalizers:  normalizers,
		patterns:     patterns,
		llmClient:    llmClient,
		hints:        normalizer.NewHintCollector(),
		llmScheduler: scheduler,
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

	// --- Step 1.4: High-risk disclosure guard (v0.47, review of F5) ---
	//
	// If the line contains a confirmed-exfiltration string (etc/passwd
	// content, private key headers, AWS secret env var, uid=0 output), it
	// MUST bypass every deterministic suppressor below. The semantic rule
	// is global: high-risk disclosure escapes deterministic suppression,
	// regardless of line shape.
	//
	// Without this guard, a line like:
	//   `ERROR dumped root:x:0:0:root "GET /missing HTTP/1.1" 404`
	// would survive isOperationalNoise (no stack-trace shape) but get
	// silently suppressed by isFailedProbe (parses the embedded "GET ...
	// 404" and decides "failed probe, no attack payload in /missing").
	// The disclosure would never reach the malicious-seed check.
	//
	// We check BOTH raw and normalized — the normalizer may scrub or
	// preserve the disclosure depending on source family, so checking
	// both forms catches it either way.
	hasDisclosure := containsHighRiskDisclosure(evt.Line) ||
		containsHighRiskDisclosure(evt.NormalizedLine)

	// --- Step 1.5: Deterministic noise suppression ---
	// Cheap regex-free detection of obvious application noise.
	// These patterns are structural (not content-dependent) and should
	// NEVER hit the LLM or pattern store. Zero cost, zero ambiguity.
	//
	// DESIGN DECISION (v0.15, 2026-03-24): Deterministic suppression
	// for stack traces.
	// The LLM already proved it can cache the WRONG answer for these
	// (Remix stack trace classified as "alert" → 25 emails overnight).
	if !hasDisclosure && isOperationalNoise(evt.Line) {
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
	// POLICY (v0.47 override): suppression is pure status-based — attack
	// indicators in the path do NOT escape this gate (a failed probe is a
	// failed probe regardless of what was probed; see isFailedProbe). Only
	// high-risk disclosures bypass it, via the guard above — those are
	// actual data leakage in the line, not scanner intent.
	if !hasDisclosure {
		if reason, ok := isFailedProbe(evt.NormalizedLine); ok {
			a.stats.NoiseSuppressed.Add(1)
			return AnalysisResult{
				Event:   evt,
				Verdict: patternstore.VerdictSuppress,
				Reason:  reason,
				Source:  "noise_filter",
			}
		}
	}

	// --- Step 2: Pattern store check ---
	//
	// v0.47: if hasDisclosure is true, a
	// historically-cached SUPPRESS or ALLOW verdict is itself a form of
	// deterministic suppression and must not be honored. Pre-v0.47 caches
	// could contain low-confidence suppress hashes (no confidence gate
	// existed before F2) on lines that happen to contain disclosure
	// strings. Even post-v0.47 caches could land on a poisoned line at
	// 0.70+ confidence by accident.
	//
	// MALICIOUS and ALERT cache hits are escalations, not suppression —
	// they fire the alert path and are correct to honor regardless of
	// disclosure presence. Only SUPPRESS and ALLOW are overridden.
	//
	// Override behavior: log it (so operators can see the cache being
	// rejected and clean up the offending pattern), increment a dedicated
	// stat counter so the override is observable, and proceed to LLM
	// classification as if the cache had returned nil. The LLM will then
	// see the disclosure content directly and the global malicious seeds
	// in seeds.go will catch it via pattern store on the way through.
	result := a.patterns.Match(evt.ScopeKey(), evt.Hash, evt.NormalizedLine)
	if result != nil {
		if hasDisclosure && (result.Verdict == patternstore.VerdictSuppress || result.Verdict == patternstore.VerdictAllow) {
			log.Printf("[analyzer] DISCLOSURE_OVERRIDE: cached %s verdict rejected for scope=%s tier=%s pattern=%q — high-risk disclosure present, forcing LLM re-classification",
				result.Verdict, evt.ScopeKey(), result.Tier, truncateForLog(result.Pattern.Value, 60))
			a.stats.DisclosureOverrides.Add(1)
			// Fall through to LLM classification (do not increment PatternHits).
		} else {
			a.stats.PatternHits.Add(1)
			return AnalysisResult{
				Event:         evt,
				Verdict:       result.Verdict,
				Tier:          result.Tier,
				Reason:        result.Pattern.Reason,
				Source:        result.Pattern.Source,
				PatternScope:  evt.ScopeKey(),
				PatternBucket: string(result.Verdict),
				PatternValue:  result.Pattern.Value,
				OriginEventID: result.Pattern.CreatedFromEventID,
			}
		}
	}

	// --- Step 3: Unknown → consult LLM (with backpressure) ---

	// Pre-pin REC evidence before the LLM path. At this point the HTTP
	// response is almost certainly still in the 30-second ring buffer.
	// Whether TryAcquire succeeds (immediate LLM call, ~5s) or fails
	// (deferred to retry queue, 60-90+ seconds), the evidence is promoted
	// to VIP (120s TTL) and protected from eviction.
	if a.prePinEvidence != nil {
		a.prePinEvidence(evt)
	}

	// Coalesce concurrent identical classifications. A burst of the same line
	// attaches to one in-flight LLM call (non-blocking acquire); only the leader
	// touches the scheduler and the pattern store. Each event still resolves to
	// its own AnalysisResult.
	return a.classifyDeduped(ctx, evt, hasDisclosure, false)
}

// AnalyzeRetry is called by retry workers for events deferred due to LLM backpressure.
// Re-checks the pattern store first (may have learned the pattern since deferral),
// then does a BLOCKING LLM acquire if still unknown.
//
// v0.47: same disclosure-override semantics
// as Analyze() — a cached SUPPRESS or ALLOW verdict on a disclosure-bearing
// line must not be honored. Falls through to blocking LLM classification.
func (a *Analyzer) AnalyzeRetry(ctx context.Context, evt *event.Event) AnalysisResult {
	a.stats.Retried.Add(1)

	hasDisclosure := containsHighRiskDisclosure(evt.Line) ||
		containsHighRiskDisclosure(evt.NormalizedLine)

	// Pattern store may have learned this since we deferred
	result := a.patterns.Match(evt.ScopeKey(), evt.Hash, evt.NormalizedLine)
	if result != nil {
		if hasDisclosure && (result.Verdict == patternstore.VerdictSuppress || result.Verdict == patternstore.VerdictAllow) {
			log.Printf("[analyzer] DISCLOSURE_OVERRIDE: cached %s verdict rejected on retry for scope=%s tier=%s pattern=%q",
				result.Verdict, evt.ScopeKey(), result.Tier, truncateForLog(result.Pattern.Value, 60))
			a.stats.DisclosureOverrides.Add(1)
			// Fall through to blocking LLM classification.
		} else {
			a.stats.PatternHits.Add(1)
			a.stats.RetriedPatternHit.Add(1)
			return AnalysisResult{
				Event:         evt,
				Verdict:       result.Verdict,
				Tier:          result.Tier,
				Reason:        result.Pattern.Reason,
				Source:        result.Pattern.Source + "_retry",
				PatternScope:  evt.ScopeKey(),
				PatternBucket: string(result.Verdict),
				PatternValue:  result.Pattern.Value,
				OriginEventID: result.Pattern.CreatedFromEventID,
			}
		}
	}

	// Coalesce concurrent retries of the same line into one blocking
	// classification. The in-flight re-check inside the flight closes the race
	// where a peer learned the pattern while we waited for a slot.
	return a.classifyDeduped(ctx, evt, hasDisclosure, true)
}

// classifyDeduped coalesces concurrent classifications of the same event shape
// into a single in-flight LLM call via singleflight. The key is scope +
// normalized-line hash + disclosure bit:
//
//   - evt.Hash is the SHA-256 of the normalized line, so scope + hash is exact
//     same-line dedup.
//   - The disclosure bit is mandatory: a normalizer may scrub a raw disclosure
//     out of NormalizedLine, so a disclosure-bearing event can share a hash with
//     a non-disclosure one. Without the bit a disclosure event could inherit a
//     non-disclosure leader's suppress/allow verdict, breaking the
//     DISCLOSURE_OVERRIDE path. hasDisclosure is deterministic per (raw,
//     normalized) line, so truly identical lines share the bit and still coalesce.
//
// One leader runs runClassifyFlight; every follower attaches to its result. The
// leader is identified by LeaderEventID == evt.ID (NOT singleflight's shared
// bool — the leader can also observe shared==true). Each caller then builds its
// own per-event AnalysisResult.
func (a *Analyzer) classifyDeduped(ctx context.Context, evt *event.Event, hasDisclosure, retry bool) AnalysisResult {
	key := evt.ScopeKey() + "\x00" + evt.Hash + "\x00disc=" + strconv.FormatBool(hasDisclosure)

	res, _, _ := a.classifyGroup.Do(key, func() (interface{}, error) {
		return a.runClassifyFlight(ctx, evt, hasDisclosure, retry), nil
	})

	fr := res.(*classifyFlightResult)
	return a.buildResult(evt, fr, retry, fr.LeaderEventID == evt.ID)
}

// runClassifyFlight is the leader-only body of a coalesced classification: it
// holds a single scheduler slot, re-checks the pattern store, calls the LLM
// once, and learns once. It returns a small shared result that every follower
// reads. It must only be invoked inside classifyGroup.Do.
func (a *Analyzer) runClassifyFlight(ctx context.Context, evt *event.Event, hasDisclosure, retry bool) *classifyFlightResult {
	fr := &classifyFlightResult{LeaderEventID: evt.ID}

	// Acquire one slot for the whole coalesced group. Because a single shared
	// singleflight group covers BOTH Analyze (TryAcquire) and AnalyzeRetry
	// (AcquireBlocking), the leader's acquire mode applies to every coalesced
	// follower: under scheduler saturation a fresh event may block for one
	// LLM-call duration instead of deferring, and a retry event may defer again
	// instead of blocking. This is an accepted, bounded trade-off — it only
	// applies within the pre-learn window for a given key and self-heals once
	// the pattern is cached. The single shared group is intentional; do not
	// split it (splitting would re-open the cross-path stampede).
	var release func()
	var ok bool
	if retry {
		// Blocking acquire — wait for a slot, this event deserves classification.
		if release, ok = a.llmScheduler.AcquireBlocking(ctx); !ok {
			fr.Source = "retry_cancelled"
			return fr
		}
	} else {
		// Non-blocking: if all slots are busy, defer to the retry queue.
		if release, ok = a.llmScheduler.TryAcquire(); !ok {
			a.stats.LLMDropped.Add(1)
			fr.Source = "backpressure"
			return fr
		}
	}
	defer release()

	// In-flight re-check: a pattern for this line may have been learned out of
	// band (operator action, T2 reclassification) since the per-event Match.
	// Re-checking after the (possibly blocking) acquire and before the LLM call
	// avoids a redundant classification. The disclosure-override guard mirrors
	// Analyze/AnalyzeRetry — a cached suppress/allow on a disclosure line is not
	// honored. We do not re-increment DisclosureOverrides here: the per-event
	// Match already counted any poisoned cache entry, and learnFromVerdict never
	// learns suppress/allow for a disclosure line, so no fresh such entry exists.
	if result := a.patterns.Match(evt.ScopeKey(), evt.Hash, evt.NormalizedLine); result != nil {
		if !(hasDisclosure && (result.Verdict == patternstore.VerdictSuppress || result.Verdict == patternstore.VerdictAllow)) {
			a.stats.PatternHits.Add(1)
			if retry {
				a.stats.RetriedPatternHit.Add(1)
			}
			fr.Source = "pattern"
			fr.Match = result
			return fr
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

		// On LLM failure, return unknown — don't auto-allow or auto-malicious
		fr.Source = "error"
		fr.Reason = fmt.Sprintf("LLM error: %v", err)
		fr.Err = err
		return fr
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

	// --- Step 3c: T1 malicious clamp for HTTP events ---
	// A T1 verdict judges only the REQUEST; "malicious" is an outcome claim,
	// and outcomes require response evidence (T2 escalation is the legitimate
	// path to malicious). Computed HERE, before learning, so the learned hash
	// lands in the ALERT bucket — clamping only at verdict-mapping time would
	// let the pattern tier resurrect malicious-without-evidence on the next
	// identical line. verdict itself is never mutated: it is the immutable
	// original that resultRouter records to the audit trail. Non-HTTP events
	// (no method/path in either line form) are untouched.
	effectiveAction := verdict.Action
	if verdict.Action == "malicious" && eventHasHTTPIdentity(evt) {
		effectiveAction = "alert"
		fr.ClampedToAlert = true
		a.stats.T1MaliciousClamped.Add(1) // once per flight (leader), like LLMCalls
		log.Printf("[clamp] T1 LLM verdict malicious capped to alert for HTTP event %s — outcome claims require response evidence", evt.ID)
	}

	// --- Step 4: Learn from the LLM's response (leader-only) ---
	fr.PatternLearned = a.learnFromVerdict(evt, verdict, effectiveAction)
	fr.Source = "llm"
	fr.Verdict = verdict
	return fr
}

// buildResult turns a shared classifyFlightResult into this caller's own
// AnalysisResult. Followers (isLeader == false) carry the shared verdict's flat
// fields so routing and findings work, but NOT the *llm.Verdict — that keeps
// followers from writing duplicate llm_decisions audit rows (resultRouter gates
// the audit row on Source=="llm" && LLMVerdict != nil), so the audit count
// reflects real LLM calls, not coalesced events.
func (a *Analyzer) buildResult(evt *event.Event, fr *classifyFlightResult, retry, isLeader bool) AnalysisResult {
	switch fr.Source {
	case "pattern":
		source := fr.Match.Pattern.Source
		if retry {
			source += "_retry"
		}
		return AnalysisResult{
			Event:         evt,
			Verdict:       fr.Match.Verdict,
			Tier:          fr.Match.Tier,
			Reason:        fr.Match.Pattern.Reason,
			Source:        source,
			PatternScope:  evt.ScopeKey(),
			PatternBucket: string(fr.Match.Verdict),
			PatternValue:  fr.Match.Pattern.Value,
			OriginEventID: fr.Match.Pattern.CreatedFromEventID,
		}

	case "backpressure":
		return AnalysisResult{
			Event:   evt,
			Verdict: patternstore.VerdictUnknown,
			Reason:  "LLM concurrency limit reached — deferred to retry queue",
			Source:  "backpressure",
		}

	case "retry_cancelled":
		return AnalysisResult{
			Event:   evt,
			Verdict: patternstore.VerdictUnknown,
			Reason:  "context cancelled waiting for LLM slot",
			Source:  "retry_cancelled",
		}

	case "error":
		return AnalysisResult{
			Event:   evt,
			Verdict: patternstore.VerdictUnknown,
			Reason:  fr.Reason,
			Source:  "error",
		}

	default: // "llm"
		v := mapActionToVerdict(fr.Verdict.Action)
		if fr.ClampedToAlert {
			// Applied verdict only — fr.Verdict stays the immutable original.
			v = patternstore.VerdictAlert
		}
		result := AnalysisResult{
			Event:             evt,
			Verdict:           v,
			Reason:            fr.Verdict.Reason,
			Source:            "llm",
			LLMClassification: fr.Verdict.Classification,
			LLMConfidence:     fr.Verdict.Confidence,
			LLMClampedToAlert: fr.ClampedToAlert,
		}
		if isLeader {
			// Only the leader carries the learn flag and the full verdict
			// (with call metadata) for the audit trail. Followers leave
			// LLMVerdict nil so they write no duplicate llm_decisions row.
			result.LLMPatternLearned = fr.PatternLearned
			result.LLMVerdict = fr.Verdict
		}
		return result
	}
}

// learnFromVerdict processes the LLM's response and adds learned patterns
// to the pattern store. Returns true if a pattern was learned.
//
// v0.47:
//   - Confidence gate at 0.70 for hash learning of allow/suppress (was: no gate).
//   - Confidence gate at 0.85 for generalized prefix/regex/contains (unchanged).
//   - Regex-fallback-to-prefix learning REMOVED. Validation saying "no" now
//     means no — we don't downgrade a failed regex into a 40-char prefix.
//     The exact hash was already learned earlier in this function (when
//     confidence >= 0.70), so we still get fast-path caching for repeats.
//
// Trust model preserved:
//   - malicious / alert: hash only, NEVER generalized
//   - allow / suppress: hash at >= 0.70, generalized at >= 0.85
//   - low confidence (< 0.70): nothing is learned
//
// effectiveAction is the action actually applied to the event — usually
// verdict.Action, but "alert" when the T1 malicious clamp fired. Passed
// separately rather than via a mutated verdict copy: verdict is the immutable
// original the audit trail records, and a divergent copy invites accidental
// sharing. Learning follows the APPLIED action so the hash lands in the
// bucket future events will actually be routed by.
func (a *Analyzer) learnFromVerdict(evt *event.Event, verdict *llm.Verdict, effectiveAction string) bool {
	scopeKey := evt.ScopeKey()
	v := mapActionToVerdict(effectiveAction)

	// === Hash-learning gate (v0.47 F2) ===
	// Below 0.70 confidence we learn NOTHING. A low-confidence allow/suppress
	// hash matches every structurally-similar future event (hash is over the
	// normalized line), so caching a bad hunch is permanent damage.
	if verdict.Confidence < 0.70 {
		log.Printf("[analyzer] Confidence %.2f < 0.70 — learning nothing for %s [action=%s]",
			verdict.Confidence, scopeKey, verdict.Action)
		return false
	}

	// === Disclosure learning guard (v0.47, third-iteration review) ===
	//
	// Completes the disclosure-bypass rule:
	//   1. Disclosure cannot be suppressed by deterministic gates  (Analyze)
	//   2. Disclosure cannot be suppressed by old cache             (Analyze cache override)
	//   3. Disclosure cannot CREATE new suppress/allow cache        (this guard)
	//
	// Without this guard, an LLM that hedges and returns suppress/allow on a
	// disclosure-bearing line would pollute the pattern store. The cache
	// override at Analyze() prevents *silent* suppression but the override
	// would fire repeatedly on every recurrence, burning LLM calls and
	// cluttering [analyzer] DISCLOSURE_OVERRIDE log lines forever.
	//
	// MALICIOUS and ALERT learning is still allowed — those are escalations,
	// not suppression. Caching them on a disclosure line is correct (and the
	// cache hit on next encounter takes the alert/escalation path correctly).
	hasDisclosure := containsHighRiskDisclosure(evt.Line) ||
		containsHighRiskDisclosure(evt.NormalizedLine)
	if hasDisclosure && (v == patternstore.VerdictAllow || v == patternstore.VerdictSuppress) {
		log.Printf("[analyzer] DISCLOSURE_REFUSE_LEARN: refusing to learn %s for %s — line contains high-risk disclosure",
			v, scopeKey)
		a.stats.DisclosureOverrides.Add(1)
		return false
	}

	// v0.52: Attack-indicator guard.
	// Mirrors the disclosure guard above. If a log line contains SQL injection,
	// path traversal, or other attack payloads, we must NOT learn suppress/allow
	// for it. A bad LLM call (wrong classification at 0.70+ confidence) would
	// otherwise permanently suppress lines containing e.g. UNION SELECT.
	//
	// MALICIOUS and ALERT learning is still allowed — caching an escalation
	// on an attack-indicator line is correct behavior.
	if v == patternstore.VerdictAllow || v == patternstore.VerdictSuppress {
		if hasAttackPayloadForLearning(evt.NormalizedLine) {
			log.Printf("[analyzer] ATTACK_INDICATOR_REFUSE_LEARN: refusing to learn %s for %s — parsed HTTP request contains attack indicators",
				v, scopeKey)
			a.stats.DisclosureOverrides.Add(1) // reuse counter — both are "refuse to learn" events
			return false
		}
	}

	// Always learn the exact hash for allow/suppress (fast path for exact repeats)
	if v == patternstore.VerdictAllow || v == patternstore.VerdictSuppress {
		a.patterns.LearnHash(scopeKey, v, evt.Hash, verdict.Reason, evt.NormalizedLine, evt.ID)
	}

	// For malicious, learn the hash but NOT patterns (conservative trust model).
	// Hash-only is always safe regardless of confidence (we already passed 0.70),
	// because malicious classification on identical normalized lines should
	// continue to fire fast.
	if v == patternstore.VerdictMalicious {
		a.patterns.LearnHash(scopeKey, v, evt.Hash, verdict.Reason, evt.NormalizedLine, evt.ID)
		return false
	}

	// For alert, learn the exact hash so identical suspicious lines get instant
	// alerts without burning another LLM call. Stored as VerdictAlert — semantically
	// distinct from VerdictMalicious (suspicious vs confirmed-bad). Hash-only, no patterns,
	// no generalization. The conservative trust model is preserved.
	if effectiveAction == "alert" {
		a.patterns.LearnHash(scopeKey, patternstore.VerdictAlert, evt.Hash, verdict.Reason, evt.NormalizedLine, evt.ID)
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

	// === Generalized-pattern gate (unchanged) ===
	// Hash learning was permitted at 0.70+, but generalized prefix/regex/contains
	// requires more confidence — these affect future events that don't share the
	// exact normalized line.
	if verdict.Confidence < 0.85 {
		log.Printf("[analyzer] Confidence %.2f below 0.85 for generalized pattern (hash-only learned)", verdict.Confidence)
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
		Type:               pt,
		Value:              verdict.Pattern,
		Source:             "llm",
		Reason:             verdict.Reason,
		OriginalLine:       evt.NormalizedLine,
		CreatedAt:          time.Now(),
		CreatedFromEventID: evt.ID,
	}

	// Strict validation lives in patternstore.validatePattern (v0.47 F3).
	// If validation fails, we DO NOT fall back to a prefix variant (v0.47 F4).
	// The exact hash was already learned above. That's enough.
	if err := a.patterns.Learn(scopeKey, v, pattern); err != nil {
		log.Printf("[analyzer] Failed to learn %s pattern for %s [%s]: %v (hash-only fallback already in place)",
			verdict.PatternType, scopeKey, v, err)
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
	case "malicious":
		return patternstore.VerdictMalicious
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
		TotalProcessed:      a.stats.TotalProcessed.Load(),
		PatternHits:         a.stats.PatternHits.Load(),
		NoiseSuppressed:     a.stats.NoiseSuppressed.Load(),
		LLMCalls:            a.stats.LLMCalls.Load(),
		LLMErrors:           a.stats.LLMErrors.Load(),
		LLMDropped:          a.stats.LLMDropped.Load(),
		PatternsLearned:     a.stats.PatternsLearned.Load(),
		Retried:             a.stats.Retried.Load(),
		RetriedPatternHit:   a.stats.RetriedPatternHit.Load(),
		DisclosureOverrides: a.stats.DisclosureOverrides.Load(),
		T1MaliciousClamped:  a.stats.T1MaliciousClamped.Load(),
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
// SAFETY RULE:
//   These checks run on the RAW line, not the normalized line. They look
//   for structural patterns (indentation + "at", "Traceback", etc.) that
//   are unambiguous. If a stack trace also contains an exploit payload,
//   the LLM prompt improvements will catch it when the non-stack-trace
//   log line (the request line) comes through separately.

// =============================================================================
// High-Risk Disclosure Detection (v0.47, F5)
// =============================================================================
//
// The operational-noise filter suppresses stack traces and framework noise
// before they can reach the pattern store or LLM. That filter must NEVER
// shadow a confirmed exfiltration string. A Java exception with the file
// content stuck in the message — e.g.
//
//	"Caused by: java.io.IOException: read failed: root:x:0:0:root:/root:..."
//
// would otherwise be silently suppressed by the "Caused by: " prefix gate.
// Same risk applies to other framework-wrapped exceptions that happen to
// embed dumped credentials, env vars, or private keys.
//
// containsHighRiskDisclosure runs BEFORE every operational-noise return-true
// path. If it matches, the line is escalated out of the noise filter and
// allowed to proceed through pattern-store match (where the global malicious
// seeds in seeds.go will catch it) and, if necessary, the LLM.
//
// Strings here are duplicated from seeds.go (package main, not importable
// from internal/analyzer). They are stable, manually curated, and short
// enough that a periodic cross-check is the right consistency strategy.
// Length floor of ~12 chars per indicator is intentional — these must be
// distinctive enough that benign log content cannot collide.
var highRiskDisclosureIndicators = []string{
	// /etc/passwd format — root:x:0:0:root...
	"root:x:0:0:root",
	// Cryptographic key headers
	"BEGIN RSA PRIVATE KEY",
	"BEGIN OPENSSH PRIVATE KEY",
	"BEGIN EC PRIVATE KEY",
	"BEGIN PRIVATE KEY",
	"BEGIN DSA PRIVATE KEY",
	// Cloud / infrastructure credentials
	"AWS_SECRET_ACCESS_KEY",
	"aws_secret_access_key",
	// Shell / privilege markers — output of `id` command in a web container
	"uid=0(root)",
}

// containsHighRiskDisclosure returns true if the line contains any string
// from highRiskDisclosureIndicators. Case-sensitive on purpose — the seeded
// indicators are exact wire formats (private key PEM headers, /etc/passwd
// records, AWS env-var names), not natural-language tokens. Lowercasing
// would create false positives on technical prose.
func containsHighRiskDisclosure(line string) bool {
	for _, ind := range highRiskDisclosureIndicators {
		if strings.Contains(line, ind) {
			return true
		}
	}
	return false
}

func isOperationalNoise(line string) bool {
	// v0.47: if the line contains a high-risk disclosure
	// string, never suppress as noise — let it proceed to malicious-seed
	// matching and LLM classification. Catches the case where an exception
	// stack trace happens to wrap dumped credentials in its message.
	if containsHighRiskDisclosure(line) {
		return false
	}

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
// Two detection paths:
//
// Path 1 — HTTP access logs with failed status codes (404/403/405/400/410).
//   The normalizer preserves the status code. If the request has no attack
//   payload and isn't targeting a sensitive path, suppress it.
//
// Path 2 — Nginx error logs with "No such file or directory" (v0.16).
//   Structurally equivalent to a 404. The file doesn't exist on disk.
//   Same safety checks apply: attack indicators and sensitive paths
//   bypass suppression.
//
// SAFETY GATES (all three must pass for suppression):
//   1. No attack indicators in the request (SQL, traversal, XSS, etc.)
//   2. Not targeting a sensitive path (/.env, /.git, /actuator, etc.)
//   3. Status code or error message confirms "nothing found"
//
// WHY THIS EXISTS:
//   The LLM gets 404s right ~90% of the time but occasionally hedges and
//   classifies a clean probe as "alert." One bad call, cached forever,
//   produced 70 alert patterns and 20+ emails from a single phpunit scan.

// =============================================================================
// !!! SYNC WITH httpparse.go — keep these in lockstep !!!
// =============================================================================
//
// The structural HTTP regexes below are intentionally duplicated from the
// package-main file httpparse.go. They cannot be imported because Go forbids
// `internal/analyzer` from importing package main.
//
// THIS DUPLICATION IS A KNOWN COST. If you change the format of any nginx /
// Apache / generic-server access log Observer parses, you MUST update BOTH:
//
//   - /httpparse.go                              (REC correlation, coordinator)
//   - /internal/analyzer/analyzer.go (this file) (deterministic gate)
//
// If they drift, you will spend 3 days debugging why coordinator correlation
// keys don't match deterministic suppression gates. the design review guarantees it.
//
// POST-V1 CLEANUP: lift httpparse.go into internal/httpid/ so both packages
// can import a single source of truth. Tracked as v1.1 work, deferred from
// v0.47 because the lift touches main.go + resultrouter.go (bigger blast
// radius, no immediate security gain).
//
// =============================================================================
// Structural HTTP identity parser (v0.47, hardening item #1, scoping review)
// =============================================================================
//
// The previous implementation used loose regexes that scanned for the FIRST
// occurrence of HTTP/<version> followed by a status code anywhere in the line:
//
//   reStatusHosted = `HTTP/\S+\s+(\d{3})`           // unanchored
//   reStatusQuoted = `HTTP/\S+"\s+(\d{3})`          // unanchored
//
// That let an attacker inject a fake status by URL-encoding HTTP-version-like
// content into a request path: a request to /?x=fake%20HTTP/1.1%22%20404
// produces a log line where the loose regex matches the *injected* "404"
// before reaching the *actual* response status. The deterministic gate then
// suppresses a successful exploit.
//
// FIX: Use STRUCTURED parsers anchored to format. These are direct copies of
// the regexes in the package-main httpparse.go (Format 1/2/3 nginx/Apache
// log shapes) — cross-package import isn't possible because httpparse.go is
// package main. The duplication is small and the formats have been stable
// since the 1990s; if they ever drift, both sites must update together.
//
// SAFETY PROPERTIES:
//   - Format 1 (hostname-prefixed) anchored to start-of-line with ^
//   - Format 2 (quoted) anchored to literal closing quote after HTTP/<version>
//   - Format 3 (bare) anchored to start-of-line with ^
//   All three positions of the captured status code are structurally bound
//   to a real request-line terminator, not a free-floating "first match wins."
//
// PARSED PATH ONLY: Safety checks (hasSensitivePath, hasAttackIndicators)
// now run on the parsed `path` — not the whole line. This eliminates the
// secondary attack class where an attack indicator inside the *response
// portion* of the log triggered "looks safe" or "looks dangerous" wrongly.

var httpMethodsRE = `GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE`

// reHTTPHosted: Format 1 — "vhost METHOD /path HTTP/x.y NNN"
var reHTTPHosted = regexp.MustCompile(
	`^\S+\s+(` + httpMethodsRE + `)\s+(\S+)\s+HTTP/\S+\s+(\d{3})`)

// reHTTPQuoted: Format 2 — `... "METHOD /path HTTP/x.y" NNN`
// Status anchored after the literal closing quote of HTTP version.
var reHTTPQuoted = regexp.MustCompile(
	`"(` + httpMethodsRE + `)\s+(\S+)\s+HTTP/\S+"\s+(\d{3})`)

// reHTTPBare: Format 3 — "METHOD /path HTTP/x.y NNN" at start of line.
var reHTTPBare = regexp.MustCompile(
	`^(` + httpMethodsRE + `)\s+(\S+)\s+HTTP/\S+\s+(\d{3})`)

// reHTTPMorgan: Format 4 — Express/morgan access logs (captain-captain):
// "GET /api/keys 200 0.563 ms - 83". No HTTP/x.x token; the status follows
// the path directly, so the strict "<status> <time> ms - <bytes|->" tail is
// what keeps this from firing on arbitrary "METHOD path 200 ..." lines.
//
// KEEP IN SYNC with reMorganHTTP in the root package (httpparse.go) — the
// router uses that one to decide an event IS HTTP (coordinator routing, REC
// lookup) while the clamp/learning gates here use this one. If they drift,
// morgan lines become HTTP to the router but invisible to the T1 clamp —
// exactly the LLM-malicious-with-no-evidence gap this format closes.
var reHTTPMorgan = regexp.MustCompile(
	`^(` + httpMethodsRE + `)\s+(\S+)\s+(\d{3})\s+\d+(?:\.\d+)?\s+ms\s+-\s+(\d+|-)`)

// parseHTTPIdentity extracts (method, path, status) from a normalized log
// line using the structured Format 1/2/3 parsers. Returns zero values for
// non-HTTP lines (error logs, syslog, etc.) — callers must treat the empty
// method as "not an access log line."
//
// Path is returned with query string intact. Status is returned as a string
// (preserving the existing `failedStatusCodes` map key shape) but only if
// it parses as a 3-digit code.
func parseHTTPIdentity(normalizedLine string) (method, path, status string) {
	if m := reHTTPHosted.FindStringSubmatch(normalizedLine); m != nil {
		return m[1], m[2], m[3]
	}
	if m := reHTTPQuoted.FindStringSubmatch(normalizedLine); m != nil {
		return m[1], m[2], m[3]
	}
	if m := reHTTPBare.FindStringSubmatch(normalizedLine); m != nil {
		return m[1], m[2], m[3]
	}
	// Format 4 tried LAST, mirroring httpparse.go's ordering — nginx-format
	// lines with an HTTP/x.x token never reach it.
	if m := reHTTPMorgan.FindStringSubmatch(normalizedLine); m != nil {
		return m[1], m[2], m[3]
	}
	return "", "", ""
}

// eventHasHTTPIdentity reports whether either line form parses to an HTTP
// access-log identity (method + path). Checks BOTH normalized and raw because
// resultRouter's isHTTP derives method from raw OR normalized; checking only
// one would let the router treat an event as HTTP while the T1 clamp didn't
// fire (clamp/routing mismatch).
func eventHasHTTPIdentity(evt *event.Event) bool {
	if m, p, _ := parseHTTPIdentity(evt.NormalizedLine); m != "" && p != "" {
		return true
	}
	m, p, _ := parseHTTPIdentity(evt.Line)
	return m != "" && p != ""
}

// hasAttackPayloadForLearning reports whether a line carries an actual attack
// payload that should block suppress/allow learning. It scans ONLY the HTTP
// request portion of the line — never arbitrary service text.
//
// The raw attackIndicators list contains bare SQL keywords ("UPDATE", "SELECT",
// "DROP", "DELETE", ...). Run against a whole non-HTTP log line via
// hasAttackIndicators, those substring-match ordinary English: "Firmware update
// daemon" -> UPDATE, "sshd dropped a connection" -> DROP. That caused routine
// service noise (systemd lifecycle, sshd MaxStartups) to hit
// ATTACK_INDICATOR_REFUSE_LEARN and re-classify on every occurrence instead of
// caching. Attack payloads only appear in request paths/query strings, so we
// restrict the scan to a parsed request path or the request embedded in an
// nginx error log. Malicious/alert learning is unaffected — this guards only
// the suppress/allow learn path.
func hasAttackPayloadForLearning(normalizedLine string) bool {
	if _, path, _ := parseHTTPIdentity(normalizedLine); path != "" {
		return hasAttackIndicators(path)
	}
	if m := reNginxErrorRequest.FindStringSubmatch(normalizedLine); m != nil {
		return hasAttackIndicators(m[1])
	}
	return false
}

// Nginx error log patterns for structural 404 detection.
var (
	// "open() "/path/file" failed (2: No such file or directory)" = file doesn't exist = 404
	reNginxFileNotFound = regexp.MustCompile(`open\(\)\s+"[^"]*"\s+failed\s+\(2:\s*No such file or directory\)`)

	// Extract the HTTP request embedded in nginx error logs: request: "GET /path HTTP/1.1"
	reNginxErrorRequest = regexp.MustCompile(`request:\s+"([^"]*)"`)
)

// failedStatusCodes are HTTP status codes that indicate a probe found nothing.
// NOTE: 401 (Unauthorized) is deliberately excluded. A 401 means "this endpoint
// exists and requires auth" — that's surface discovery, not pure nothing.
// Note: /admin returning 401 is a meaningful finding.
var failedStatusCodes = map[string]bool{
	"400": true, // Bad request
	"403": true, // Forbidden
	"404": true, // Not found
	"405": true, // Method not allowed
	"410": true, // Gone
}

// =============================================================================
// Probe Classification Helpers — RESERVED FOR FUTURE PROBES VIEW
// =============================================================================
//
// v0.47 (policy override): the helpers below classify probe shape
// (sensitive-path target, attack-payload presence). They are NOT used in
// routing decisions. They were previously called from isFailedProbe to
// escape suppression, but operational data showed that path filled the main
// dashboard with orange noise on legitimate scanner traffic.
//
// New rule: failed probes always suppress in the main routing pipeline.
//
// IMPORTANT: deterministic-suppressed failed probes are currently NOT
// persisted anywhere. The orchestration path returns at Route() before
// any finding write. If the future Probes view needs probe history, a
// dedicated write path (or `probes` table) must be added — the classifier
// helpers below will then be useful for filtering and aggregation. Until
// that view is built, these helpers are dead code maintained as
// intelligence-surface scaffolding.
//
// DO NOT call these from routing logic. They are intelligence-surface
// classifiers, not action-surface gates.

// attackIndicators are substrings that suggest the request itself contains
// an attack payload. Used by hasAttackIndicators for future Probes view
// filtering. Not used in routing.
var attackIndicators = []string{
	"UNION", "SELECT", "DROP", "INSERT", "UPDATE", "DELETE", // SQL
	"../", "..\\", // path traversal
	"%00", "%0a", "%0d", "%27", "%22", // null/injection encoding
	"<script", "javascript:", // XSS
	";ls", ";cat", ";rm", ";wget", ";curl", // command injection (specific)
	"|", "`", "$(", "${", // command injection (operators)
	"php://", "data://", "file://", // PHP wrappers
	"eval(", "exec(", "system(", // code execution
	"call_user_func", "invokefunction", // PHP indirect execution (ThinkPHP RCE)
}

// sensitivePaths are URL paths historically considered "credential/config/
// debug endpoints worth tagging." Used by hasSensitivePath for future
// Probes view classification. Not used in routing.
//
// Original source: deep research (2026-03-24).
// That decision was overridden in v0.47 — sensitive-path probes no longer
// escape suppression — but the path list itself remains useful as a
// classifier label for the Probes view.
var sensitivePaths = []string{
	"/.env",
	"/.git",
	"/.aws",
	"/.ssh",
	"/.docker",
	"/.htaccess",
	"/.htpasswd",
	"/wp-admin",
	"/wp-login",
	"/wp-config",
	"/actuator",
	"/_ignition",
	"/debug",
	"/phpinfo",
	"/server-status",
	"/server-info",
	"/elmah.axd",
	"/web.config",
	"/config.php",
	"/config.json",
	"/credentials",
	"/containers/json",
}

// hasAttackIndicators returns true if the request contains substrings that
// suggest an attack payload. Case-insensitive.
//
// v0.47 (policy override): this function is RESERVED for future Probes
// view classification. NOT called from routing logic. The forgiving URL
// decoder below ensures encoded payloads don't bypass classification once
// the Probes view is built.
//
// Decode is bounded: input + decode-once + decode-twice. No recursion, no
// loop — three candidates max — so a malformed input cannot expand without
// limit. Forgiving decoder so malformed escapes don't discard the whole
// string (the way stdlib url.QueryUnescape does).
func hasAttackIndicators(request string) bool {
	candidates := attackIndicatorCandidates(request)
	for _, candidate := range candidates {
		upper := strings.ToUpper(candidate)
		for _, indicator := range attackIndicators {
			if strings.Contains(upper, strings.ToUpper(indicator)) {
				return true
			}
		}
	}
	return false
}

// attackIndicatorCandidates returns the input plus up to two URL-decoded
// derivatives. Bounded to 3 entries; never expands further. Uses the
// forgiving decoder so malformed escapes don't discard the whole string.
func attackIndicatorCandidates(input string) []string {
	candidates := []string{input}
	d1 := forgivingURLDecode(input)
	if d1 != input {
		candidates = append(candidates, d1)
		d2 := forgivingURLDecode(d1)
		if d2 != d1 {
			candidates = append(candidates, d2)
		}
	}
	return candidates
}

// forgivingURLDecode performs URL percent-decoding while tolerating malformed
// escape sequences. Where url.QueryUnescape returns an error and discards the
// whole string on the first invalid `%XY`, this function decodes valid
// triplets and passes invalid ones through unchanged.
//
// the attack class (2026-05): an attacker appends `%zz` (or any invalid
// percent-triplet) to an otherwise-encoded payload, e.g.
//
//	q=%3Cscript%3E&garbage=%zz
//
// The stdlib decoder fails on `%zz` and returns ("", error). Falling back to
// "no decoded candidate" means the encoded `<script>` is never compared
// against the attack indicator list. This decoder yields:
//
//	q=<script>&garbage=%zz
//
// Decode rules:
//   - `+` is decoded to space (matches QueryUnescape behavior)
//   - `%` followed by exactly two hex digits is decoded to that byte
//   - `%` followed by anything else is passed through literally as `%`,
//     preserving the malformed sequence in the output without halting.
//
// Performance: single pass, O(n), no allocations beyond the result builder.
func forgivingURLDecode(input string) string {
	// Fast path: no percent-encoded bytes and no plus signs — nothing to do.
	if !strings.ContainsAny(input, "%+") {
		return input
	}

	var b strings.Builder
	b.Grow(len(input))
	i := 0
	for i < len(input) {
		c := input[i]
		switch {
		case c == '%' && i+2 < len(input) && isHexByte(input[i+1]) && isHexByte(input[i+2]):
			// Valid triplet — decode it
			b.WriteByte(unhexByte(input[i+1])<<4 | unhexByte(input[i+2]))
			i += 3
		case c == '+':
			b.WriteByte(' ')
			i++
		default:
			// Malformed escape (e.g. "%zz") or any non-encoded byte — pass through.
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// isHexByte reports whether b is a valid ASCII hex digit (0-9, a-f, A-F).
func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// unhexByte returns the numeric value of a hex digit byte. Caller must
// ensure b passes isHexByte first.
func unhexByte(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	default: // 'A' - 'F'
		return b - 'A' + 10
	}
}

// truncateForLog shortens a string to maxLen characters with an ellipsis
// for safe inclusion in log lines (avoid spamming journalctl with full
// pattern values when DISCLOSURE_OVERRIDE fires).
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// hasSensitivePath returns true if the request targets a path historically
// classified as a credential/config/debug endpoint.
//
// v0.47 (policy override): this function is RESERVED for future Probes
// view classification. NOT called from routing logic. A failed probe is a
// failed probe regardless of target path.
func hasSensitivePath(request string) bool {
	lower := strings.ToLower(request)
	for _, p := range sensitivePaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isFailedProbe(normalizedLine string) (string, bool) {
	if normalizedLine == "" {
		return "", false
	}

	// v0.47: defense-in-depth — high-risk disclosure
	// must never be suppressed by ANY deterministic gate. The Analyze()
	// orchestration layer also enforces this, but a function-level guard
	// keeps the safety property correct in isolation. Cheap (single-pass
	// substring check over a 9-element list) and idempotent with the
	// orchestration check.
	if containsHighRiskDisclosure(normalizedLine) {
		return "", false
	}

	// --- Path 1: Nginx error log "No such file or directory" ---
	// Structurally a 404. The file doesn't exist on disk.
	// The error log format has no HTTP status code, but the meaning is
	// unambiguous: nginx tried to open a file and it wasn't there.
	//
	// v0.47 (policy override of v0.16 / March 24 decision): no longer
	// escapes for sensitive paths or attack indicators. A failed probe is
	// a failed probe, regardless of what was probed. Operational data
	// showed the previous "never suppress sensitive paths" rule fills
	// the main dashboard with orange noise that drowns real alerts.
	//
	// NOTE: deterministic-suppressed failed probes are NOT currently written
	// to the findings store — they return at Route() before any DB write.
	// If the future Probes view needs probe history, a separate write path
	// (or a dedicated `probes` table) must be added. The classifier helpers
	// below (hasSensitivePath, hasAttackIndicators) remain available for
	// that future use, but no probe data is currently captured for them.
	//
	// EXCEPTION: high-risk disclosure indicators still bypass suppression
	// (handled at top of this function). Those represent actual data
	// leakage in the log line, not scanner intent.
	if reNginxFileNotFound.MatchString(normalizedLine) {
		return "Deterministic: nginx file not found — failed probe", true
	}

	// --- Path 2: HTTP access log with failed status code ---
	//
	// v0.47: Use structural parseHTTPIdentity instead of
	// loose status regexes. Status anchored to format prevents the
	// regex-spoofing attack class.
	//
	// v0.47 (policy override): pure status-based suppression. No
	// sensitive-path or attack-indicator escapes — failed = suppress.
	method, _, statusCode := parseHTTPIdentity(normalizedLine)
	if method == "" {
		return "", false // not an HTTP access log line
	}

	if !failedStatusCodes[statusCode] {
		return "", false
	}

	reason := fmt.Sprintf("Deterministic: HTTP %s — failed probe, no exfiltration possible", statusCode)
	return reason, true
}
