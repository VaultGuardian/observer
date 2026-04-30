// resultrouter.go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/notifier"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
	"github.com/vaultguardian/observer/internal/watcher"
)

// resultRouter handles post-classification routing for ALL analysis results.
// Both the primary pipeline workers and retry workers call Route().
// One function, one truth, no drift.
type resultRouter struct {
	cfg              Config
	db               *store.Store
	collector        rec.EvidenceCollector
	alertCoordinator *coordinator.Coordinator
	dispatch         *notifier.Dispatcher
}

// Route processes a classification result: records LLM decision to audit trail,
// handles recon_failed, routes alerts through coordinator (HTTP) or directly
// to findings (non-HTTP). Called by both primary and retry workers.
func (r *resultRouter) Route(evt *event.Event, result *analyzer.AnalysisResult, line watcher.LogLine, tier string) {
	// --- Record LLM decision to audit trail ---
	if result.Source == "llm" && result.LLMVerdict != nil {
		v := result.LLMVerdict
		r.db.RecordLLMDecision(context.Background(), &store.LLMDecision{
			EventID:          evt.ID,
			Timestamp:        evt.Timestamp,
			Tier:             tier,
			Model:            r.cfg.LLMModel,
			ReasoningEffort:  r.cfg.Tier1Effort,
			PromptTokens:     v.PromptTokens,
			CompletionTokens: v.CompletionTokens,
			LatencyMs:        v.LatencyMs,
			SourceScope:      evt.ScopeKey(),
			RawLine:          evt.Line,
			NormalizedLine:   evt.NormalizedLine,
			NormalizedHash:   evt.Hash,
			LLMResponseRaw:   v.ResponseRaw,
			Classification:   v.Classification,
			Action:           v.Action,
			Confidence:       v.Confidence,
			Reason:           v.Reason,
			PatternType:      v.PatternType,
			PatternValue:     v.Pattern,
			SourceHint:       v.SourceHint,
			PatternLearned:   result.LLMPatternLearned,
			PatternBucket:    v.Action,
			CacheKey:         v.Pattern,
			FinalVerdict:     string(result.Verdict),
		})
	}

	// --- Route based on verdict ---
	switch result.Verdict {
	case patternstore.VerdictAllow, patternstore.VerdictSuppress:
		return

	case patternstore.VerdictMalicious, patternstore.VerdictAlert:
		r.routeAlert(evt, result, line)

	case patternstore.VerdictUnknown:
		if result.Source == "error" {
			log.Printf("[LLM_ERROR] Source=%s Line=%s", evt.ScopeKey(), truncate(evt.Line, 100))
		}
	}
}

// routeAlert handles malicious/alert verdicts.
func (r *resultRouter) routeAlert(evt *event.Event, result *analyzer.AnalysisResult, line watcher.LogLine) {
	method, path, host, statusCode := parseNormalizedLine(evt.NormalizedLine)
	isHTTP := method != ""

	// --- Recon routing ---
	if result.LLMClassification == "recon_failed" {
		log.Printf("[RECON] EventID=%s Source=%s Classification=%s Reason=%s MatchedVia=%s Line=%s",
			evt.ID, evt.ScopeKey(), result.LLMClassification, result.Reason, result.Source,
			truncate(evt.Line, 200))

		// Fix 3: Use async writer for recon (droppable under DDoS)
		r.db.SubmitFinding(&store.Finding{
			EventID:              evt.ID,
			Timestamp:            evt.Timestamp,
			SourceType:           evt.SourceType,
			SourceName:           evt.SourceName,
			DestHost:             host,
			HTTPMethod:           method,
			HTTPPath:             path,
			HTTPStatus:           statusCode,
			Verdict:              "recon",
			Classification:       result.LLMClassification,
			Confidence:           result.LLMConfidence,
			Reason:               result.Reason,
			MatchedVia:           result.Source,
			MatchedPatternScope:  result.PatternScope,
			MatchedPatternBucket: result.PatternBucket,
			MatchedPatternValue:  result.PatternValue,
			RawLine:              evt.Line,
			NormalizedLine:       evt.NormalizedLine,
			NormalizedHash:       evt.Hash,
			Notified:             false,
		})
		return
	}

	// --- Cache-hit status-aware routing (Option C — design consensus) ---
	//
	// WHY: The pattern store caches T1 verdicts ("this is an attack") but NOT
	// T2 outcomes ("the attack failed"). Cache-hit events go to the coordinator,
	// but the coordinator/graveyard cycle re-produces MALICIOUS findings every
	// ~5 minutes as graveyard entries expire. Over 12 hours, the dashboard
	// fills with orange badges for attacks bouncing off 404s.
	//
	// FIX: For cache-hit attack patterns where the HTTP status code in the log
	// line already proves the attack was rejected, short-circuit as recon.
	// No coordinator, no REC, no email. The pattern store is untouched — the
	// pattern still means "this request shape is malicious." The event outcome
	// means "this specific attempt failed."
	//
	// SCOPE:
	//   - Cache hits only (result.Source != "llm") — fresh LLM events always
	//     go through the full coordinator/evidence pipeline.
	//   - HTTP events with status 403/404/405/410 only.
	//   - 200/3xx/5xx/unknown still route to coordinator for REC/T2.
	//   - Non-HTTP events are untouched.
	//   - Pattern store verdict is NOT modified.
	//
	// SAFETY: 400 excluded from first cut. Ship conservative, add after logs.
	if result.Source != "llm" && isHTTP && statusCodeRejectsAttack(statusCode) {
		reason := fmt.Sprintf("Known attack pattern (via:%s) rejected by server — HTTP %d confirms failure", result.Source, statusCode)

		log.Printf("[RECON:STATUS] EventID=%s Source=%s Status=%d Classification=%s PatternVia=%s Line=%s",
			evt.ID, evt.ScopeKey(), statusCode, result.LLMClassification, result.Source,
			truncate(evt.Line, 200))

		r.db.SubmitFinding(&store.Finding{
			EventID:              evt.ID,
			Timestamp:            evt.Timestamp,
			SourceType:           evt.SourceType,
			SourceName:           evt.SourceName,
			DestHost:             host,
			HTTPMethod:           method,
			HTTPPath:             path,
			HTTPStatus:           statusCode,
			Verdict:              "recon",
			Classification:       "recon_failed_status",
			Confidence:           result.LLMConfidence,
			Reason:               reason,
			MatchedVia:           result.Source,
			MatchedPatternScope:  result.PatternScope,
			MatchedPatternBucket: result.PatternBucket,
			MatchedPatternValue:  result.PatternValue,
			RawLine:              evt.Line,
			NormalizedLine:       evt.NormalizedLine,
			NormalizedHash:       evt.Hash,
			Notified:             false,
			Downgraded:           true,
			DowngradeReason:      reason,
			ResolutionStatus:     "resolved",
			ResolutionMethod:     "status_only",
			PreviousVerdict:      string(result.Verdict),
		})
		return
	}

	severity := "malicious"
	notifSeverity := notifier.SeverityMalicious
	if result.Verdict == patternstore.VerdictAlert {
		severity = "suspicious"
		notifSeverity = notifier.SeveritySuspicious
	}

	respBytes := extractResponseBytes(evt.Line)

	// --- HTTP alerts: route through coordinator for evidence huddle ---
	if isHTTP && r.collector.Enabled() {
		correlationKey := fmt.Sprintf("%s|%s|%d", method, canonicalPath(path), statusCode)

		// Fix 1: Pin VIP evidence for malicious events.
		// The collector stores match criteria in a protected map that
		// CANNOT be evicted by traffic floods. When a matching response
		// arrives, the VIP callback fires immediately.
		if result.Verdict == patternstore.VerdictMalicious {
			r.collector.PinVIP(evt.ID, correlationKey, rec.LookupRequest{
				Method:          method,
				Path:            path,
				Host:            host,
				SourceContainer: evt.SourceName,
				StatusCode:      statusCode,
				Timestamp:       evt.Timestamp,
				Window:          5 * time.Second,
				ExpectedBytes:   respBytes,
			})
		}

		// Capture variables for closure
		evtCopy := evt
		resultCopy := result
		lineCopy := line

		alertBuilder := func() interface{} {
			evidence := r.collector.Lookup(rec.LookupRequest{
				Method:          method,
				Path:            path,
				SourceContainer: evtCopy.SourceName,
				StatusCode:      statusCode,
				Timestamp:       evtCopy.Timestamp,
				Window:          5 * time.Second,
				ExpectedBytes:   respBytes,
			})
			return notifier.Alert{
				EventID:        evtCopy.ID,
				Severity:       notifSeverity,
				ContainerID:    lineCopy.ContainerID,
				ContainerName:  lineCopy.ContainerName,
				LogLine:        evtCopy.Line,
				NormalizedHash: evtCopy.Hash,
				Reason:         resultCopy.Reason,
				MatchedVia:     resultCopy.Source,
				Classification: resultCopy.LLMClassification,
				Confidence:     resultCopy.LLMConfidence,
				Timestamp:      evtCopy.Timestamp,
				Evidence:       evidence,
			}
		}

		r.alertCoordinator.Process(correlationKey, &coordinator.PendingAlert{
			EventID:        evt.ID,
			ScopeKey:       evt.ScopeKey(),
			SourceType:     evt.SourceType,
			Reason:         result.Reason,
			MatchedVia:     result.Source,
			PatternScope:   result.PatternScope,
			PatternBucket:  result.PatternBucket,
			PatternValue:   result.PatternValue,
			Hash:           evt.Hash,
			Line:           evt.Line,
			Verdict:        string(result.Verdict),
			Severity:       severity,
			Classification: result.LLMClassification,
			Host:           host,
			StatusCode:     statusCode,
			ResponseBytes:  respBytes,
			HTTPMethod:     method,
			HTTPPath:       path,
			// Fix 2: BodyPreviewHash for catch-all matching.
			// Intentionally empty at routing time — evidence callback in
			// tryEvidenceCheck() populates this when REC captures a response
			// (Phase 2 re-arm). If REC misses entirely, Phase 3 fallback in
			// investigationLoop() uses ResponseBytes instead.
			BodyPreviewHash: "",
			NormalizedLine:  evt.NormalizedLine,
			SourceName:      evt.SourceName,
			Timestamp:       evt.Timestamp,
			BuildAlert:      alertBuilder,
		})
		return
	}

	// --- Non-HTTP alerts: direct to findings ---
	log.Printf("[ALERT] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s Line=%s",
		evt.ID, evt.ScopeKey(), result.Reason, result.Source, evt.Hash,
		truncate(evt.Line, 200))

	// Non-HTTP malicious events (e.g., container stderr with credential dumps,
	// command execution output) bypass the coordinator evidence pipeline because
	// there is no HTTP request/response pair to evaluate. The malicious content
	// IS the log line itself. Dispatch notification directly, same as policy engine.
	shouldNotify := result.Verdict == patternstore.VerdictMalicious

	if shouldNotify {
		log.Printf("[ESCALATE] EventID=%s Source=%s Reason=%s MatchedVia=%s (non-HTTP malicious, direct dispatch)",
			evt.ID, evt.ScopeKey(), result.Reason, result.Source)

		alert := notifier.Alert{
			EventID:        evt.ID,
			Severity:       notifier.SeverityMalicious,
			ContainerID:    line.ContainerID,
			ContainerName:  line.ContainerName,
			LogLine:        evt.Line,
			Reason:         result.Reason,
			MatchedVia:     result.Source,
			Classification: result.LLMClassification,
			Confidence:     result.LLMConfidence,
			Timestamp:      evt.Timestamp,
		}
		r.dispatch.Dispatch(context.Background(), alert)
	}

	// Fix 3: Use async writer for non-HTTP alerts (non-droppable — blocks if full)
	r.db.SubmitFinding(&store.Finding{
		EventID:              evt.ID,
		Timestamp:            evt.Timestamp,
		SourceType:           evt.SourceType,
		SourceName:           evt.SourceName,
		DestHost:             host,
		HTTPMethod:           method,
		HTTPPath:             path,
		HTTPStatus:           statusCode,
		ResponseBytes:        respBytes,
		Verdict:              string(result.Verdict),
		Classification:       result.LLMClassification,
		Confidence:           result.LLMConfidence,
		Reason:               result.Reason,
		MatchedVia:           result.Source,
		MatchedPatternScope:  result.PatternScope,
		MatchedPatternBucket: result.PatternBucket,
		MatchedPatternValue:  result.PatternValue,
		RawLine:              evt.Line,
		NormalizedLine:       evt.NormalizedLine,
		NormalizedHash:       evt.Hash,
		Notified:             shouldNotify,
	})
}