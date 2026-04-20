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
			EventID:        evt.ID,
			Timestamp:      evt.Timestamp,
			SourceType:     evt.SourceType,
			SourceName:     evt.SourceName,
			DestHost:       host,
			HTTPMethod:     method,
			HTTPPath:       path,
			HTTPStatus:     statusCode,
			Verdict:        "recon",
			Classification: result.LLMClassification,
			Confidence:     result.LLMConfidence,
			Reason:         result.Reason,
			MatchedVia:     result.Source,
			RawLine:        evt.Line,
			NormalizedLine: evt.NormalizedLine,
			NormalizedHash: evt.Hash,
			Notified:       false,
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
			// Empty at routing time — populated when evidence arrives.
			// Catch-all Check skips when empty.
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

	// Fix 3: Use async writer for non-HTTP alerts (non-droppable — blocks if full)
	r.db.SubmitFinding(&store.Finding{
		EventID:        evt.ID,
		Timestamp:      evt.Timestamp,
		SourceType:     evt.SourceType,
		SourceName:     evt.SourceName,
		DestHost:       host,
		HTTPMethod:     method,
		HTTPPath:       path,
		HTTPStatus:     statusCode,
		ResponseBytes:  respBytes,
		Verdict:        string(result.Verdict),
		Classification: result.LLMClassification,
		Confidence:     result.LLMConfidence,
		Reason:         result.Reason,
		MatchedVia:     result.Source,
		RawLine:        evt.Line,
		NormalizedLine: evt.NormalizedLine,
		NormalizedHash: evt.Hash,
		Notified:       false,
	})
}
