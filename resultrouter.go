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
//
// code review code review (April 2026): the retry worker had its own copy of
// post-classification routing that drifted from the primary path.
// Two confirmed bugs: non-HTTP alerts silently dropped on retry,
// and retried HTTP alerts missing ResponseBytes.
type resultRouter struct {
	cfg              Config
	db               *store.Store
	collector        rec.EvidenceCollector
	alertCoordinator *coordinator.Coordinator
}

// Route processes a classification result: records LLM decision to audit trail,
// handles recon_failed, routes alerts through coordinator (HTTP) or directly
// to findings (non-HTTP). Called by both primary and retry workers.
//
// tier is "classify" for primary pipeline, "classify_retry" for retry workers.
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
		// Done — pattern learned or noise confirmed
		return

	case patternstore.VerdictMalicious, patternstore.VerdictAlert:
		r.routeAlert(evt, result, line)

	case patternstore.VerdictUnknown:
		if result.Source == "error" {
			log.Printf("[LLM_ERROR] Source=%s Line=%s", evt.ScopeKey(), truncate(evt.Line, 100))
		}
	}
}

// routeAlert handles malicious/alert verdicts: recon routing, HTTP coordinator path,
// and non-HTTP direct-to-findings path.
func (r *resultRouter) routeAlert(evt *event.Event, result *analyzer.AnalysisResult, line watcher.LogLine) {
	method, path, host, statusCode := parseNormalizedLine(evt.NormalizedLine)
	isHTTP := method != ""

	// --- Recon routing: log + store, no email ---
	// recon_failed = probe found nothing. Telemetry only.
	// recon_success = probe got a 200. Must flow through coordinator
	// for evidence check — if the response contains credentials,
	// T2 reclassify will escalate to malicious and send email.
	if result.LLMClassification == "recon_failed" {
		log.Printf("[RECON] EventID=%s Source=%s Classification=%s Reason=%s MatchedVia=%s Line=%s",
			evt.ID, evt.ScopeKey(), result.LLMClassification, result.Reason, result.Source,
			truncate(evt.Line, 200))

		r.db.RecordFinding(context.Background(), &store.Finding{
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
			NormalizedLine: evt.NormalizedLine,
			SourceName:     evt.SourceName,
			Timestamp:      evt.Timestamp,
			BuildAlert:     alertBuilder,
		})
		return
	}

	// --- Non-HTTP alerts (sshd, sudo, kernel, etc.): direct to findings ---
	// No coordinator huddle, no evidence capture — these aren't HTTP requests.
	// Log and record to SQLite for dashboard review.
	log.Printf("[ALERT] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s Line=%s",
		evt.ID, evt.ScopeKey(), result.Reason, result.Source, evt.Hash,
		truncate(evt.Line, 200))

	// NO EMAIL — only escalated alerts (evidence-confirmed exposure) send email.
	// Non-HTTP alerts are logged to SQLite for dashboard review.
	r.db.RecordFinding(context.Background(), &store.Finding{
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