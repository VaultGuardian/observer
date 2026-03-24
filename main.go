package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/notifier"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/watcher"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("[observer] VaultGuardian Observer starting...")

	cfg := LoadConfig()

	// ------- Ensure data dir exists -------
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatalf("[observer] Failed to create data dir: %v", err)
	}

	// ------- Init components -------
	normReg := normalizer.NewRegistry()
	log.Println("[observer] Normalizer registry initialized")

	patterns, err := patternstore.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("[observer] Failed to init pattern store: %v", err)
	}
	seedDenyPatterns(patterns)
	log.Printf("[observer] Pattern store initialized (%d scopes)", patterns.ScopeCount())

	llmClient := llm.NewClient(cfg.LLMURL, cfg.LLMModel, cfg.LLMAPIKey)
	a := analyzer.New(normReg, patterns, llmClient, cfg.MaxConcurrentLLM)
	log.Println("[observer] Analyzer pipeline ready")

	notifCfg, err := notifier.LoadConfig(cfg.DataDir)
	if err != nil {
		log.Fatalf("[observer] Failed to load notification config: %v", err)
	}
	dispatch, err := notifier.NewDispatcher(notifCfg)
	if err != nil {
		log.Fatalf("[observer] Failed to init notifications: %v", err)
	}
	dispatch.PrintStatus()
	if dispatch.ChannelCount() == 0 {
		log.Println("[observer] No notification channels configured — alerts will be logged to stdout only")
	}

	// ------- Init Response Evidence Capture (opt-in) -------
	recCfg := rec.DefaultCollectorConfig()
	recCfg.Enabled = cfg.RECEnabled
	recCfg.DockerSocket = cfg.DockerSocket
	recCfg.Interface = cfg.RECInterface
	recCfg.VXLANPort = cfg.RECVXLANPort
	recCfg.NSContainer = cfg.RECNSContainer
	collector := rec.NewCollector(recCfg)

	// ------- Context with graceful shutdown -------
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[observer] Shutting down...")
		cancel()
	}()

	// ------- Start REC capture -------
	if err := collector.Start(ctx); err != nil {
		log.Printf("[observer] REC failed to start: %v (continuing without evidence capture)", err)
	}

	// ------- LLM health check (non-blocking) -------
	go func() {
		for {
			if err := llmClient.HealthCheck(ctx); err != nil {
				log.Printf("[observer] LLM not ready: %v (will retry)", err)
				time.Sleep(10 * time.Second)
				continue
			}
			log.Println("[observer] LLM inference server connected")
			return
		}
	}()

	// ------- Periodic persistence + stats -------
	go runPeriodicStats(ctx, a, patterns, collector)

	// ------- Re-Classification Cache -------
	reclassCache := newReclassCache()

	// ------- Alert Coordinator -------
	alertCoordinator := coordinator.New(
		ctx,
		coordinator.DefaultConfig(),
		makeDispatchCallback(dispatch),
		makeEvidenceCheckCallback(collector, llmClient, reclassCache, ctx),
	)

	// ------- Log handler -------
	handler := makeLogHandler(cfg, a, collector, alertCoordinator, dispatch)

	// ------- Start watching -------
	w := watcher.New(cfg.DockerSocket, handler)
	w.SetSelfID(cfg.SelfID)

	log.Println("[observer] Starting container log watcher...")
	if err := w.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("[observer] Watcher error: %v", err)
	}

	// ------- Shutdown -------
	if err := a.Persist(); err != nil {
		log.Printf("[observer] Failed final persist: %v", err)
	}
	aStats := a.GetStats()
	log.Printf("[observer] Final stats: processed=%d pattern_hits=%d noise_suppressed=%d llm_calls=%d learned=%d",
		aStats.TotalProcessed, aStats.PatternHits, aStats.NoiseSuppressed, aStats.LLMCalls, aStats.PatternsLearned)
	log.Println("[observer] Shutdown complete")
}

// =============================================================================
// Coordinator Callbacks
// =============================================================================

// makeDispatchCallback creates the function called when a coordinator
// investigation concludes — either dispatching or suppressing the alert.
func makeDispatchCallback(dispatch *notifier.Dispatcher) coordinator.DispatchFunc {
	return func(alert coordinator.FinalAlert) {
		if alert.Downgraded {
			log.Printf("[DOWNGRADED] EventID=%s key=%s events=%d Original→recon_failed Reason=%s",
				alert.EventID, alert.ScopeKey, alert.EventCount, alert.DowngradeReason)
			log.Printf("[INFO] EventID=%s Source=%s OriginalReason=%s DowngradedReason=%s %s Line=%s",
				alert.EventID, alert.ScopeKey, alert.Reason, alert.DowngradeReason,
				alert.EvidenceJournal, truncate(alert.Line, 200))
			return
		}

		if alert.BuildAlert == nil {
			return
		}
		builtAlert, ok := alert.BuildAlert().(notifier.Alert)
		if !ok {
			return
		}

		severity := "ALERT"
		if alert.Severity == "suspicious" {
			severity = "SUSPICIOUS"
		}
		log.Printf("[%s] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s %s Line=%s",
			severity, alert.EventID, alert.ScopeKey, alert.Reason,
			alert.MatchedVia, alert.Hash, alert.EvidenceJournal, truncate(alert.Line, 200))

		dispatch.Dispatch(context.Background(), builtAlert)
	}
}

// makeEvidenceCheckCallback creates the function called periodically by the
// coordinator to check if REC evidence can downgrade a pending alert.
func makeEvidenceCheckCallback(
	collector rec.EvidenceCollector,
	llmClient *llm.Client,
	cache *reclassCache,
	ctx context.Context,
) coordinator.EvidenceCheckFunc {
	return func(pending *coordinator.PendingAlert) (bool, string) {
		method, path, host, statusCode := parseNormalizedLine(pending.NormalizedLine)
		if method == "" {
			log.Printf("[coordinator] Evidence check SKIP: no HTTP in normalized line key=%s normalized=%s",
				pending.Key, truncate(pending.NormalizedLine, 120))
			return false, ""
		}

		evidence := collector.Lookup(rec.LookupRequest{
			Method:          method,
			Path:            path,
			Host:            host,
			SourceContainer: pending.SourceName,
			StatusCode:      statusCode,
			Timestamp:       pending.Timestamp,
			Window:          5 * time.Second,
		})

		// --- Diagnostic: reveal WHY evidence check fails ---
		if evidence == nil || evidence.SafeBodyPreview == "" || evidence.Transport == nil {
			// Build diagnostic without panic on nil fields
			evStatus := "nil"
			evCandidates := 0
			hasTransport := false
			previewLen := 0
			evFormat := "n/a"
			if evidence != nil {
				evStatus = string(evidence.Status)
				evCandidates = evidence.CandidateCount
				hasTransport = evidence.Transport != nil
				previewLen = len(evidence.SafeBodyPreview)
				if evidence.Disclosure != nil {
					evFormat = string(evidence.Disclosure.Format)
				}
			}
			log.Printf("[coordinator] Evidence check MISS: key=%s lookup=%s/%s?status=%d candidates=%d transport=%v preview_len=%d format=%s status=%s",
				pending.Key, method, path, statusCode, evCandidates, hasTransport, previewLen, evFormat, evStatus)
			return false, ""
		}

		// Update pending with evidence info for logging
		pending.EvidenceResult = evidence
		pending.EvidenceJournal = evidence.ForJournal()

		// Determine classification
		classification := pending.Classification
		if classification == "" {
			if pending.Verdict == "deny" {
				classification = "malicious"
			} else {
				classification = "suspicious"
			}
		}

		// Check re-classification cache
		bodyHash := rec.HashBody([]byte(evidence.SafeBodyPreview))
		if cached, ok := cache.get(bodyHash); ok {
			if cached.downgraded {
				log.Printf("[reclassify] Cache hit (redacted_body=%s): downgraded → %s",
					bodyHash[:16], cached.reason)
			}
			return cached.downgraded, cached.reason
		}

		// Cache miss — call LLM
		reclass, err := llmClient.ReclassifyWithEvidence(
			ctx,
			classification,
			pending.Reason,
			pending.Line,
			evidence.Transport.StatusCode,
			evidence.Transport.ContentType,
			evidence.Transport.ContentLength,
			evidence.SafeBodyPreview,
		)
		if err != nil {
			log.Printf("[reclassify] Error: %v — not downgrading", err)
			return false, ""
		}

		cache.put(bodyHash, reclass.Downgraded, reclass.Reason)

		if reclass.Downgraded {
			log.Printf("[DOWNGRADED] Original=%s→%s Reason=%s",
				classification, reclass.Classification, reclass.Reason)
		}
		return reclass.Downgraded, reclass.Reason
	}
}

// =============================================================================
// Log Handler
// =============================================================================

// makeLogHandler creates the core pipeline handler that processes each log line.
func makeLogHandler(
	cfg Config,
	a *analyzer.Analyzer,
	collector rec.EvidenceCollector,
	alertCoordinator *coordinator.Coordinator,
	dispatch *notifier.Dispatcher,
) watcher.LogHandler {
	return func(line watcher.LogLine) {
		if cfg.ExcludeContainers[line.ContainerName] {
			return
		}

		evt := &event.Event{
			ID:         event.NewID(),
			SourceType: event.SourceDocker,
			SourceName: line.ContainerName,
			Line:       line.Line,
			Stream:     line.Stream,
			Timestamp:  line.Timestamp,
			Metadata: map[string]string{
				"container_id": line.ContainerID,
			},
		}

		result := a.Analyze(context.Background(), evt)

		buildAlert := func(severity notifier.Severity, evidence *rec.Evidence) notifier.Alert {
			return notifier.Alert{
				EventID:        evt.ID,
				Severity:       severity,
				ContainerID:    line.ContainerID,
				ContainerName:  line.ContainerName,
				LogLine:        evt.Line,
				NormalizedHash: evt.Hash,
				Reason:         result.Reason,
				MatchedVia:     result.Source,
				Classification: result.LLMClassification,
				Confidence:     result.LLMConfidence,
				Timestamp:      time.Now(),
				Evidence:       evidence,
			}
		}

		switch result.Verdict {
		case patternstore.VerdictAllow, patternstore.VerdictSuppress:
			return

		case patternstore.VerdictDeny, patternstore.VerdictAlert:
			method, path, _, statusCode := parseNormalizedLine(evt.NormalizedLine)
			isHTTP := method != ""

			severity := "malicious"
			notifSeverity := notifier.SeverityMalicious
			if result.Verdict == patternstore.VerdictAlert {
				severity = "suspicious"
				notifSeverity = notifier.SeveritySuspicious
			}

			if isHTTP && collector.Enabled() {
				correlationKey := fmt.Sprintf("%s|%s|%d", method, path, statusCode)

				alertBuilder := func() interface{} {
					evidence := collector.Lookup(rec.LookupRequest{
						Method:          method,
						Path:            path,
						SourceContainer: evt.SourceName,
						StatusCode:      statusCode,
						Timestamp:       evt.Timestamp,
						Window:          5 * time.Second,
					})
					return buildAlert(notifSeverity, evidence)
				}

				alertCoordinator.Process(correlationKey, &coordinator.PendingAlert{
					EventID:        evt.ID,
					ScopeKey:       evt.ScopeKey(),
					Reason:         result.Reason,
					MatchedVia:     result.Source,
					Hash:           evt.Hash,
					Line:           evt.Line,
					Verdict:        string(result.Verdict),
					Severity:       severity,
					Classification: result.LLMClassification,
					NormalizedLine: evt.NormalizedLine,
					SourceName:     evt.SourceName,
					Timestamp:      evt.Timestamp,
					BuildAlert:     alertBuilder,
				})
			} else {
				log.Printf("[ALERT] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s Line=%s",
					evt.ID, evt.ScopeKey(), result.Reason, result.Source, evt.Hash,
					truncate(evt.Line, 200))
				dispatch.Dispatch(context.Background(), buildAlert(notifSeverity, nil))
			}

		case patternstore.VerdictUnknown:
			if result.Source == "error" {
				log.Printf("[LLM_ERROR] Source=%s Line=%s", evt.ScopeKey(), truncate(evt.Line, 100))
			}
		}
	}
}

// =============================================================================
// Periodic Stats
// =============================================================================

func runPeriodicStats(ctx context.Context, a *analyzer.Analyzer, patterns *patternstore.Store, collector rec.EvidenceCollector) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.Persist(); err != nil {
				log.Printf("[observer] Failed to persist state: %v", err)
			}
			aStats := a.GetStats()
			pStats := patterns.GetStats()
			log.Printf("[observer] Pipeline: processed=%d pattern_hits=%d noise_suppressed=%d llm_calls=%d llm_errors=%d learned=%d",
				aStats.TotalProcessed, aStats.PatternHits, aStats.NoiseSuppressed, aStats.LLMCalls, aStats.LLMErrors, aStats.PatternsLearned)
			log.Printf("[observer] Patterns: hash=%d prefix=%d regex=%d contains=%d deny=%d alert=%d suppress=%d misses=%d",
				pStats.HashHits, pStats.PrefixHits, pStats.RegexHits, pStats.ContainsHits,
				pStats.DenyHits, pStats.AlertHits, pStats.SuppressHits, pStats.Misses)
			if collector.Enabled() {
				rStats := collector.Stats()
				log.Printf("[observer] REC: packets=%d http_req=%d http_resp=%d pair_misses=%d vxlan=%d vxlan_req=%d vxlan_resp=%d buf_entries=%d buf_bytes=%d",
					rStats.PacketsSeen, rStats.HTTPRequests, rStats.HTTPResponses, rStats.PairMisses,
					rStats.VXLANUnwrapped, rStats.VXLANHTTPReq, rStats.VXLANHTTPResp,
					rStats.BufferEntries, rStats.BufferBytes)
			}
		}
	}
}
