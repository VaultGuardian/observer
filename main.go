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
	"github.com/vaultguardian/observer/internal/api"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/notifier"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
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

	// ------- Init SQLite findings store -------
	db, err := store.Init(cfg.DataDir)
	if err != nil {
		log.Fatalf("[observer] Failed to init SQLite store: %v", err)
	}
	defer db.Close()

	llmClient := llm.NewClient(cfg.LLMURL, cfg.LLMModel, cfg.LLMAPIKey, cfg.Tier1Effort, cfg.Tier2Effort)
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

	// ------- Start Dashboard API -------
	apiServer, err := api.NewServer(
		api.ServerConfig{
			Port:    cfg.DashboardPort,
			KeyFile: cfg.DashboardKeyFile,
		},
		db, patterns, a, collector,
	)
	if err != nil {
		log.Printf("[observer] Dashboard API failed to start: %v (continuing without dashboard)", err)
	} else {
		go func() {
			if err := apiServer.Start(); err != nil {
				log.Printf("[observer] Dashboard API error: %v", err)
			}
		}()
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
	go runPeriodicStats(ctx, a, patterns, collector, db)

	// ------- Re-Classification Cache -------
	reclassCache := newReclassCache()

	// ------- Alert Coordinator -------
	alertCoordinator := coordinator.New(
		ctx,
		coordinator.DefaultConfig(),
		makeDispatchCallback(dispatch, db),
		makeEvidenceCheckCallback(collector, llmClient, reclassCache, ctx),
	)

	// ------- Log handler -------
	handler := makeLogHandler(cfg, a, collector, alertCoordinator, dispatch, db)

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
func makeDispatchCallback(dispatch *notifier.Dispatcher, db *store.Store) coordinator.DispatchFunc {
	return func(alert coordinator.FinalAlert) {
		if alert.Downgraded {
			log.Printf("[DOWNGRADED] EventID=%s key=%s events=%d Original→recon_failed Reason=%s",
				alert.EventID, alert.ScopeKey, alert.EventCount, alert.DowngradeReason)
			log.Printf("[INFO] EventID=%s Source=%s OriginalReason=%s DowngradedReason=%s %s Line=%s",
				alert.EventID, alert.ScopeKey, alert.Reason, alert.DowngradeReason,
				alert.EvidenceJournal, truncate(alert.Line, 200))

			// Record downgraded finding to SQLite
			db.RecordFinding(context.Background(), &store.Finding{
				EventID:         alert.EventID,
				Timestamp:       time.Now(),
				SourceType:      "docker",
				SourceName:      alert.ScopeKey,
				Verdict:         "downgraded",
				Classification:  alert.Severity,
				Reason:          alert.Reason,
				MatchedVia:      alert.MatchedVia,
				RawLine:         alert.Line,
				NormalizedHash:  alert.Hash,
				CoordinatorKey:  alert.ScopeKey,
				CoordinatorEvents: alert.EventCount,
				Downgraded:      true,
				DowngradeReason: alert.DowngradeReason,
				Notified:        false,
			})
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

		// Record dispatched alert to SQLite
		db.RecordFinding(context.Background(), &store.Finding{
			EventID:         alert.EventID,
			Timestamp:       time.Now(),
			SourceType:      "docker",
			SourceName:      alert.ScopeKey,
			Verdict:         alert.Verdict,
			Classification:  alert.Severity,
			Reason:          alert.Reason,
			MatchedVia:      alert.MatchedVia,
			RawLine:         alert.Line,
			NormalizedHash:  alert.Hash,
			CoordinatorKey:  alert.ScopeKey,
			CoordinatorEvents: alert.EventCount,
			Notified:        true,
		})
	}
}

// makeEvidenceCheckCallback creates the function called periodically by the
// coordinator to check if REC evidence can downgrade a pending alert.
//
// Two downgrade paths (design consensus, 2026-03-25):
//
//   Path 1 — Transport-only downgrade:
//     If REC captured the HTTP response and the status code is conclusively
//     "attack failed" (403/404/405/410), downgrade immediately.
//     No body preview required. No LLM call required.
//     These events are already known to contain attack payloads (they're in
//     the coordinator because they were classified as deny/alert). A 404 on
//     a SQL injection means the server rejected/ignored the payload. Period.
//
//   Path 2 — Body-aware re-classification:
//     For ambiguous status codes (200, 3xx, 5xx), the status alone doesn't
//     tell us if the attack succeeded. Check SafeBodyPreview and call the
//     LLM to inspect the actual response content.
//
// Status code tiers (design team agreed):
//   403, 404, 405, 410 → auto-downgrade (attack failed)
//   400                → ambiguous in v1, may add later
//   401                → surface discovery, not a failed probe
//   200, 3xx           → ambiguous, need body inspection
//   5xx                → suspicious, never auto-downgrade
func makeEvidenceCheckCallback(
	collector rec.EvidenceCollector,
	llmClient *llm.Client,
	cache *reclassCache,
	ctx context.Context,
) coordinator.EvidenceCheckFunc {
	// Status codes where transport alone proves the attack failed.
	// Only applies to payload-bearing events (which is all events
	// that reach the coordinator — clean probes are suppressed upstream).
	transportDowngradeCodes := map[int]bool{
		403: true, // Forbidden — server blocked the request
		404: true, // Not found — resource doesn't exist
		405: true, // Method not allowed — server rejected the method
		410: true, // Gone — resource permanently removed
	}

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
			ExpectedBytes:   extractResponseBytes(pending.Line),
		})

		// --- Path 1: Transport-only downgrade ---
		// If REC captured transport metadata and the status code is conclusive,
		// downgrade immediately. Don't need the body to know a 404 failed.
		if evidence != nil && evidence.Transport != nil {
			code := evidence.Transport.StatusCode
			if transportDowngradeCodes[code] {
				// Update evidence info for logging
				pending.EvidenceResult = evidence
				pending.EvidenceJournal = evidence.ForJournal()

				reason := fmt.Sprintf("Transport evidence confirms attack failed (HTTP %d) — payload was rejected/ignored by the server", code)
				log.Printf("[coordinator] Transport downgrade: key=%s status=%d candidates=%d",
					pending.Key, code, evidence.CandidateCount)
				return true, reason
			}
		}

		// --- Diagnostic: log why we can't downgrade yet ---
		if evidence == nil || evidence.Transport == nil {
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

		// --- Path 2: Body-aware re-classification ---
		// Status code is ambiguous (200, 3xx, 5xx). Need body to determine
		// if the attack actually succeeded.
		if evidence.SafeBodyPreview == "" {
			log.Printf("[coordinator] Evidence check: transport available (HTTP %d) but ambiguous status, no body preview — key=%s candidates=%d format=%s",
				evidence.Transport.StatusCode, pending.Key, evidence.CandidateCount,
				func() string {
					if evidence.Disclosure != nil {
						return string(evidence.Disclosure.Format)
					}
					return "n/a"
				}())
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
	db *store.Store,
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
			method, path, host, statusCode := parseNormalizedLine(evt.NormalizedLine)
			isHTTP := method != ""

			// --- Recon routing: log + store, no email ---
			// Reconnaissance (successful or failed) is telemetry, not an alert.
			// Record it to SQLite for trend analysis and dashboard queries.
			// No email, no coordinator, no notification.
			if result.LLMClassification == "recon_success" || result.LLMClassification == "recon_failed" {
				log.Printf("[RECON] EventID=%s Source=%s Classification=%s Reason=%s MatchedVia=%s Line=%s",
					evt.ID, evt.ScopeKey(), result.LLMClassification, result.Reason, result.Source,
					truncate(evt.Line, 200))

				db.RecordFinding(context.Background(), &store.Finding{
					EventID:        evt.ID,
					Timestamp:      evt.Timestamp,
					SourceType:     string(evt.SourceType),
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

			if isHTTP && collector.Enabled() {
				correlationKey := fmt.Sprintf("%s|%s|%d", method, canonicalPath(path), statusCode)

				alertBuilder := func() interface{} {
					evidence := collector.Lookup(rec.LookupRequest{
						Method:          method,
						Path:            path,
						SourceContainer: evt.SourceName,
						StatusCode:      statusCode,
						Timestamp:       evt.Timestamp,
						Window:          5 * time.Second,
						ExpectedBytes:   extractResponseBytes(evt.Line),
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

				// Record non-coordinator alert to SQLite
				db.RecordFinding(context.Background(), &store.Finding{
					EventID:        evt.ID,
					Timestamp:      evt.Timestamp,
					SourceType:     string(evt.SourceType),
					SourceName:     evt.SourceName,
					Verdict:        string(result.Verdict),
					Classification: result.LLMClassification,
					Confidence:     result.LLMConfidence,
					Reason:         result.Reason,
					MatchedVia:     result.Source,
					RawLine:        evt.Line,
					NormalizedLine: evt.NormalizedLine,
					NormalizedHash: evt.Hash,
					Notified:       true,
				})
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

func runPeriodicStats(ctx context.Context, a *analyzer.Analyzer, patterns *patternstore.Store, collector rec.EvidenceCollector, db *store.Store) {
	ticker := time.NewTicker(30 * time.Second)
	pruneTicker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	defer pruneTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pruneTicker.C:
			if err := db.Prune(ctx); err != nil {
				log.Printf("[store] Prune error: %v", err)
			}
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
				log.Printf("[observer] REC parse: req_prefix=%d req_fail=%d resp_prefix=%d resp_fail=%d",
					rStats.ReqPrefixHits, rStats.ReqParseFails, rStats.RespPrefixHits, rStats.RespParseFails)
			}

			// Record pipeline stats to SQLite
			db.RecordPipelineStats(ctx, &store.PipelineStats{
				Timestamp:       time.Now(),
				Processed:       aStats.TotalProcessed,
				PatternHits:     aStats.PatternHits,
				NoiseSuppressed: aStats.NoiseSuppressed,
				LLMCalls:        aStats.LLMCalls,
				LLMErrors:       aStats.LLMErrors,
				PatternsLearned: aStats.PatternsLearned,
				DenyCount:       pStats.DenyHits,
				AlertCount:      pStats.AlertHits,
				SuppressCount:   pStats.SuppressHits,
			})
		}
	}
}