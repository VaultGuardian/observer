// main.go
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync/atomic"
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
	"github.com/vaultguardian/observer/internal/policy"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
	"github.com/vaultguardian/observer/internal/watcher"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	var pipelineDrops atomic.Int64
	log.Println("[observer] VaultGuardian Observer starting...")

	// --- pprof ---
	go func() {
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			log.Printf("[observer] pprof server failed: %v", err)
		}
	}()

	cfg := LoadConfig()

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
	seedMaliciousPatterns(patterns)
	log.Printf("[observer] Pattern store initialized (%d scopes)", patterns.ScopeCount())

	// ------- Init SQLite findings store -------
	db, err := store.Init(cfg.DataDir)
	if err != nil {
		log.Fatalf("[observer] Failed to init SQLite store: %v", err)
	}
	defer db.Close()

	// ------- Init Policy Engine -------
	policyEngine := policy.New(db)

	llmClient := llm.NewClient(cfg.LLMURL, cfg.LLMModel, cfg.LLMAPIKey, cfg.Tier1Effort, cfg.Tier2Effort)
	llmScheduler := NewLLMScheduler(cfg.MaxConcurrentLLM)

	a := analyzer.New(normReg, patterns, llmClient, llmScheduler)
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

	// ------- Init Response Evidence Capture -------
	recCfg := rec.DefaultCollectorConfig()
	recCfg.Enabled = cfg.RECEnabled
	recCfg.DockerSocket = cfg.DockerSocket
	recCfg.Interface = cfg.RECInterface
	recCfg.VXLANPort = cfg.RECVXLANPort
	recCfg.NSContainer = cfg.RECNSContainer
	recCfg.Verbose = cfg.RECVerbose
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

	// ------- Fix 3: Start async findings writer -------
	db.StartAsyncWriter(ctx, 5000)

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

	// ------- LLM health check -------
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

	// ------- Re-Classification Cache -------
	reclassCache := newReclassCache()

	// ------- Self-Suppression Token Registry -------
	selfSuppress := coordinator.NewSelfSuppressor()

	// ------- Alert Coordinator -------
	alertCoordinator := coordinator.New(
		ctx,
		coordinator.DefaultConfig(),
		makeDispatchCallback(dispatch, db),
		makeEvidenceCheckCallback(collector, llmClient, reclassCache, db, cfg, llmScheduler, ctx),
		makeVerifyCallback(db, llmClient, selfSuppress, cfg, llmScheduler, ctx),
		selfSuppress,
	)

	// ------- Fix 1: Wire VIP push callback -------
	// When VIP evidence matches a malicious event, the collector fires this
	// callback. The coordinator immediately re-checks evidence for that
	// investigation, bypassing the polling cycle.
	collector.SetVIPCallback(func(correlationKey string) {
		alertCoordinator.TryResolveVIP(correlationKey)
	})

	// ------- Seed verified catch-alls from database -------
	seedCatchAllsFromDB(db, alertCoordinator)

	// ------- Ingestion Pipeline -------
	const pipelineBufferSize = 1000
	pipeline := make(chan watcher.LogLine, pipelineBufferSize)

	const retryQueueSize = 500
	retryQueue := make(chan *retryEvent, retryQueueSize)
	var retryQueueDrops atomic.Int64

	router := &resultRouter{
		cfg:              cfg,
		db:               db,
		collector:        collector,
		alertCoordinator: alertCoordinator,
		dispatch:         dispatch,
	}

	pipelineHandler := makeLogHandler(cfg, a, collector, alertCoordinator, db, router, retryQueue, &retryQueueDrops, policyEngine, dispatch)

	numWorkers := cfg.MaxConcurrentLLM * 2
	if numWorkers < 4 {
		numWorkers = 4
	}
	for i := 0; i < numWorkers; i++ {
		go func() {
			for line := range pipeline {
				pipelineHandler(line)
			}
		}()
	}

	numRetryWorkers := 2
	for i := 0; i < numRetryWorkers; i++ {
		go func() {
			for item := range retryQueue {
				result := a.AnalyzeRetry(ctx, item.evt)
				router.Route(item.evt, &result, item.line, "classify_retry")
			}
		}()
	}

	log.Printf("[observer] Pipeline ready: buffer=%d workers=%d retry_queue=%d retry_workers=%d llm_slots=%d",
		pipelineBufferSize, numWorkers, retryQueueSize, numRetryWorkers, cfg.MaxConcurrentLLM)

	// ------- Periodic persistence + stats -------
	go runPeriodicStats(ctx, a, patterns, collector, db, alertCoordinator, llmScheduler, policyEngine, &pipelineDrops, &retryQueueDrops)

	// ------- Fix 4: Evidence reconciler goroutine -------
	go runReconciler(ctx, db)

	// Ingestion handler
	ingestionHandler := func(line watcher.LogLine) {
		select {
		case pipeline <- line:
		default:
			pipelineDrops.Add(1)
			log.Println("[observer] WARNING: pipeline full — dropping log line")
		}
	}

	// ------- Start watching -------
	if _, err := os.Stat(cfg.DockerSocket); err == nil {
		w := watcher.New(cfg.DockerSocket, ingestionHandler)
		w.SetSelfID(cfg.SelfID)
		go func() {
			log.Println("[observer] Starting container log watcher...")
			if err := w.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[observer] Docker watcher error: %v", err)
			}
		}()
	} else {
		log.Printf("[observer] Docker socket %s not found — skipping container watcher", cfg.DockerSocket)
	}

	if cfg.JournaldEnabled {
		jw := watcher.NewJournaldWatcher(ingestionHandler, cfg.ExcludeUnits, "")
		go func() {
			log.Println("[observer] Starting journald watcher...")
			if err := jw.Run(ctx); err != nil && ctx.Err() == nil {
				log.Printf("[observer] Journald watcher error: %v", err)
			}
		}()
	}

	<-ctx.Done()

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

func makeDispatchCallback(dispatch *notifier.Dispatcher, db *store.Store) coordinator.DispatchFunc {
	return func(alert coordinator.FinalAlert) {
		if alert.Downgraded {
			log.Printf("[DOWNGRADED] EventID=%s key=%s events=%d Original→recon_failed Reason=%s",
				alert.EventID, alert.ScopeKey, alert.EventCount, alert.DowngradeReason)
			log.Printf("[INFO] EventID=%s Source=%s OriginalReason=%s DowngradedReason=%s %s Line=%s",
				alert.EventID, alert.ScopeKey, alert.Reason, alert.DowngradeReason,
				alert.EvidenceJournal, truncate(alert.Line, 200))

			// Fix 4: Set resolution status on downgraded findings
			now := time.Now()
			db.SubmitFinding(&store.Finding{
				EventID:           alert.EventID,
				Timestamp:         alert.Timestamp,
				SourceType:        alert.SourceType,
				SourceName:        alert.ScopeKey,
				DestHost:          alert.Host,
				HTTPMethod:        alert.HTTPMethod,
				HTTPPath:          alert.HTTPPath,
				HTTPStatus:        alert.StatusCode,
				ResponseBytes:     alert.ResponseBytes,
				Verdict:           "downgraded",
				Classification:    alert.Severity,
				Reason:            alert.Reason,
				MatchedVia:        alert.MatchedVia,
				RawLine:           alert.Line,
				NormalizedHash:    alert.Hash,
				CoordinatorKey:    alert.ScopeKey,
				CoordinatorEvents: alert.EventCount,
				Downgraded:        true,
				DowngradeReason:   alert.DowngradeReason,
				Notified:          false,
				ResolutionStatus:  "resolved",
				ResolvedAt:        &now,
				ResolutionMethod:  "rec_evidence",
				PreviousVerdict:   alert.Verdict,
			})
			return
		}

		if alert.Escalated {
			log.Printf("[ESCALATED] EventID=%s key=%s events=%d →%s Reason=%s",
				alert.EventID, alert.ScopeKey, alert.EventCount, alert.Severity, alert.EscalateReason)
			log.Printf("[INFO] EventID=%s Source=%s EscalatedReason=%s %s Line=%s",
				alert.EventID, alert.ScopeKey, alert.EscalateReason,
				alert.EvidenceJournal, truncate(alert.Line, 200))

			if alert.BuildAlert != nil {
				if builtAlert, ok := alert.BuildAlert().(notifier.Alert); ok {
					builtAlert.Severity = notifier.SeverityMalicious
					builtAlert.Reason = alert.EscalateReason
					dispatch.Dispatch(context.Background(), builtAlert)
				}
			}

			now := time.Now()
			db.SubmitFinding(&store.Finding{
				EventID:           alert.EventID,
				Timestamp:         alert.Timestamp,
				SourceType:        alert.SourceType,
				SourceName:        alert.ScopeKey,
				DestHost:          alert.Host,
				HTTPMethod:        alert.HTTPMethod,
				HTTPPath:          alert.HTTPPath,
				HTTPStatus:        alert.StatusCode,
				ResponseBytes:     alert.ResponseBytes,
				Verdict:           "malicious",
				Classification:    "malicious",
				Reason:            alert.EscalateReason,
				MatchedVia:        alert.MatchedVia,
				RawLine:           alert.Line,
				NormalizedHash:    alert.Hash,
				CoordinatorKey:    alert.ScopeKey,
				CoordinatorEvents: alert.EventCount,
				Notified:          true,
				ResolutionStatus:  "resolved",
				ResolvedAt:        &now,
				ResolutionMethod:  "rec_evidence",
				PreviousVerdict:   "alert",
			})
			return
		}

		if alert.BuildAlert == nil {
			return
		}

		severity := "ALERT"
		if alert.Severity == "suspicious" {
			severity = "SUSPICIOUS"
		}
		log.Printf("[%s] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s %s Line=%s",
			severity, alert.EventID, alert.ScopeKey, alert.Reason,
			alert.MatchedVia, alert.Hash, alert.EvidenceJournal, truncate(alert.Line, 200))

		// Fix 4: Non-resolved findings get "pending" resolution status
		db.SubmitFinding(&store.Finding{
			EventID:           alert.EventID,
			Timestamp:         alert.Timestamp,
			SourceType:        alert.SourceType,
			SourceName:        alert.ScopeKey,
			DestHost:          alert.Host,
			HTTPMethod:        alert.HTTPMethod,
			HTTPPath:          alert.HTTPPath,
			HTTPStatus:        alert.StatusCode,
			ResponseBytes:     alert.ResponseBytes,
			Verdict:           alert.Verdict,
			Classification:    alert.Severity,
			Reason:            alert.Reason,
			MatchedVia:        alert.MatchedVia,
			RawLine:           alert.Line,
			NormalizedHash:    alert.Hash,
			CoordinatorKey:    alert.ScopeKey,
			CoordinatorEvents: alert.EventCount,
			Notified:          false,
			ResolutionStatus:  "pending",
		})
	}
}

// makeEvidenceCheckCallback creates the function called periodically by the
// coordinator to check if REC evidence can downgrade a pending alert.
//
// Two downgrade paths (design consensus, 2026-03-25):
//   Path 1 — Transport-only downgrade (403/404/405/410)
//   Path 2 — Body-aware re-classification (200, 3xx, 5xx)
func makeEvidenceCheckCallback(
	collector rec.EvidenceCollector,
	llmClient *llm.Client,
	cache *reclassCache,
	db *store.Store,
	cfg Config,
	scheduler *LLMScheduler,
	ctx context.Context,
) coordinator.EvidenceCheckFunc {
	transportDowngradeCodes := map[int]bool{
		403: true, 404: true, 405: true, 410: true,
	}

	return func(pending *coordinator.PendingAlert) (bool, bool, string, string) {
		method, path, host, statusCode := parseNormalizedLine(pending.NormalizedLine)
		if method == "" {
			log.Printf("[coordinator] Evidence check SKIP: no HTTP in normalized line key=%s normalized=%s",
				pending.Key, truncate(pending.NormalizedLine, 120))
			return false, false, "", ""
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
		if evidence != nil && evidence.Transport != nil {
			// Phase 2 re-arm: populate BodyPreviewHash from REC evidence.
			// This was hardcoded empty at routing time (resultrouter.go) because
			// the hash only exists after REC captures the response. Now that
			// evidence has arrived, arm the field so catch-all can use it.
			if evidence.Transport.BodyPreviewHash != "" {
				pending.BodyPreviewHash = evidence.Transport.BodyPreviewHash
			}

			code := evidence.Transport.StatusCode
			if transportDowngradeCodes[code] {
				pending.EvidenceResult = evidence
				pending.EvidenceJournal = evidence.ForJournal()

				reason := fmt.Sprintf("Transport evidence confirms attack failed (HTTP %d) — payload was rejected/ignored by the server", code)
				log.Printf("[coordinator] Transport downgrade: key=%s status=%d candidates=%d",
					pending.Key, code, evidence.CandidateCount)
				return true, false, reason, ""
			}
		}

		// --- Diagnostic logging ---
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
			return false, false, "", ""
		}

		// --- Path 2: Body-aware re-classification ---
		if evidence.SafeBodyPreview == "" {
			log.Printf("[coordinator] Evidence check: transport available (HTTP %d) but ambiguous status, no body preview — key=%s candidates=%d format=%s",
				evidence.Transport.StatusCode, pending.Key, evidence.CandidateCount,
				func() string {
					if evidence.Disclosure != nil {
						return string(evidence.Disclosure.Format)
					}
					return "n/a"
				}())
			return false, false, "", ""
		}

		pending.EvidenceResult = evidence
		pending.EvidenceJournal = evidence.ForJournal()

		classification := pending.Classification
		if classification == "" {
			if pending.Verdict == "malicious" {
				classification = "malicious"
			} else {
				classification = "suspicious"
			}
		}

		bodyHash := rec.HashBody([]byte(evidence.SafeBodyPreview))
		if cached, ok := cache.get(bodyHash); ok {
			if cached.downgraded {
				log.Printf("[reclassify] Cache hit (redacted_body=%s): downgraded → %s",
					bodyHash[:16], cached.reason)
			} else if cached.escalated {
				log.Printf("[reclassify] Cache hit (redacted_body=%s): escalated → %s → %s",
					bodyHash[:16], cached.newSeverity, cached.reason)
			}
			return cached.downgraded, cached.escalated, cached.reason, cached.newSeverity
		}

		release, ok := scheduler.AcquireBlocking(ctx)
		if !ok {
			log.Printf("[reclassify] Context cancelled waiting for LLM slot")
			return false, false, "", ""
		}
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
		release()
		if err != nil {
			log.Printf("[reclassify] Error: %v — not changing verdict", err)
			return false, false, "", ""
		}

		cache.put(bodyHash, reclass.Downgraded, reclass.Escalated, reclass.Reason, reclass.Classification)

		db.RecordLLMDecision(context.Background(), &store.LLMDecision{
			EventID:          pending.EventID,
			Timestamp:        time.Now(),
			Tier:             "reclassify",
			Model:            cfg.LLMModel,
			ReasoningEffort:  cfg.Tier2Effort,
			PromptTokens:     reclass.PromptTokens,
			CompletionTokens: reclass.CompletionTokens,
			LatencyMs:        reclass.LatencyMs,
			SourceScope:      pending.ScopeKey,
			RawLine:          pending.Line,
			NormalizedLine:   pending.NormalizedLine,
			EvidencePreview:  evidence.SafeBodyPreview,
			EvidenceStatus:   evidence.Transport.StatusCode,
			EvidenceType:     evidence.Transport.ContentType,
			EvidenceHash:     evidence.Transport.BodyPreviewHash,
			LLMResponseRaw:   reclass.ResponseRaw,
			Classification:   reclass.Classification,
			Action:           reclass.Action,
			Confidence:       reclass.Confidence,
			Reason:           reclass.Reason,
			CacheKey:         bodyHash,
			FinalVerdict:     reclass.Classification,
			Escalated:        reclass.Escalated,
			Downgraded:       reclass.Downgraded,
		})

		if reclass.Downgraded {
			log.Printf("[DOWNGRADED] Original=%s→%s Reason=%s",
				classification, reclass.Classification, reclass.Reason)
		} else if reclass.Escalated {
			log.Printf("[ESCALATED] Original=%s→%s Reason=%s",
				classification, reclass.Classification, reclass.Reason)
		}
		return reclass.Downgraded, reclass.Escalated, reclass.Reason, reclass.Classification
	}
}

// =============================================================================
// Catch-All Verification Callback
// =============================================================================

func makeVerifyCallback(
	db *store.Store,
	llmClient *llm.Client,
	selfSuppress *coordinator.SelfSuppressor,
	cfg Config,
	scheduler *LLMScheduler,
	ctx context.Context,
) coordinator.VerifyFunc {

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpsClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return func(req coordinator.VerifyRequest) *coordinator.VerifyResult {
		fp := req.Fingerprint
		path := req.SamplePath
		if path == "" {
			return &coordinator.VerifyResult{Confirmed: false, Reason: "no sample path available"}
		}

		log.Printf("[verify] Starting verification: host=%s method=%s status=%d hash=%.16s path=%s",
			fp.Host, fp.Method, fp.StatusCode, fp.BodyPreviewHash, path)

		userAgent, _ := selfSuppress.GenerateToken()

		schemes := []struct {
			scheme string
			client *http.Client
		}{
			{"http", httpClient},
			{"https", httpsClient},
		}

		for _, s := range schemes {
			url := fmt.Sprintf("%s://127.0.0.1%s", s.scheme, path)

			httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				log.Printf("[verify] Failed to create request: %v", err)
				continue
			}
			httpReq.Host = fp.Host
			httpReq.Header.Set("User-Agent", userAgent)

			resp, err := s.client.Do(httpReq)
			if err != nil {
				log.Printf("[verify] %s request failed: %v", s.scheme, err)
				continue
			}

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyLen := int64(len(body))
			contentType := resp.Header.Get("Content-Type")

			// Fix 2: Match by body hash, not response bytes.
			bodyHash := rec.HashBody(body)

			if resp.StatusCode != fp.StatusCode {
				log.Printf("[verify] Status mismatch: expected=%d got=%d (scheme=%s)",
					fp.StatusCode, resp.StatusCode, s.scheme)
				continue
			}

			// Fix 2: Compare body preview hash instead of response bytes
			if bodyHash != fp.BodyPreviewHash {
				log.Printf("[verify] Body hash mismatch: expected=%.16s got=%.16s (scheme=%s)",
					fp.BodyPreviewHash, bodyHash, s.scheme)
				continue
			}

			log.Printf("[verify] Response matched: scheme=%s status=%d bytes=%d hash=%.16s",
				s.scheme, resp.StatusCode, bodyLen, bodyHash)

			// Redact the body using existing REC pipeline
			disclosure := rec.ClassifyAndRedact(body, contentType)
			safePreview := disclosure.RedactedPreview()

			if safePreview == "" {
				if bodyLen <= 200 {
					safePreview = string(body)
				} else if bodyLen <= 2048 {
					reason := fmt.Sprintf("Verified: %s %d response (%d bytes), format=%s, body hash %.16s, consistent across %d+ paths",
						s.scheme, resp.StatusCode, bodyLen, disclosure.Format, bodyHash, coordinator.DefaultCatchAllThreshold)
					result := &coordinator.VerifyResult{
						Confirmed:   true,
						Reason:      reason,
						ContentType: contentType,
						BodyHash:    bodyHash,
					}
					persistVerifiedCatchAll(db, ctx, fp, path, result, contentType)
					return result
				} else {
					return &coordinator.VerifyResult{Confirmed: false, Reason: "redaction failed on large body — cannot verify safety"}
				}
			}

			// LLM re-classification
			release, acquired := scheduler.AcquireBlocking(ctx)
			if !acquired {
				return &coordinator.VerifyResult{Confirmed: false, Reason: "context cancelled waiting for LLM slot"}
			}
			reclass, err := llmClient.ReclassifyWithEvidence(ctx,
				"suspicious",
				"Catch-all verification probe",
				fmt.Sprintf("GET %s → %d", path, resp.StatusCode),
				resp.StatusCode, contentType, bodyLen, safePreview,
			)
			release()

			if err != nil {
				log.Printf("[verify] LLM error: %v — not confirming", err)
				return &coordinator.VerifyResult{Confirmed: false, Reason: fmt.Sprintf("LLM error: %v", err)}
			}

			db.RecordLLMDecision(context.Background(), &store.LLMDecision{
				Timestamp:        time.Now(),
				Tier:             "catchall_verify",
				Model:            cfg.LLMModel,
				ReasoningEffort:  cfg.Tier2Effort,
				PromptTokens:     reclass.PromptTokens,
				CompletionTokens: reclass.CompletionTokens,
				LatencyMs:        reclass.LatencyMs,
				SourceScope:      fp.Host,
				RawLine:          fmt.Sprintf("GET %s → %d", path, resp.StatusCode),
				EvidencePreview:  safePreview,
				EvidenceStatus:   resp.StatusCode,
				EvidenceType:     contentType,
				EvidenceHash:     bodyHash,
				LLMResponseRaw:   reclass.ResponseRaw,
				Classification:   reclass.Classification,
				Action:           reclass.Action,
				Confidence:       reclass.Confidence,
				Reason:           reclass.Reason,
				CacheKey:         bodyHash,
				FinalVerdict:     reclass.Classification,
				Downgraded:       reclass.Downgraded,
			})

			if reclass.Downgraded {
				reason := fmt.Sprintf("LLM confirmed benign: %s", reclass.Reason)
				result := &coordinator.VerifyResult{
					Confirmed:   true,
					Reason:      reason,
					ContentType: contentType,
					BodyHash:    bodyHash,
				}
				persistVerifiedCatchAll(db, ctx, fp, path, result, contentType)
				return result
			}

			reason := fmt.Sprintf("LLM rejected: %s (classification=%s)", reclass.Reason, reclass.Classification)
			log.Printf("[verify] LLM rejected catch-all: %s", reason)
			return &coordinator.VerifyResult{Confirmed: false, Reason: reason}
		}

		return &coordinator.VerifyResult{
			Confirmed: false,
			Reason:    "all verification attempts failed (both HTTP and HTTPS)",
		}
	}
}

// persistVerifiedCatchAll saves a confirmed catch-all to SQLite.
// Fix 2: Uses BodyPreviewHash instead of ResponseBytes.
func persistVerifiedCatchAll(db *store.Store, ctx context.Context, fp coordinator.CatchAllFingerprint, path string, result *coordinator.VerifyResult, contentType string) {
	err := db.SaveVerifiedCatchAll(ctx, &store.CatchAllRule{
		Host:                fp.Host,
		HTTPMethod:          fp.Method,
		HTTPStatus:          fp.StatusCode,
		BodyPreviewHash:     fp.BodyPreviewHash,
		VerifiedAt:          time.Now(),
		SamplePath:          path,
		ContentType:         contentType,
		BodyHash:            result.BodyHash,
		VerificationVerdict: "benign",
		VerificationReason:  result.Reason,
	})
	if err != nil {
		log.Printf("[verify] Failed to persist verified catch-all: %v", err)
	} else {
		log.Printf("[verify] Persisted verified catch-all: host=%s method=%s status=%d hash=%.16s",
			fp.Host, fp.Method, fp.StatusCode, fp.BodyPreviewHash)
	}
}

// seedCatchAllsFromDB loads previously verified catch-all fingerprints.
// Fix 2: Seeds with BodyPreviewHash instead of ResponseBytes.
func seedCatchAllsFromDB(db *store.Store, coord *coordinator.Coordinator) {
	rules, err := db.LoadVerifiedCatchAlls(context.Background())
	if err != nil {
		log.Printf("[observer] Failed to load catch-all seeds: %v (continuing without pre-warm)", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	fps := make([]coordinator.CatchAllFingerprint, len(rules))
	reasons := make([]string, len(rules))
	for i, r := range rules {
		fps[i] = coordinator.CatchAllFingerprint{
			Host:            r.Host,
			Method:          r.HTTPMethod,
			StatusCode:      r.HTTPStatus,
			BodyPreviewHash: r.BodyPreviewHash,
		}
		reasons[i] = r.VerificationReason
	}

	coord.CatchAllTracker().SeedVerified(fps, reasons)
}

// =============================================================================
// Policy Outcome Routing
// =============================================================================

func routePolicyOutcome(evt *event.Event, pr policy.Result, dispatch *notifier.Dispatcher, db *store.Store) {
	switch pr.Action {
	case "allow":
		log.Printf("[POLICY:ALLOW] EventID=%s rule=%s ip=%s user=%s reason=%s",
			evt.ID, pr.RuleID, pr.SourceIP, pr.Username, pr.Reason)

	case "alert":
		log.Printf("[POLICY:ALERT] EventID=%s rule=%s ip=%s user=%s reason=%s",
			evt.ID, pr.RuleID, pr.SourceIP, pr.Username, pr.Reason)

		db.SubmitFinding(&store.Finding{
			EventID:        evt.ID,
			Timestamp:      evt.Timestamp,
			SourceType:     evt.SourceType,
			SourceName:     evt.SourceName,
			SourceIP:       pr.SourceIP,
			Verdict:        "alert",
			Classification: "policy_alert",
			Confidence:     1.0,
			Reason:         pr.Reason,
			MatchedVia:     "policy:" + pr.RuleID,
			RawLine:        evt.Line,
			Notified:       false,
		})

	case "escalate":
		log.Printf("[POLICY:ESCALATE] EventID=%s rule=%s ip=%s user=%s reason=%s",
			evt.ID, pr.RuleID, pr.SourceIP, pr.Username, pr.Reason)

		db.SubmitFinding(&store.Finding{
			EventID:        evt.ID,
			Timestamp:      evt.Timestamp,
			SourceType:     evt.SourceType,
			SourceName:     evt.SourceName,
			SourceIP:       pr.SourceIP,
			Verdict:        "malicious",
			Classification: "policy_escalated",
			Confidence:     1.0,
			Reason:         pr.Reason,
			MatchedVia:     "policy:" + pr.RuleID,
			RawLine:        evt.Line,
			Notified:       true,
		})

		alert := notifier.Alert{
			EventID:        evt.ID,
			Severity:       notifier.SeverityMalicious,
			ContainerID:    "",
			ContainerName:  evt.SourceName,
			LogLine:        evt.Line,
			Reason:         pr.Reason,
			MatchedVia:     "policy:" + pr.RuleID,
			Classification: "policy_escalated",
			Confidence:     1.0,
			Timestamp:      evt.Timestamp,
		}
		dispatch.Dispatch(context.Background(), alert)
	}
}

// =============================================================================
// Log Handler
// =============================================================================

type retryEvent struct {
	evt  *event.Event
	line watcher.LogLine
}

func makeLogHandler(
	cfg Config,
	a *analyzer.Analyzer,
	collector rec.EvidenceCollector,
	alertCoordinator *coordinator.Coordinator,
	db *store.Store,
	router *resultRouter,
	retryQueue chan *retryEvent,
	retryQueueDrops *atomic.Int64,
	policyEngine *policy.Engine,
	dispatch *notifier.Dispatcher,
) watcher.LogHandler {
	return func(line watcher.LogLine) {
		if cfg.ExcludeContainers[line.ContainerName] {
			return
		}

		if alertCoordinator.SelfSuppressor().IsSelfVerify(line.Line) {
			return
		}

		sourceType := line.SourceType
		sourceName := line.SourceName
		metadata := line.Metadata
		if sourceType == "" {
			sourceType = event.SourceDocker
			sourceName = line.ContainerName
			metadata = map[string]string{
				"container_id": line.ContainerID,
			}
		}

		evt := &event.Event{
			ID:          event.NewID(),
			SourceType:  sourceType,
			SourceName:  sourceName,
			Line:        line.Line,
			Stream:      line.Stream,
			Timestamp:   line.Timestamp,
			ProcessedAt: time.Now(),
			Metadata:    metadata,
		}

		// Policy engine — deterministic pre-LLM layer
		if pr := policyEngine.Evaluate(evt); pr.Matched {
			routePolicyOutcome(evt, pr, dispatch, db)
			return
		}

		result := a.Analyze(context.Background(), evt)

		if result.Source == "backpressure" {
			select {
			case retryQueue <- &retryEvent{evt: evt, line: line}:
				log.Printf("[observer] Deferred to retry queue: %s %s", evt.ScopeKey(), truncate(evt.NormalizedLine, 80))
			default:
				retryQueueDrops.Add(1)
				log.Println("[observer] WARNING: retry queue full — truly dropping unknown event")
			}
			return
		}

		router.Route(evt, &result, line, "classify")
	}
}

// =============================================================================
// Fix 4: Evidence Reconciler
// =============================================================================
//
// Background goroutine that finalizes stale malicious HTTP findings as
// "evidence_unavailable" after a bounded window. Never auto-downgrades —
// just stamps the terminal state so the dashboard can distinguish
// "confirmed malicious, outcome unknown" from "evidence attempted but missed."
//
// Runs every 60 seconds. Processes findings older than 15 minutes.
// Append-only: preserves original verdict, adds resolution metadata.

func runReconciler(ctx context.Context, db *store.Store) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	log.Println("[reconciler] Evidence reconciler started (window=15m, interval=60s)")

	for {
		select {
		case <-ctx.Done():
			log.Println("[reconciler] Shutting down")
			return
		case <-ticker.C:
			findings, err := db.QueryUnresolvedMalicious(ctx, 15*time.Minute, 50)
			if err != nil {
				log.Printf("[reconciler] Query error: %v", err)
				continue
			}

			if len(findings) == 0 {
				continue
			}

			finalized := 0
			for _, f := range findings {
				err := db.UpdateFindingResolution(ctx, f.EventID, "evidence_unavailable", "timeout", "")
				if err != nil {
					log.Printf("[reconciler] Failed to finalize %s: %v", f.EventID, err)
					continue
				}
				finalized++
			}

			if finalized > 0 {
				log.Printf("[reconciler] Finalized %d findings as evidence_unavailable", finalized)
			}
		}
	}
}

// =============================================================================
// Periodic Stats
// =============================================================================

func runPeriodicStats(ctx context.Context, a *analyzer.Analyzer, patterns *patternstore.Store, collector rec.EvidenceCollector, db *store.Store, coord *coordinator.Coordinator, scheduler *LLMScheduler, policyEngine *policy.Engine, pipelineDrops *atomic.Int64, retryQueueDrops *atomic.Int64) {
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
			llmTotal, llmDropped := scheduler.Stats()
			drops := pipelineDrops.Load()
			retryDrops := retryQueueDrops.Load()
			asyncDrops := db.AsyncWriterStats() // Fix 3: async writer drops
			log.Printf("[observer] Pipeline: processed=%d pattern_hits=%d noise_suppressed=%d llm_calls=%d llm_errors=%d learned=%d deferred=%d retried=%d retry_pattern=%d llm_sched_total=%d llm_sched_dropped=%d pipeline_drops=%d retry_drops=%d async_drops=%d",
				aStats.TotalProcessed, aStats.PatternHits, aStats.NoiseSuppressed, aStats.LLMCalls, aStats.LLMErrors, aStats.PatternsLearned,
				aStats.LLMDropped, aStats.Retried, aStats.RetriedPatternHit, llmTotal, llmDropped, drops, retryDrops, asyncDrops)
			log.Printf("[observer] Patterns: hash=%d prefix=%d regex=%d contains=%d malicious=%d alert=%d suppress=%d misses=%d",
				pStats.HashHits, pStats.PrefixHits, pStats.RegexHits, pStats.ContainsHits,
				pStats.MaliciousHits, pStats.AlertHits, pStats.SuppressHits, pStats.Misses)
			if collector.Enabled() {
				rStats := collector.Stats()
				log.Printf("[observer] REC: packets=%d http_req=%d http_resp=%d pair_misses=%d vxlan=%d vxlan_req=%d vxlan_resp=%d buf_entries=%d buf_bytes=%d vip_matches=%d",
					rStats.PacketsSeen, rStats.HTTPRequests, rStats.HTTPResponses, rStats.PairMisses,
					rStats.VXLANUnwrapped, rStats.VXLANHTTPReq, rStats.VXLANHTTPResp,
					rStats.BufferEntries, rStats.BufferBytes, rStats.VIPMatches)
				log.Printf("[observer] REC parse: req_prefix=%d req_fail=%d resp_prefix=%d resp_fail=%d",
					rStats.ReqPrefixHits, rStats.ReqParseFails, rStats.RespPrefixHits, rStats.RespParseFails)
			}

			caTotal, caCandidates, caPending, caVerified, caRejected, caSuppressed := coord.CatchAllStats()
			if caTotal > 0 {
				log.Printf("[observer] CatchAll: fingerprints=%d candidates=%d pending=%d verified=%d rejected=%d suppressed=%d",
					caTotal, caCandidates, caPending, caVerified, caRejected, caSuppressed)
			}

			policyMatches, policyEscalations, policyAllows, policyAlerts := policyEngine.Stats()
			if policyMatches > 0 {
				log.Printf("[observer] Policy: matches=%d escalations=%d allows=%d alerts=%d",
					policyMatches, policyEscalations, policyAllows, policyAlerts)
			}

			db.RecordPipelineStats(ctx, &store.PipelineStats{
				Timestamp:       time.Now(),
				Processed:       aStats.TotalProcessed,
				PatternHits:     aStats.PatternHits,
				NoiseSuppressed: aStats.NoiseSuppressed,
				LLMCalls:        aStats.LLMCalls,
				LLMErrors:       aStats.LLMErrors,
				PatternsLearned: aStats.PatternsLearned,
				MaliciousCount:  pStats.MaliciousHits,
				AlertCount:      pStats.AlertHits,
				SuppressCount:   pStats.SuppressHits,
			})
		}
	}
}