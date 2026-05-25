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

// Version is set at build time via ldflags:
//
//	go build -ldflags "-X main.Version=v0.52.0" -o observer .
var Version = "dev"

func main() {
	// --- Version flag ---
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Printf("observer %s\n", Version)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	var pipelineDrops atomic.Int64
	log.Println("[observer] VaultGuardian Observer starting...")

	// --- pprof (debug only) ---
	// v0.52: gated behind OBSERVER_DEBUG=1. pprof exposes sensitive runtime
	// data (goroutine stacks, heap profiles, symbol tables) and should not
	// be unconditionally available, even on localhost.
	if os.Getenv("OBSERVER_DEBUG") == "1" {
		go func() {
			log.Println("[observer] pprof enabled on localhost:6060 (OBSERVER_DEBUG=1)")
			if err := http.ListenAndServe("localhost:6060", nil); err != nil {
				log.Printf("[observer] pprof server failed: %v", err)
			}
		}()
	}

	cfg := LoadConfig()

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		log.Fatalf("[observer] Failed to create data dir: %v", err)
	}
	// v0.52: MkdirAll won't tighten permissions on an existing directory.
	// Explicit Chmod ensures dirs created by older versions (0755) get fixed.
	if err := os.Chmod(cfg.DataDir, 0700); err != nil {
		log.Fatalf("[observer] Failed to chmod data dir: %v", err)
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
	recCfg.Ports = cfg.RECPorts
	recCfg.LearnedPortCap = cfg.RECLearnedPortCap
	// Effective byte ceiling is the tighter of the two memory knobs:
	// REC_BUFFER_MAX_BYTES (legacy) and REC_BUFFER_MAX_MB (preferred dial).
	// BufferConfig stays oblivious to the MB-vs-bytes distinction.
	maxBytes := cfg.RECBufferMaxBytes
	if mbCap := int64(cfg.RECBufferMaxMB) * 1024 * 1024; mbCap > 0 && mbCap < maxBytes {
		maxBytes = mbCap
	}
	recCfg.Buffer = rec.BufferConfig{
		MaxEntries:    cfg.RECBufferMaxEntries,
		MaxTotalBytes: maxBytes,
		MaxAge:        cfg.RECBufferMaxAge,
		MaxBodyBytes:  cfg.RECBufferMaxBody,
	}
	recCfg.Reassembly = rec.ReassemblyConfig{
		MaxBody:                 cfg.RECReassemblyMaxBody,
		StreamTTL:               cfg.RECReassemblyStreamTTL,
		IdleTimeout:             cfg.RECReassemblyIdleTimeout,
		MaxBufferedPagesTotal:   cfg.RECReassemblyMaxBufferedPagesTotal,
		MaxBufferedPagesPerConn: cfg.RECReassemblyMaxBufferedPagesPerConn,
		MaxActiveStreams:        cfg.RECReassemblyMaxActiveStreams,
	}
	recCfg.Flow = rec.FlowConfig{
		MaxFlowStates:         cfg.RECFlowMaxStates,
		MaxRequestsPerFlow:    cfg.RECFlowMaxReqPerFlow,
		MaxResponsesPerFlow:   cfg.RECFlowMaxRespPerFlow,
		ResponseOrphanTimeout: cfg.RECFlowRespOrphanTimeout,
		RequestExpireTimeout:  cfg.RECFlowReqExpireTimeout,
	}
	collector := rec.NewCollector(recCfg)

	// Wire REC evidence pre-pinning into the analyzer.
	// When the analyzer hits a pattern-store miss (event entering LLM path),
	// it calls this to promote any matching ring buffer evidence to VIP
	// before LLM queue delay can cause eviction. Parses HTTP identity the
	// same way routeAlert() does — raw path for REC, normalized host.
	a.SetPrePinFunc(func(evt *event.Event) {
		if !collector.Enabled() {
			return
		}

		nMethod, nPath, nHost, nStatus := parseNormalizedLine(evt.NormalizedLine)
		rMethod, rPath, _, rStatus := parseRawHTTPLine(evt.Line)

		method := rMethod
		if method == "" {
			method = nMethod
		}

		rawPath := rPath
		if rawPath == "" {
			rawPath = nPath
		}

		statusCode := rStatus
		if statusCode == 0 {
			statusCode = nStatus
		}

		if method == "" || rawPath == "" {
			return // non-HTTP event, no REC evidence to pin
		}

		collector.PrePin(evt.ID, rec.LookupRequest{
			Method:          method,
			Path:            rawPath,
			Host:            nHost,
			SourceContainer: evt.SourceName,
			StatusCode:      statusCode,
			Timestamp:       evt.Timestamp,
			Window:          10 * time.Second,
			ExpectedBytes:   extractResponseBytes(evt.Line),
		})
	})

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
			Port:           cfg.DashboardPort,
			KeyFile:        cfg.DashboardKeyFile,
			BindAddr:       cfg.DashboardBindAddr,
			AllowedOrigins: cfg.DashboardAllowedOrigins,
			Version:        Version,
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

	// ------- ExpectedEndpoint Tracker (v1.0 Card 4) -------
	// Built BEFORE the coordinator and evidence callback because both need
	// access (evidence callback for the hot-path Check, API server for
	// SeedVerified + Stats via the correction handler). The tracker lives
	// in main.go's lifecycle, not inside the coordinator — the coordinator
	// itself never invokes Check(); the check runs inside the evidence
	// callback after redaction so it can short-circuit reclass cache + LLM
	// using the redacted shape hash. (Design lock-in, May 11 2026.)
	expectedEndpointTracker := coordinator.NewExpectedEndpointTracker(coordinator.DefaultExpectedEndpointCap)
	seedExpectedEndpointsFromDB(db, expectedEndpointTracker)

	// ------- Alert Coordinator -------
	alertCoordinator := coordinator.New(
		ctx,
		coordinator.DefaultConfig(),
		makeDispatchCallback(dispatch, db),
		makeEvidenceCheckCallback(collector, llmClient, reclassCache, db, cfg, llmScheduler, ctx, expectedEndpointTracker),
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

	// ------- Wire human correction callbacks -------
	// The API server needs to reach the coordinator's catch-all tracker and
	// the reclass cache for human corrections. We pass narrow callbacks
	// instead of the full objects to avoid coupling.
	//
	// Section 3 / Landmine A: seedCatchAll now takes responseBytes from the
	// finding. Human-confirmed entries with responseBytes=0 will be skipped
	// by the byte-aware fallback (conservative — they'll still match exact
	// body-hash via Check(), just not the byte-similarity Phase 3 path).
	//
	// v1.0 Card 4: seedExpectedEndpoint wires the new path-scoped tracker.
	// Signature includes http_status (P1 lock-in). bodyHash here is the
	// REDACTED shape hash (decision.CacheKey on the API side), NEVER the
	// raw transport hash. expectedEndpointStats exposes tracker counters
	// to /api/stats without forcing the API server to import the tracker
	// type.
	if apiServer != nil {
		apiServer.SetCorrectionCallbacks(
			// Invalidate reclass cache entry
			func(bodyHash string) {
				reclassCache.delete(bodyHash)
			},
			// Seed a verified catch-all fingerprint (live, no restart needed)
			func(host, method string, status int, bodyHash, reason string, responseBytes int64) {
				fps := []coordinator.CatchAllFingerprint{{
					Host:            host,
					Method:          method,
					StatusCode:      status,
					BodyPreviewHash: bodyHash,
				}}
				alertCoordinator.CatchAllTracker().SeedVerified(fps, []string{reason}, []int64{responseBytes})
			},
			// v1.0 Card 4: Seed an expected-endpoint fingerprint (live).
			// bodyHash is the REDACTED shape hash; the API handler reads it
			// from decision.CacheKey before calling this.
			func(host, method string, status int, path, bodyHash, reason string) {
				fps := []coordinator.ExpectedEndpointFingerprint{{
					Host:            host,
					Method:          method,
					Path:            path,
					Status:          status,
					BodyPreviewHash: bodyHash,
				}}
				expectedEndpointTracker.SeedVerified(fps, []string{reason})
			},
			// v1.0 Card 4: Expose tracker counters for /api/stats
			func() (total int, suppressed int64) {
				return expectedEndpointTracker.Stats()
			},
		)

		// Notifier dispatcher counters → /api/stats and the periodic log
		// line. Same nil guard as the correction callbacks above: when
		// api.NewServer failed we logged "continuing without dashboard"
		// and apiServer is nil here.
		apiServer.SetNotifierStatsCallback(func() (dropped int64, channels int) {
			return dispatch.DroppedCount(), dispatch.ChannelCount()
		})
	}

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
	go runPeriodicStats(ctx, a, patterns, collector, db, alertCoordinator, llmScheduler, policyEngine, &pipelineDrops, &retryQueueDrops, dispatch)

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
			for ctx.Err() == nil {
				if err := w.Run(ctx); err != nil && ctx.Err() == nil {
					log.Printf("[observer] Docker watcher error: %v — restarting in 2s", err)
					time.Sleep(2 * time.Second)
				}
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

	// ------- Ordered Shutdown -------
	// v0.52: Proper shutdown ordering prevents data loss and races.
	// Sequence: stop API (drain in-flight requests) → persist patterns
	// → close DB (stops async writer, then closes SQLite).
	log.Println("[observer] Shutting down...")

	// 1. Stop API server — no new requests accepted, in-flight get 5s to finish.
	if apiServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := apiServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[observer] API server shutdown error: %v", err)
		}
		shutdownCancel()
	}

	// 2. Stop notifier dispatcher — drain queued alerts up to 3s, then drop.
	if dispatch != nil {
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 3*time.Second)
		dispatch.Stop(drainCtx)
		drainCancel()
	}

	// 3. Persist pattern store to disk.
	if err := a.Persist(); err != nil {
		log.Printf("[observer] Failed final persist: %v", err)
	}

	// 4. Close DB — stops async findings writer (drains queue), then closes SQLite.
	if err := db.Close(); err != nil {
		log.Printf("[observer] DB close error: %v", err)
	}

	aStats := a.GetStats()
	log.Printf("[observer] Final stats: processed=%d pattern_hits=%d noise_suppressed=%d llm_calls=%d learned=%d",
		aStats.TotalProcessed, aStats.PatternHits, aStats.NoiseSuppressed, aStats.LLMCalls, aStats.PatternsLearned)
	log.Println("[observer] Shutdown complete")
}

// =============================================================================
// Coordinator Callbacks
// =============================================================================

// evidenceFields extracts the persistence fields from a coordinator-attached
// rec.Evidence value. Returns zero values when evidence is missing or the
// transport layer is absent. Used to populate finding rows so the dashboard
// correction workflow has body hash + transport metadata to work with.
//
// Section 3 follow-up: coordinator findings used to
// drop these fields, leaving the correction endpoint to fall back to the
// LLMDecision table — which doesn't exist for every finding, especially
// catch-all auto-downgrades that never invoke the LLM.
func evidenceFields(e interface{}) (status string, code int, contentType string, bodyHash string, mode string) {
	ev, ok := e.(*rec.Evidence)
	if !ok || ev == nil {
		return "", 0, "", "", ""
	}
	status = string(ev.Status)
	if ev.Transport != nil {
		code = ev.Transport.StatusCode
		contentType = ev.Transport.ContentType
		bodyHash = ev.Transport.BodyPreviewHash
		mode = ev.Transport.CaptureMode
	}
	return
}

func makeDispatchCallback(dispatch *notifier.Dispatcher, db *store.Store) coordinator.DispatchFunc {
	return func(alert coordinator.FinalAlert) {
		// Extract evidence fields once per dispatch — used by all three
		// finding-write branches below.
		evStatus, evCode, evCT, evHash, evMode := evidenceFields(alert.Evidence)

		if alert.Downgraded {
			log.Printf("[DOWNGRADED] EventID=%s key=%s events=%d Original→recon_failed Reason=%s",
				alert.EventID, alert.Key, alert.EventCount, alert.DowngradeReason)
			log.Printf("[INFO] EventID=%s Source=%s OriginalReason=%s DowngradedReason=%s %s Line=%s",
				alert.EventID, alert.ScopeKey, alert.Reason, alert.DowngradeReason,
				alert.EvidenceJournal, truncate(alert.Line, 200))

			// Fix 4: Set resolution status on downgraded findings
			now := time.Now()
			db.SubmitFinding(&store.Finding{
				EventID:              alert.EventID,
				Timestamp:            alert.Timestamp,
				SourceType:           alert.SourceType,
				SourceName:           alert.ScopeKey,
				DestHost:             alert.Host,
				HTTPMethod:           alert.HTTPMethod,
				HTTPPath:             alert.HTTPPath,
				HTTPStatus:           alert.StatusCode,
				ResponseBytes:        alert.ResponseBytes,
				Verdict:              "downgraded",
				Classification:       alert.Severity,
				Reason:               alert.Reason,
				MatchedVia:           alert.MatchedVia,
				MatchedPatternScope:  alert.PatternScope,
				MatchedPatternBucket: alert.PatternBucket,
				MatchedPatternValue:  alert.PatternValue,
				OriginEventID:        alert.OriginEventID,
				RawLine:              alert.Line,
				NormalizedHash:       alert.Hash,
				CoordinatorKey:       alert.Key, // Real correlation key, not source identity
				CoordinatorEvents:    alert.EventCount,
				EvidenceStatus:       evStatus,
				EvidenceStatusCode:   evCode,
				EvidenceContentType:  evCT,
				EvidenceBodyHash:     evHash,
				EvidenceCaptureMode:  evMode,
				Downgraded:           true,
				DowngradeReason:      alert.DowngradeReason,
				Notified:             false,
				ResolutionStatus:     "resolved",
				ResolvedAt:           &now,
				ResolutionMethod:     "rec_evidence",
				PreviousVerdict:      alert.Verdict,
			})
			return
		}

		if alert.Escalated {
			log.Printf("[ESCALATED] EventID=%s key=%s events=%d →%s Reason=%s",
				alert.EventID, alert.Key, alert.EventCount, alert.Severity, alert.EscalateReason)
			log.Printf("[INFO] EventID=%s Source=%s EscalatedReason=%s %s Line=%s",
				alert.EventID, alert.ScopeKey, alert.EscalateReason,
				alert.EvidenceJournal, truncate(alert.Line, 200))

			// Compute notified by trying to dispatch. The notified flag in
			// the finding must reflect whether anything actually entered a
			// notifier queue — queue-full drops or no-channels-configured
			// both count as "not notified."
			notified := false
			if alert.BuildAlert != nil {
				// Section 3 / Finding 7: pass the coordinator's already-attached
				// evidence to the closure instead of doing a second host-less
				// REC lookup at dispatch time.
				if builtAlert, ok := alert.BuildAlert(alert.Evidence).(notifier.Alert); ok {
					builtAlert.Severity = notifier.SeverityMalicious
					builtAlert.Reason = alert.EscalateReason
					if dispatch.Dispatch(context.Background(), builtAlert) > 0 {
						notified = true
					}
				}
			}

			now := time.Now()
			db.SubmitFinding(&store.Finding{
				EventID:              alert.EventID,
				Timestamp:            alert.Timestamp,
				SourceType:           alert.SourceType,
				SourceName:           alert.ScopeKey,
				DestHost:             alert.Host,
				HTTPMethod:           alert.HTTPMethod,
				HTTPPath:             alert.HTTPPath,
				HTTPStatus:           alert.StatusCode,
				ResponseBytes:        alert.ResponseBytes,
				Verdict:              "malicious",
				Classification:       "malicious",
				Reason:               alert.EscalateReason,
				MatchedVia:           alert.MatchedVia,
				MatchedPatternScope:  alert.PatternScope,
				MatchedPatternBucket: alert.PatternBucket,
				MatchedPatternValue:  alert.PatternValue,
				OriginEventID:        alert.OriginEventID,
				RawLine:              alert.Line,
				NormalizedHash:       alert.Hash,
				CoordinatorKey:       alert.Key, // Real correlation key, not source identity
				CoordinatorEvents:    alert.EventCount,
				EvidenceStatus:       evStatus,
				EvidenceStatusCode:   evCode,
				EvidenceContentType:  evCT,
				EvidenceBodyHash:     evHash,
				EvidenceCaptureMode:  evMode,
				Notified:             notified,
				ResolutionStatus:     "resolved",
				ResolvedAt:           &now,
				ResolutionMethod:     "rec_evidence",
				PreviousVerdict:      "alert",
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
		log.Printf("[%s] EventID=%s Source=%s key=%s Reason=%s MatchedVia=%s Hash=%s %s Line=%s",
			severity, alert.EventID, alert.ScopeKey, alert.Key, alert.Reason,
			alert.MatchedVia, alert.Hash, alert.EvidenceJournal, truncate(alert.Line, 200))

		// Fix 4: Non-resolved findings get "pending" resolution status
		db.SubmitFinding(&store.Finding{
			EventID:              alert.EventID,
			Timestamp:            alert.Timestamp,
			SourceType:           alert.SourceType,
			SourceName:           alert.ScopeKey,
			DestHost:             alert.Host,
			HTTPMethod:           alert.HTTPMethod,
			HTTPPath:             alert.HTTPPath,
			HTTPStatus:           alert.StatusCode,
			ResponseBytes:        alert.ResponseBytes,
			Verdict:              alert.Verdict,
			Classification:       alert.Severity,
			Reason:               alert.Reason,
			MatchedVia:           alert.MatchedVia,
			MatchedPatternScope:  alert.PatternScope,
			MatchedPatternBucket: alert.PatternBucket,
			MatchedPatternValue:  alert.PatternValue,
			OriginEventID:        alert.OriginEventID,
			RawLine:              alert.Line,
			NormalizedHash:       alert.Hash,
			CoordinatorKey:       alert.Key, // Real correlation key, not source identity
			CoordinatorEvents:    alert.EventCount,
			EvidenceStatus:       evStatus,
			EvidenceStatusCode:   evCode,
			EvidenceContentType:  evCT,
			EvidenceBodyHash:     evHash,
			EvidenceCaptureMode:  evMode,
			Notified:             false,
			ResolutionStatus:     "pending",
		})
	}
}

// makeEvidenceCheckCallback creates the function called periodically by the
// coordinator to check if REC evidence can downgrade a pending alert.
//
// Two downgrade paths (design consensus, 2026-03-25):
//
//	Path 1 — Transport-only downgrade (403/404/405/410)
//	Path 2 — Body-aware re-classification (200, 3xx, 5xx)
//
// =============================================================================
// PATH SOURCE — design consensus P0 fix (2026-05)
// =============================================================================
// We intentionally do NOT re-parse pending.NormalizedLine here. That field
// can contain <NUM>-substituted paths from the generic/Docker normalizer, and
// REC's wire capture stores raw paths. Exact-match lookup against <NUM>
// fails for any URL with 4+ digit numbers, which was the dominant cause of
// "REC missed but should have matched" findings before this fix.
//
// resultRouter.routeAlert now stores the RAW path on PendingAlert.HTTPPath
// (parsed from evt.Line via parseRawHTTPLine). The coordinator join logic
// preserves raw over <NUM> when events merge. We just read the struct here.
// =============================================================================
func makeEvidenceCheckCallback(
	collector rec.EvidenceCollector,
	llmClient *llm.Client,
	cache *reclassCache,
	db *store.Store,
	cfg Config,
	scheduler *LLMScheduler,
	ctx context.Context,
	expectedEndpointTracker *coordinator.ExpectedEndpointTracker,
) coordinator.EvidenceCheckFunc {
	transportDowngradeCodes := map[int]bool{
		403: true, 404: true, 405: true, 410: true,
	}

	return func(snapshot *coordinator.PendingAlert) coordinator.EvidenceDecision {
		// Section 3 / Findings 4+5: snapshot is a value-typed snapshot of the
		// pending alert. We never mutate it. All state to apply (evidence,
		// journal, body preview hash) flows back through EvidenceDecision
		// and the coordinator applies it under its own lock.
		method := snapshot.HTTPMethod
		path := snapshot.HTTPPath
		host := snapshot.Host
		statusCode := snapshot.StatusCode

		if method == "" {
			log.Printf("[coordinator] Evidence check SKIP: no HTTP identity on pending key=%s normalized=%s",
				snapshot.Key, truncate(snapshot.NormalizedLine, 120))
			return coordinator.EvidenceDecision{}
		}

		evidence := collector.Lookup(rec.LookupRequest{
			Method:          method,
			Path:            path,
			Host:            host,
			SourceContainer: snapshot.SourceName,
			StatusCode:      statusCode,
			Timestamp:       snapshot.Timestamp,
			Window:          10 * time.Second, // Matches coordinator finalize window (v0.43.2+)
			// Section 3 follow-up: prefer the
			// merged ResponseBytes off the pending alert. mergePendingMetadata
			// upgrades this from sibling events with stronger byte data;
			// extractResponseBytes(snapshot.Line) is a fallback for the
			// first-arrival event before any merge has happened.
			ExpectedBytes: func() int64 {
				if snapshot.ResponseBytes > 0 {
					return snapshot.ResponseBytes
				}
				return extractResponseBytes(snapshot.Line)
			}(),
		})

		// --- Path 1: Transport-only downgrade ---
		if evidence != nil && evidence.Transport != nil {
			code := evidence.Transport.StatusCode
			if transportDowngradeCodes[code] {
				reason := fmt.Sprintf("Transport evidence confirms attack failed (HTTP %d) — payload was rejected/ignored by the server", code)
				log.Printf("[coordinator] Transport downgrade: key=%s status=%d candidates=%d",
					snapshot.Key, code, evidence.CandidateCount)
				return coordinator.EvidenceDecision{
					Downgraded:      true,
					Reason:          reason,
					Evidence:        evidence,
					EvidenceJournal: evidence.ForJournal(),
					BodyPreviewHash: evidence.Transport.BodyPreviewHash,
				}
			}
		}

		// --- Diagnostic logging on REC miss ---
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
				snapshot.Key, method, path, statusCode, evCandidates, hasTransport, previewLen, evFormat, evStatus)
			return coordinator.EvidenceDecision{}
		}

		// --- Path 2: Body-aware re-classification ---
		// Even if we can't reclassify (no body preview), surface what we have
		// so the coordinator's Phase 2 catch-all re-arm can fire on the
		// transport-side BodyPreviewHash if appropriate.
		if evidence.SafeBodyPreview == "" {
			log.Printf("[coordinator] Evidence check: transport available (HTTP %d) but ambiguous status, no body preview — key=%s candidates=%d format=%s",
				evidence.Transport.StatusCode, snapshot.Key, evidence.CandidateCount,
				func() string {
					if evidence.Disclosure != nil {
						return string(evidence.Disclosure.Format)
					}
					return "n/a"
				}())
			return coordinator.EvidenceDecision{
				Evidence:        evidence,
				EvidenceJournal: evidence.ForJournal(),
				BodyPreviewHash: evidence.Transport.BodyPreviewHash,
			}
		}

		classification := snapshot.Classification
		if classification == "" {
			if snapshot.Verdict == "malicious" {
				classification = "malicious"
			} else {
				classification = "suspicious"
			}
		}

		bodyHash := rec.HashBody([]byte(evidence.SafeBodyPreview))

		// --- Path 2a: ExpectedEndpoint short-circuit (v1.0 Card 4) ---
		// Operator-explicit truth beats reclass cache and LLM inference.
		// Runs AFTER redaction (need the shape hash) but BEFORE reclass
		// cache so a stale "token-looking = malicious" verdict can't
		// pre-empt the operator's approval. Without this ordering, Card 4
		// silently fails for the exact case it was built for. (P0
		// catch + design lock-in, May 11 2026.)
		//
		// bodyHash here is the REDACTED response-shape hash — same value
		// used as the reclass cache key below, stable across token rotations
		// because redaction replaces secret values with markers before
		// hashing. The correction handler stores decision.CacheKey (which
		// equals this bodyHash) so live traffic and stored rules match.
		//
		// Status source consistency: use the
		// status captured AT THE EVIDENCE LAYER (same layer that produced
		// the shape hash) so the key is internally consistent. snapshot.StatusCode
		// is the fallback if evidence didn't carry a code (defensive — by
		// this point in the function evidence.Transport is non-nil, but the
		// fallback keeps us safe under refactor).
		statusForKey := evidence.Transport.StatusCode
		if statusForKey == 0 {
			statusForKey = statusCode
		}
		if expectedEndpointTracker != nil {
			if matched, reason := expectedEndpointTracker.Check(host, method, statusForKey, path, bodyHash); matched {
				log.Printf("[reclassify] ExpectedEndpoint match: host=%s method=%s path=%s status=%d shape=%.16s — operator-confirmed downgrade",
					host, method, path, statusForKey, bodyHash)
				return coordinator.EvidenceDecision{
					Downgraded:      true,
					Reason:          reason,
					Evidence:        evidence,
					EvidenceJournal: evidence.ForJournal(),
					BodyPreviewHash: evidence.Transport.BodyPreviewHash,
				}
			}
		}

		if cached, ok := cache.get(bodyHash); ok {
			if cached.downgraded {
				log.Printf("[reclassify] Cache hit (redacted_body=%s): downgraded → %s",
					bodyHash[:16], cached.reason)
			} else if cached.escalated {
				log.Printf("[reclassify] Cache hit (redacted_body=%s): escalated → %s → %s",
					bodyHash[:16], cached.newSeverity, cached.reason)
			}
			return coordinator.EvidenceDecision{
				Downgraded:      cached.downgraded,
				Escalated:       cached.escalated,
				Reason:          cached.reason,
				NewSeverity:     cached.newSeverity,
				Evidence:        evidence,
				EvidenceJournal: evidence.ForJournal(),
				BodyPreviewHash: evidence.Transport.BodyPreviewHash,
			}
		}

		release, ok := scheduler.AcquireBlocking(ctx)
		if !ok {
			log.Printf("[reclassify] Context cancelled waiting for LLM slot")
			// Return what evidence we have so catch-all re-arm can still fire.
			return coordinator.EvidenceDecision{
				Evidence:        evidence,
				EvidenceJournal: evidence.ForJournal(),
				BodyPreviewHash: evidence.Transport.BodyPreviewHash,
			}
		}
		reclass, err := llmClient.ReclassifyWithEvidence(
			ctx,
			classification,
			snapshot.Reason,
			snapshot.Line,
			evidence.Transport.StatusCode,
			evidence.Transport.ContentType,
			evidence.Transport.ContentLength,
			evidence.SafeBodyPreview,
		)
		release()
		if err != nil {
			log.Printf("[reclassify] Error: %v — not changing verdict", err)
			return coordinator.EvidenceDecision{
				Evidence:        evidence,
				EvidenceJournal: evidence.ForJournal(),
				BodyPreviewHash: evidence.Transport.BodyPreviewHash,
			}
		}

		cache.put(bodyHash, reclass.Downgraded, reclass.Escalated, reclass.Reason, reclass.Classification)

		auditCtx, auditCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := db.RecordLLMDecision(auditCtx, &store.LLMDecision{
			EventID:          snapshot.EventID,
			Timestamp:        time.Now(),
			Tier:             "reclassify",
			Model:            cfg.LLMModel,
			ReasoningEffort:  cfg.Tier2Effort,
			PromptTokens:     reclass.PromptTokens,
			CompletionTokens: reclass.CompletionTokens,
			LatencyMs:        reclass.LatencyMs,
			SourceScope:      snapshot.ScopeKey,
			RawLine:          snapshot.Line,
			NormalizedLine:   snapshot.NormalizedLine,
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
		}); err != nil {
			log.Printf("[reclassify] WARN: audit write failed for %s: %v", snapshot.EventID, err)
		}
		auditCancel()

		if reclass.Downgraded {
			log.Printf("[DOWNGRADED] Original=%s→%s Reason=%s",
				classification, reclass.Classification, reclass.Reason)
		} else if reclass.Escalated {
			log.Printf("[ESCALATED] Original=%s→%s Reason=%s",
				classification, reclass.Classification, reclass.Reason)
		}
		return coordinator.EvidenceDecision{
			Downgraded:      reclass.Downgraded,
			Escalated:       reclass.Escalated,
			Reason:          reclass.Reason,
			NewSeverity:     reclass.Classification,
			Evidence:        evidence,
			EvidenceJournal: evidence.ForJournal(),
			BodyPreviewHash: evidence.Transport.BodyPreviewHash,
		}
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

	// Section 3 follow-up: DisableCompression: true
	// on both transports, and Accept-Encoding: identity on every request.
	// REC hashes wire-byte response previews; Go's default http.Client requests
	// gzip and silently decompresses, so the verifier would hash decompressed
	// bytes while REC hashed compressed bytes — body hashes would never match
	// for any response that nginx gzipped (catch-all verification fails
	// silently). Belt-and-suspenders: header + transport flag.
	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}
	httpsClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
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

		// Section 3 follow-up: use the fingerprint's
		// method instead of hardcoded GET. catchall.Check accepts both GET and
		// HEAD; verifying a HEAD-method fingerprint with a GET request would
		// produce a different body hash (HEAD has no body, GET does) and the
		// verification would fail even when the page is identical.
		verifyMethod := fp.Method
		if verifyMethod == "" {
			verifyMethod = "GET"
		}

		schemes := []struct {
			scheme string
			client *http.Client
		}{
			{"http", httpClient},
			{"https", httpsClient},
		}

		for _, s := range schemes {
			url := fmt.Sprintf("%s://127.0.0.1%s", s.scheme, path)

			httpReq, err := http.NewRequestWithContext(ctx, verifyMethod, url, nil)
			if err != nil {
				log.Printf("[verify] Failed to create request: %v", err)
				continue
			}
			httpReq.Host = fp.Host
			httpReq.Header.Set("User-Agent", userAgent)
			httpReq.Header.Set("Accept-Encoding", "identity")

			resp, err := s.client.Do(httpReq)
			if err != nil {
				log.Printf("[verify] %s request failed: %v", s.scheme, err)
				continue
			}

			// Section 3 / Finding 6: hash budget must match REC's actual capture
			// limit, not the package default constant. cfg.RECReassemblyMaxBody
			// is the runtime knob the sniffer uses; if a customer ever sets
			// REC_REASSEMBLY_MAX_BODY=4096, REC hashes 4096 bytes and the verifier
			// must hash exactly that range or every catch-all verification fails
			// silently. This was a latent bug as long as the env defaulted to 2048.
			maxHash := int64(cfg.RECReassemblyMaxBody)
			if maxHash <= 0 {
				maxHash = int64(rec.DefaultMaxBodyBytes)
			}

			// Section 3 / Landmine A: read past the hash budget so we can persist
			// the actual response size on the verified catch-all entry. The
			// Phase 3 fallback (CheckFallbackByBytes) needs this to bound
			// suppression to byte-similar responses only.
			const maxByteCountRead int64 = 64 * 1024 // 64KB sanity cap
			readLimit := maxByteCountRead
			if maxHash > readLimit {
				readLimit = maxHash
			}
			fullBody, readErr := io.ReadAll(io.LimitReader(resp.Body, readLimit))
			resp.Body.Close()

			// v0.52: Fail closed on read errors. A broken connection or
			// mid-stream error can produce a partial body whose prefix hash
			// accidentally matches REC's preview — leading to false verification.
			if readErr != nil {
				log.Printf("[verify] Body read error: %v — skipping (fail closed)", readErr)
				continue
			}

			fullBodyLen := int64(len(fullBody))

			// Truncate to maxHash for fingerprint match — REC's sniffer hashes
			// the first maxHash bytes; we must compare hashes over the same range.
			body := fullBody
			if int64(len(body)) > maxHash {
				body = body[:maxHash]
			}
			bodyLen := int64(len(body))
			contentType := resp.Header.Get("Content-Type")
			bodyHash := rec.HashBody(body)

			// Use Content-Length header when known and larger than what we
			// actually read (response was bigger than readLimit). Falls back
			// to fullBodyLen when chunked or unknown.
			responseBytes := fullBodyLen
			if resp.ContentLength > responseBytes {
				responseBytes = resp.ContentLength
			}

			if resp.StatusCode != fp.StatusCode {
				log.Printf("[verify] Status mismatch: expected=%d got=%d (scheme=%s)",
					fp.StatusCode, resp.StatusCode, s.scheme)
				continue
			}

			if bodyHash != fp.BodyPreviewHash {
				log.Printf("[verify] Body hash mismatch: expected=%.16s got=%.16s (scheme=%s, maxHash=%d)",
					fp.BodyPreviewHash, bodyHash, s.scheme, maxHash)
				continue
			}

			log.Printf("[verify] Response matched: scheme=%s status=%d hashed_bytes=%d total_bytes=%d hash=%.16s",
				s.scheme, resp.StatusCode, bodyLen, responseBytes, bodyHash)

			// Redact the body using existing REC pipeline (over the maxHash slice
			// — that matches what REC redacts and what we hashed).
			disclosure := rec.ClassifyAndRedact(body, contentType)
			safePreview := disclosure.RedactedPreview()

			if safePreview == "" {
				if bodyLen <= 200 {
					safePreview = string(body)
				} else if bodyLen <= maxHash {
					reason := fmt.Sprintf("Verified: %s %d response (%d bytes hashed, %d total), format=%s, body hash %.16s, consistent across %d+ paths",
						s.scheme, resp.StatusCode, bodyLen, responseBytes, disclosure.Format, bodyHash, coordinator.DefaultCatchAllThreshold)
					result := &coordinator.VerifyResult{
						Confirmed:     true,
						Reason:        reason,
						ContentType:   contentType,
						BodyHash:      bodyHash,
						ResponseBytes: responseBytes,
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
				fmt.Sprintf("%s %s → %d", verifyMethod, path, resp.StatusCode),
				resp.StatusCode, contentType, bodyLen, safePreview,
			)
			release()

			if err != nil {
				log.Printf("[verify] LLM error: %v — not confirming", err)
				return &coordinator.VerifyResult{Confirmed: false, Reason: fmt.Sprintf("LLM error: %v", err)}
			}

			auditCtx2, auditCancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			if err := db.RecordLLMDecision(auditCtx2, &store.LLMDecision{
				Timestamp:        time.Now(),
				Tier:             "catchall_verify",
				Model:            cfg.LLMModel,
				ReasoningEffort:  cfg.Tier2Effort,
				PromptTokens:     reclass.PromptTokens,
				CompletionTokens: reclass.CompletionTokens,
				LatencyMs:        reclass.LatencyMs,
				SourceScope:      fp.Host,
				RawLine:          fmt.Sprintf("%s %s → %d", verifyMethod, path, resp.StatusCode),
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
			}); err != nil {
				log.Printf("[verify] WARN: audit write failed: %v", err)
			}
			auditCancel2()

			if reclass.Downgraded {
				reason := fmt.Sprintf("LLM confirmed benign: %s", reclass.Reason)
				result := &coordinator.VerifyResult{
					Confirmed:     true,
					Reason:        reason,
					ContentType:   contentType,
					BodyHash:      bodyHash,
					ResponseBytes: responseBytes,
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
// Section 3 / Landmine A: persists ResponseBytes so the byte-aware Phase 3
// fallback can use it after a restart.
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
		ResponseBytes:       result.ResponseBytes,
	})
	if err != nil {
		log.Printf("[verify] Failed to persist verified catch-all: %v", err)
	} else {
		log.Printf("[verify] Persisted verified catch-all: host=%s method=%s status=%d hash=%.16s bytes=%d",
			fp.Host, fp.Method, fp.StatusCode, fp.BodyPreviewHash, result.ResponseBytes)
	}
}

// seedCatchAllsFromDB loads previously verified catch-all fingerprints.
// Section 3 / Landmine A: also seeds ResponseBytes for the byte-aware fallback.
// Pre-migration rows have response_bytes=0 — those entries will be skipped by
// CheckFallbackByBytes until they're re-verified with a real measurement.
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
	bytesList := make([]int64, len(rules))
	for i, r := range rules {
		fps[i] = coordinator.CatchAllFingerprint{
			Host:            r.Host,
			Method:          r.HTTPMethod,
			StatusCode:      r.HTTPStatus,
			BodyPreviewHash: r.BodyPreviewHash,
		}
		reasons[i] = r.VerificationReason
		bytesList[i] = r.ResponseBytes
	}

	coord.CatchAllTracker().SeedVerified(fps, reasons, bytesList)
}

// seedExpectedEndpointsFromDB loads previously confirmed expected-endpoint
// rules (Card 4 / "Expected sensitive response") into the in-memory tracker.
// Takes the tracker directly rather than going through the coordinator
// because the coordinator doesn't own the tracker — both the evidence
// callback and the API server reference it independently.
//
// Boot graceful degradation (design decision, May 11 2026): log loudly
// and continue on error. Missing seeds mean prior Card 4 corrections don't
// apply until the operator re-clicks — annoying but not security-degrading
// (CatchAll re-arm + Tier-2 LLM escalation still work).
func seedExpectedEndpointsFromDB(db *store.Store, tracker *coordinator.ExpectedEndpointTracker) {
	rules, err := db.LoadExpectedEndpoints(context.Background())
	if err != nil {
		log.Printf("[observer:warn] Failed to load expected-endpoint seeds: %v — prior Card 4 corrections are NOT active until re-clicked", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	fps := make([]coordinator.ExpectedEndpointFingerprint, len(rules))
	reasons := make([]string, len(rules))
	for i, r := range rules {
		fps[i] = coordinator.ExpectedEndpointFingerprint{
			Host:            r.Host,
			Method:          r.HTTPMethod,
			Path:            r.HTTPPath,
			Status:          r.HTTPStatus,
			BodyPreviewHash: r.BodyPreviewHash, // redacted shape hash from DB
		}
		reasons[i] = r.Description
	}

	tracker.SeedVerified(fps, reasons)
	log.Printf("[observer] Seeded %d expected-endpoint rules from DB", len(rules))
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
		// Dispatch first so the finding's Notified flag reflects reality.
		notified := dispatch.Dispatch(context.Background(), alert) > 0

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
			Notified:       notified,
		})
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

func runPeriodicStats(ctx context.Context, a *analyzer.Analyzer, patterns *patternstore.Store, collector rec.EvidenceCollector, db *store.Store, coord *coordinator.Coordinator, scheduler *LLMScheduler, policyEngine *policy.Engine, pipelineDrops *atomic.Int64, retryQueueDrops *atomic.Int64, dispatch *notifier.Dispatcher) {
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
				log.Printf("[observer] REC: packets=%d inline_req=%d resp=%d pair_immediate=%d orphan_resp=%d req_expired=%d vxlan=%d buf_entries=%d buf_bytes=%d buf_evictions_total=%d buf_evictions_capacity=%d buf_evictions_age=%d buf_evictions_bytes=%d vip_matches=%d",
					rStats.PacketsSeen, rStats.InlineRequests, rStats.ReassemblyResponses,
					rStats.PairImmediate, rStats.OrphanResponses, rStats.RequestsExpired,
					rStats.VXLANUnwrapped, rStats.BufferEntries, rStats.BufferBytes,
					rStats.BufferEvictionsTotal, rStats.BufferEvictionsCapacity,
					rStats.BufferEvictionsAge, rStats.BufferEvictionsBytes,
					rStats.VIPMatches)
				log.Printf("[observer] REC reassembly: streams_active=%d streams_total=%d streams_timeout=%d stream_drops=%d parse_errors=%d flows=%d flow_evictions=%d flow_evictions_live=%d",
					rStats.ReassemblyStreamsActive, rStats.ReassemblyStreamsTotal,
					rStats.ReassemblyStreamsTimedOut, rStats.ReassemblyStreamDrops,
					rStats.ReassemblyParseErrors, rStats.FlowStates, rStats.FlowEvictions, rStats.FlowEvictionsLive)
				log.Printf("[observer] REC inline: requests=%d seq_dedup=%d body_skip=%d feed_http=%d",
					rStats.InlineRequests, rStats.InlineDuplicateDrops,
					rStats.InlineBodySkips, rStats.FeedHTTP)
				log.Printf("[observer] REC ports: configured=%d learned=%d cap=%d attempts=%d added=%d refused=%d",
					rStats.PortConfiguredCount, rStats.PortLearnedCount, rStats.PortLearnCap,
					rStats.PortLearnAttempts, rStats.PortLearnAdded, rStats.PortLearnRefused)
			}

			caTotal, caCandidates, caPending, caVerified, caRejected, caSuppressed := coord.CatchAllStats()
			if caTotal > 0 {
				log.Printf("[observer] CatchAll: fingerprints=%d candidates=%d pending=%d verified=%d rejected=%d suppressed=%d",
					caTotal, caCandidates, caPending, caVerified, caRejected, caSuppressed)
			}

			// Section 3 follow-up telemetry: hostless coordinator keys.
			// Logged only when non-zero to avoid noise on healthy boxes.
			if hk := coord.HostlessKeys(); hk > 0 {
				log.Printf("[observer] Coordinator: hostless_keys=%d (events with no parseable Host — investigate normalizer if growing fast)", hk)
			}

			policyMatches, policyEscalations, policyAllows, policyAlerts := policyEngine.Stats()
			if policyMatches > 0 {
				log.Printf("[observer] Policy: matches=%d escalations=%d allows=%d alerts=%d",
					policyMatches, policyEscalations, policyAllows, policyAlerts)
			}

			// Notifier — log only when channels are configured. Dropped
			// counter is the cumulative number of alerts shed because a
			// channel's queue was full (sustained overload protection).
			if dispatch != nil && dispatch.ChannelCount() > 0 {
				if nd := dispatch.DroppedCount(); nd > 0 {
					log.Printf("[observer] Notifier: channels=%d dropped=%d",
						dispatch.ChannelCount(), nd)
				}
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
