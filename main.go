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
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
	"github.com/vaultguardian/observer/internal/watcher"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// Pipeline drop counter — tracked as first-class metric, not just a warning log.
	// code review review: "under pressure you can silently lose security-relevant events
	// unless you track and expose this as a first-class metric."
	var pipelineDrops atomic.Int64
	log.Println("[observer] VaultGuardian Observer starting...")

	// --- pprof profiling endpoint (localhost only) ---
	// CPU:        go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30
	// Memory:     go tool pprof http://localhost:6060/debug/pprof/heap
	// Goroutines: curl http://localhost:6060/debug/pprof/goroutine?debug=2
	go func() {
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			log.Printf("[observer] pprof server failed: %v", err)
		}
	}()

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

	// Global LLM scheduler — shared across T1 classify, T2 evidence, catch-all verify.
	// code review code review (April 2026): without unified scheduling, T2 and catch-all
	// calls run unbounded while T1 is throttled. One scheduler, three acquire modes.
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

	// ------- Init Response Evidence Capture (opt-in) -------
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

	// ------- Re-Classification Cache -------
	reclassCache := newReclassCache()

	// ------- Self-Suppression Token Registry -------
	// Created here so both the coordinator and verify callback can reference it.
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

	// ------- Seed verified catch-alls from database -------
	seedCatchAllsFromDB(db, alertCoordinator)

	// ------- Periodic persistence + stats -------
	go runPeriodicStats(ctx, a, patterns, collector, db, alertCoordinator, llmScheduler, &pipelineDrops)

	// ------- Ingestion Pipeline -------
	// Decouples watcher goroutines from the analysis pipeline.
	// code review code review (April 2026): synchronous ingestion means watcher
	// throughput is coupled to LLM call latency. A burst of unknown lines
	// stalls the per-container stream. Bounded channel provides backpressure
	// without blocking the watcher.
	const pipelineBufferSize = 1000
	pipeline := make(chan watcher.LogLine, pipelineBufferSize)

	pipelineHandler := makeLogHandler(cfg, a, collector, alertCoordinator, dispatch, db)

	// Worker pool: enough goroutines to keep LLM slots fed without over-subscribing.
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
	log.Printf("[observer] Pipeline ready: buffer=%d workers=%d llm_slots=%d",
		pipelineBufferSize, numWorkers, cfg.MaxConcurrentLLM)

	// Ingestion handler: lightweight, just pushes to channel.
	// Non-blocking: if pipeline is full, drop the line rather than stall the watcher.
	ingestionHandler := func(line watcher.LogLine) {
		select {
		case pipeline <- line:
		default:
			pipelineDrops.Add(1)
			log.Println("[observer] WARNING: pipeline full — dropping log line")
		}
	}

	// ------- Start watching -------
	w := watcher.New(cfg.DockerSocket, ingestionHandler)
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
				DestHost:        alert.Host,
				HTTPMethod:      alert.HTTPMethod,
				HTTPPath:        alert.HTTPPath,
				HTTPStatus:      alert.StatusCode,
				ResponseBytes:   alert.ResponseBytes,
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

		if alert.Escalated {
			log.Printf("[ESCALATED] EventID=%s key=%s events=%d →%s Reason=%s",
				alert.EventID, alert.ScopeKey, alert.EventCount, alert.Severity, alert.EscalateReason)
			log.Printf("[INFO] EventID=%s Source=%s EscalatedReason=%s %s Line=%s",
				alert.EventID, alert.ScopeKey, alert.EscalateReason,
				alert.EvidenceJournal, truncate(alert.Line, 200))

			// Send alert at escalated severity
			if alert.BuildAlert != nil {
				if builtAlert, ok := alert.BuildAlert().(notifier.Alert); ok {
					// Override to malicious — evidence confirmed real exposure
					builtAlert.Severity = notifier.SeverityMalicious
					builtAlert.Reason = alert.EscalateReason
					dispatch.Dispatch(context.Background(), builtAlert)
				}
			}

			// Record escalated finding to SQLite
			db.RecordFinding(context.Background(), &store.Finding{
				EventID:           alert.EventID,
				Timestamp:         time.Now(),
				SourceType:        "docker",
				SourceName:        alert.ScopeKey,
				DestHost:          alert.Host,
				HTTPMethod:        alert.HTTPMethod,
				HTTPPath:          alert.HTTPPath,
				HTTPStatus:        alert.StatusCode,
				ResponseBytes:     alert.ResponseBytes,
				Verdict:           "deny",
				Classification:    "malicious",
				Reason:            alert.EscalateReason,
				MatchedVia:        alert.MatchedVia,
				RawLine:           alert.Line,
				NormalizedHash:    alert.Hash,
				CoordinatorKey:    alert.ScopeKey,
				CoordinatorEvents: alert.EventCount,
				Notified:          true,
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

		// NO EMAIL — only escalated alerts (evidence-confirmed exposure) send email.
		// Everything else is logged to SQLite for dashboard review.

		// Record finding to SQLite (not notified — review on dashboard)
		db.RecordFinding(context.Background(), &store.Finding{
			EventID:         alert.EventID,
			Timestamp:       time.Now(),
			SourceType:      "docker",
			SourceName:      alert.ScopeKey,
			DestHost:        alert.Host,
			HTTPMethod:      alert.HTTPMethod,
			HTTPPath:        alert.HTTPPath,
			HTTPStatus:      alert.StatusCode,
			ResponseBytes:   alert.ResponseBytes,
			Verdict:         alert.Verdict,
			Classification:  alert.Severity,
			Reason:          alert.Reason,
			MatchedVia:      alert.MatchedVia,
			RawLine:         alert.Line,
			NormalizedHash:  alert.Hash,
			CoordinatorKey:  alert.ScopeKey,
			CoordinatorEvents: alert.EventCount,
			Notified:        false,
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
	db *store.Store,
	cfg Config,
	scheduler *LLMScheduler,
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
				return true, false, reason, ""
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
			return false, false, "", ""
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
			return false, false, "", ""
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
			} else if cached.escalated {
				log.Printf("[reclassify] Cache hit (redacted_body=%s): escalated → %s → %s",
					bodyHash[:16], cached.newSeverity, cached.reason)
			}
			return cached.downgraded, cached.escalated, cached.reason, cached.newSeverity
		}

		// Cache miss — call LLM (blocking acquire: T2 evidence is high priority)
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
		release() // free LLM slot immediately after call completes
		if err != nil {
			log.Printf("[reclassify] Error: %v — not changing verdict", err)
			return false, false, "", ""
		}

		cache.put(bodyHash, reclass.Downgraded, reclass.Escalated, reclass.Reason, reclass.Classification)

		// Record LLM decision to audit trail (Tier 2: reclassification with evidence)
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

// makeVerifyCallback creates the function called once per fingerprint lifetime
// when the catch-all tracker wants to confirm a candidate is benign.
//
// ARCHITECTURE (design consensus, 2026-03-31):
//   Structural inference NOMINATES, active verify CONFIRMS.
//   One HTTP request + one LLM call per fingerprint lifetime.
//
// FLOW:
//   1. GET the sample path via HTTP first, then HTTPS if HTTP doesn't match
//   2. Compare status + body length against expected fingerprint values
//   3. Feed body through redaction → LLM re-classification
//   4. If LLM says benign → confirmed, persist to SQLite
//   5. If LLM says sensitive → rejected, keep alerting
//
// SELF-SUPPRESSION:
//   Uses cryptographic token in User-Agent. The log handler checks tokens
//   against the SelfSuppressor registry and drops matching lines.
//   the design review mandate: no static strings an attacker can copy.
func makeVerifyCallback(
	db *store.Store,
	llmClient *llm.Client,
	selfSuppress *coordinator.SelfSuppressor,
	cfg Config,
	scheduler *LLMScheduler,
	ctx context.Context,
) coordinator.VerifyFunc {

	// HTTP client with short timeout — localhost should respond in ms
	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects — we want to see the 302
		},
	}
	httpsClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed certs
		},
	}

	return func(req coordinator.VerifyRequest) *coordinator.VerifyResult {
		fp := req.Fingerprint
		path := req.SamplePath
		if path == "" {
			return &coordinator.VerifyResult{Confirmed: false, Reason: "no sample path available"}
		}

		log.Printf("[verify] Starting verification: host=%s method=%s status=%d bytes=%d path=%s",
			fp.Host, fp.Method, fp.StatusCode, fp.ResponseBytes, path)

		// Generate self-suppression token — unique per verify request.
		// The log handler will match this token and silently drop the log line.
		// the design review mandate: cryptographic randomness, not a static string.
		userAgent, _ := selfSuppress.GenerateToken()

		// Try HTTP first (port 80), then HTTPS (port 443)
		// The logged response could be from either — match against expected values
		schemes := []struct {
			scheme string
			client *http.Client
		}{
			{"http", httpClient},
			{"https", httpsClient},
		}

		for _, s := range schemes {
			// SECURITY: Always verify through localhost — never use attacker-controlled
			// host as network destination. nginx routes based on Host header, so we
			// connect to 127.0.0.1 and set Host to the observed value.
			// Without this, an attacker who sends requests with a custom Host header
			// could trick Observer into making outbound requests to arbitrary servers (SSRF).
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

			// Read body (capped at 4KB like REC)
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			bodyLen := int64(len(body))
			statusMatch := resp.StatusCode == fp.StatusCode
			sizeMatch := bodyLen == fp.ResponseBytes

			log.Printf("[verify] %s response: status=%d (want %d) body=%d bytes (want %d) match=%v",
				s.scheme, resp.StatusCode, fp.StatusCode, bodyLen, fp.ResponseBytes, statusMatch && sizeMatch)

			if !statusMatch || !sizeMatch {
				continue // try next scheme
			}

			// Status + size match — now verify the body is benign
			contentType := resp.Header.Get("Content-Type")

			// Redact the body using existing REC pipeline
			disclosure := rec.ClassifyAndRedact(body, contentType)
			safePreview := disclosure.RedactedPreview()

			if safePreview == "" {
				// Redaction couldn't produce a preview — still classify as benign
				// if the body is very small (redirect pages, error templates)
				if bodyLen <= 200 {
					safePreview = string(body) // small enough to use raw
				} else {
					log.Printf("[verify] Redaction produced empty preview, format=%s — skipping LLM", disclosure.Format)
					// For unknown formats, trust the size match alone if body is small-ish
					if bodyLen <= 2048 {
						reason := fmt.Sprintf("Verified: %s %d response (%d bytes), format=%s, consistent across %d+ paths",
							s.scheme, resp.StatusCode, bodyLen, disclosure.Format, coordinator.DefaultCatchAllThreshold)
						result := &coordinator.VerifyResult{
							Confirmed:   true,
							Reason:      reason,
							ContentType: contentType,
							BodyHash:    rec.HashBody(body),
						}
						persistVerifiedCatchAll(db, ctx, fp, path, result, contentType)
						return result
					}
					return &coordinator.VerifyResult{Confirmed: false, Reason: "redaction failed on large body — cannot verify safety"}
				}
			}

			// Ask LLM: is this response benign?
			// Blocking acquire: catch-all verify fires once per fingerprint LIFETIME
			// (~3-5/week). If we drop it, the fingerprint is permanently rejected
			// with no retry mechanism. Worth waiting for a slot.
			release, ok := scheduler.AcquireBlocking(ctx)
			if !ok {
				log.Printf("[verify] Context cancelled waiting for LLM slot")
				return &coordinator.VerifyResult{Confirmed: false, Reason: "context cancelled"}
			}
			reclass, err := llmClient.ReclassifyWithEvidence(
				ctx,
				"suspicious",                    // original classification
				"Catch-all verification probe",  // original reason
				fmt.Sprintf("GET %s → %d", path, resp.StatusCode), // synthetic log line
				resp.StatusCode,
				contentType,
				bodyLen,
				safePreview,
			)
			release() // free LLM slot immediately
			if err != nil {
				log.Printf("[verify] LLM error: %v — not confirming", err)
				return &coordinator.VerifyResult{Confirmed: false, Reason: fmt.Sprintf("LLM error: %v", err)}
			}

			bodyHash := rec.HashBody(body)

			// Record LLM decision to audit trail (Tier 3: catch-all verification)
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

			// LLM said NOT benign — reject this fingerprint
			reason := fmt.Sprintf("LLM rejected: %s (classification=%s)", reclass.Reason, reclass.Classification)
			log.Printf("[verify] LLM rejected catch-all: %s", reason)
			return &coordinator.VerifyResult{Confirmed: false, Reason: reason}
		}

		return &coordinator.VerifyResult{Confirmed: false, Reason: "no scheme matched expected status+size"}
	}
}

// persistVerifiedCatchAll saves a confirmed catch-all to SQLite for restart persistence.
func persistVerifiedCatchAll(db *store.Store, ctx context.Context, fp coordinator.CatchAllFingerprint, path string, result *coordinator.VerifyResult, contentType string) {
	err := db.SaveVerifiedCatchAll(ctx, &store.CatchAllRule{
		Host:                fp.Host,
		HTTPMethod:          fp.Method,
		HTTPStatus:          fp.StatusCode,
		ResponseBytes:       fp.ResponseBytes,
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
		log.Printf("[verify] Persisted verified catch-all: host=%s method=%s status=%d bytes=%d",
			fp.Host, fp.Method, fp.StatusCode, fp.ResponseBytes)
	}
}

// seedCatchAllsFromDB loads previously verified catch-all fingerprints from SQLite
// and pre-warms the tracker. Zero learning period for known catch-alls.
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
			Host:          r.Host,
			Method:        r.HTTPMethod,
			StatusCode:    r.HTTPStatus,
			ResponseBytes: r.ResponseBytes,
		}
		reasons[i] = r.VerificationReason
	}

	coord.CatchAllTracker().SeedVerified(fps, reasons)
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

		// Self-suppression: skip log lines generated by Observer's own
		// catch-all verify requests. Uses cryptographic tokens — not a
		// static User-Agent that an attacker could spoof.
		// (the design review security mandate, 2026-03-31)
		if alertCoordinator.SelfSuppressor().IsSelfVerify(line.Line) {
			return
		}

		evt := &event.Event{
			ID:          event.NewID(),
			SourceType:  event.SourceDocker,
			SourceName:  line.ContainerName,
			Line:        line.Line,
			Stream:      line.Stream,
			Timestamp:   line.Timestamp,
			ProcessedAt: time.Now(),
			Metadata: map[string]string{
				"container_id": line.ContainerID,
			},
		}

		result := a.Analyze(context.Background(), evt)

		// Record LLM decision to audit trail (Tier 1: classification)
		if result.Source == "llm" && result.LLMVerdict != nil {
			v := result.LLMVerdict
			db.RecordLLMDecision(context.Background(), &store.LLMDecision{
				EventID:          evt.ID,
				Timestamp:        evt.Timestamp,
				Tier:             "classify",
				Model:            cfg.LLMModel,
				ReasoningEffort:  cfg.Tier1Effort,
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
					Host:           host,
					StatusCode:     statusCode,
					ResponseBytes:  extractResponseBytes(evt.Line),
					HTTPMethod:     method,
					HTTPPath:       path,
					NormalizedLine: evt.NormalizedLine,
					SourceName:     evt.SourceName,
					Timestamp:      evt.Timestamp,
					BuildAlert:     alertBuilder,
				})
			} else {
				log.Printf("[ALERT] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s Line=%s",
					evt.ID, evt.ScopeKey(), result.Reason, result.Source, evt.Hash,
					truncate(evt.Line, 200))

				// NO EMAIL — only escalated alerts send email.
				// Non-HTTP alerts logged to SQLite for dashboard review.

				// Record non-coordinator alert to SQLite
				db.RecordFinding(context.Background(), &store.Finding{
					EventID:        evt.ID,
					Timestamp:      evt.Timestamp,
					SourceType:     string(evt.SourceType),
					SourceName:     evt.SourceName,
					DestHost:       host,
					HTTPMethod:     method,
					HTTPPath:       path,
					HTTPStatus:     statusCode,
					ResponseBytes:  extractResponseBytes(evt.Line),
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

func runPeriodicStats(ctx context.Context, a *analyzer.Analyzer, patterns *patternstore.Store, collector rec.EvidenceCollector, db *store.Store, coord *coordinator.Coordinator, scheduler *LLMScheduler, pipelineDrops *atomic.Int64) {
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
			log.Printf("[observer] Pipeline: processed=%d pattern_hits=%d noise_suppressed=%d llm_calls=%d llm_errors=%d learned=%d llm_sched_total=%d llm_sched_dropped=%d pipeline_drops=%d",
				aStats.TotalProcessed, aStats.PatternHits, aStats.NoiseSuppressed, aStats.LLMCalls, aStats.LLMErrors, aStats.PatternsLearned, llmTotal, llmDropped, drops)
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

			// Catch-all tracker stats
			caTotal, caCandidates, caPending, caVerified, caRejected, caSuppressed := coord.CatchAllStats()
			if caTotal > 0 {
				log.Printf("[observer] CatchAll: fingerprints=%d candidates=%d pending=%d verified=%d rejected=%d suppressed=%d",
					caTotal, caCandidates, caPending, caVerified, caRejected, caSuppressed)
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