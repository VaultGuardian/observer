package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vaultguardian/logwatch/internal/analyzer"
	"github.com/vaultguardian/logwatch/internal/coordinator"
	"github.com/vaultguardian/logwatch/internal/event"
	"github.com/vaultguardian/logwatch/internal/llm"
	"github.com/vaultguardian/logwatch/internal/normalizer"
	"github.com/vaultguardian/logwatch/internal/notifier"
	"github.com/vaultguardian/logwatch/internal/patternstore"
	"github.com/vaultguardian/logwatch/internal/rec"
	"github.com/vaultguardian/logwatch/internal/watcher"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("[observer] VaultGuardian Observer starting...")

	// ------- Config (env vars with sane defaults) -------
	dockerSocket := getEnv("DOCKER_SOCKET", "/var/run/docker.sock")
	dataDir := getEnv("DATA_DIR", "/data")
	llmURL := getEnv("LLM_URL", "http://llm:11434")
	llmModel := getEnv("LLM_MODEL", "qwen2.5:7b")
	llmAPIKey := getEnv("LLM_API_KEY", "")
	selfID := getEnv("HOSTNAME", "")
	excludeRaw := getEnv("EXCLUDE_CONTAINERS", "")

	// Build exclusion set from comma-separated container names
	excludeContainers := make(map[string]bool)
	if excludeRaw != "" {
		for _, name := range strings.Split(excludeRaw, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				excludeContainers[name] = true
			}
		}
	}
	if len(excludeContainers) > 0 {
		log.Printf("[observer] Excluding containers: %s", excludeRaw)
	}

	// ------- Ensure data dir exists -------
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("[observer] Failed to create data dir: %v", err)
	}

	// ------- Init normalizer registry -------
	normReg := normalizer.NewRegistry()
	log.Println("[observer] Normalizer registry initialized")

	// ------- Init pattern store -------
	patterns, err := patternstore.NewStore(dataDir)
	if err != nil {
		log.Fatalf("[observer] Failed to init pattern store: %v", err)
	}

	// Seed default deny patterns (common attack indicators)
	seedDenyPatterns(patterns)
	log.Printf("[observer] Pattern store initialized (%d scopes)", patterns.ScopeCount())

	// ------- Init LLM client -------
	llmClient := llm.NewClient(llmURL, llmModel, llmAPIKey)

	// ------- Init analyzer -------
	a := analyzer.New(normReg, patterns, llmClient, 2) // 2 concurrent LLM calls for local Ollama
	log.Println("[observer] Analyzer pipeline ready")

	// ------- Init notifications -------
	notifCfg, err := notifier.LoadConfig(dataDir)
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
	recCfg.Enabled = getEnv("REC_ENABLED", "") == "true"
	recCfg.DockerSocket = dockerSocket
	if iface := getEnv("REC_INTERFACE", ""); iface != "" {
		recCfg.Interface = iface
	}
	if vxlanPortStr := getEnv("REC_VXLAN_PORT", ""); vxlanPortStr != "" {
		if port, err := strconv.Atoi(vxlanPortStr); err == nil && port > 0 && port < 65536 {
			recCfg.VXLANPort = uint16(port)
		} else {
			log.Printf("[observer] Invalid REC_VXLAN_PORT=%q — using auto-detect", vxlanPortStr)
		}
	}
	if nsContainer := getEnv("REC_NS_CONTAINER", ""); nsContainer != "" {
		recCfg.NSContainer = nsContainer
	}
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

	// ------- Start REC capture (non-blocking, non-fatal) -------
	if err := collector.Start(ctx); err != nil {
		log.Printf("[observer] REC failed to start: %v (continuing without evidence capture)", err)
	}

	// ------- Check LLM availability (non-blocking) -------
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
	go func() {
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
				log.Printf("[observer] Pipeline: processed=%d pattern_hits=%d llm_calls=%d llm_errors=%d learned=%d",
					aStats.TotalProcessed, aStats.PatternHits, aStats.LLMCalls, aStats.LLMErrors, aStats.PatternsLearned)
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
	}()

	// ------- Re-Classification Cache -------
	reclassCache := newReclassCache()

	// ------- Alert Coordinator ("Forensic Huddle") -------
	// Instead of dispatching alerts immediately, evidence-eligible HTTP alerts
	// go into a short holding period. Sibling logs from other containers join
	// the same investigation. REC captures the response. Re-classification
	// cache or LLM determines if the attack actually succeeded.
	//
	// Non-HTTP alerts (SSH, sudo, kernel) bypass the coordinator entirely.
	alertCoordinator := coordinator.New(
		ctx,
		coordinator.DefaultConfig(),

		// Dispatch callback — called when an investigation concludes
		func(alert coordinator.FinalAlert) {
			if alert.Downgraded {
				log.Printf("[DOWNGRADED] EventID=%s key=%s events=%d Original→recon_failed Reason=%s",
					alert.EventID, alert.ScopeKey, alert.EventCount, alert.DowngradeReason)
				log.Printf("[INFO] EventID=%s Source=%s OriginalReason=%s DowngradedReason=%s %s Line=%s",
					alert.EventID, alert.ScopeKey, alert.Reason, alert.DowngradeReason,
					alert.EvidenceJournal, truncate(alert.Line, 200))
				// No email — attack was ignored by the server
				return
			}

			// Not downgraded — dispatch the alert
			if alert.BuildAlert != nil {
				builtAlert, ok := alert.BuildAlert().(notifier.Alert)
				if ok {
					severity := "ALERT"
					if alert.Severity == "suspicious" {
						severity = "SUSPICIOUS"
					}
					log.Printf("[%s] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s %s Line=%s",
						severity, alert.EventID, alert.ScopeKey, alert.Reason,
						alert.MatchedVia, alert.Hash, alert.EvidenceJournal, truncate(alert.Line, 200))
					dispatch.Dispatch(ctx, builtAlert)
				}
			}
		},

		// Evidence check callback — called periodically by the coordinator
		// to see if REC evidence + re-classification can downgrade the alert
		func(pending *coordinator.PendingAlert) (bool, string) {
			method, path, host, statusCode := parseNormalizedLine(pending.NormalizedLine)
			if method == "" {
				return false, "" // non-HTTP, can't check evidence
			}

			evidence := collector.Lookup(rec.LookupRequest{
				Method:          method,
				Path:            path,
				Host:            host,
				SourceContainer: pending.SourceName,
				StatusCode:      statusCode,
				Timestamp:       pending.Timestamp,
				Window:          5 * time.Second, // wider window for coordinator's retry pattern
			})

			if evidence == nil || evidence.SafeBodyPreview == "" || evidence.Transport == nil {
				return false, ""
			}

			// Update pending with evidence info for logging
			pending.EvidenceResult = evidence
			pending.EvidenceJournal = evidence.ForJournal()

			// Determine classification for re-classification
			classification := pending.Classification
			if classification == "" {
				if pending.Verdict == "deny" {
					classification = "malicious"
				} else {
					classification = "suspicious"
				}
			}

			// Check re-classification cache first
			bodyHash := rec.HashBody([]byte(evidence.SafeBodyPreview))
			if cached, ok := reclassCache.get(bodyHash); ok {
				if cached.downgraded {
					log.Printf("[reclassify] Cache hit (redacted_body=%s): downgraded → %s",
						bodyHash[:16], cached.reason)
				}
				return cached.downgraded, cached.reason
			}

			// Cache miss — call LLM for re-classification
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

			reclassCache.put(bodyHash, reclass.Downgraded, reclass.Reason)

			if reclass.Downgraded {
				log.Printf("[DOWNGRADED] Original=%s→%s Reason=%s",
					classification, reclass.Classification, reclass.Reason)
			}
			return reclass.Downgraded, reclass.Reason
		},
	)

	// ------- Log handler: the core pipeline -------
	handler := func(line watcher.LogLine) {
		// Skip excluded containers (prevents feedback loops)
		if excludeContainers[line.ContainerName] {
			return
		}

		// Convert watcher.LogLine → event.Event
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

		result := a.Analyze(ctx, evt)

		// Build the alert snapshot ONCE from this specific event+result pair.
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
		case patternstore.VerdictAllow:
			return

		case patternstore.VerdictSuppress:
			return

		case patternstore.VerdictDeny, patternstore.VerdictAlert:
			// Determine if this is an evidence-eligible HTTP alert
			method, path, _, statusCode := parseNormalizedLine(evt.NormalizedLine)
			isHTTP := method != ""

			severity := "malicious"
			notifSeverity := notifier.SeverityMalicious
			if result.Verdict == patternstore.VerdictAlert {
				severity = "suspicious"
				notifSeverity = notifier.SeveritySuspicious
			}

			if isHTTP && collector.Enabled() {
				// Route through coordinator — hold for evidence
				correlationKey := fmt.Sprintf("%s|%s|%d", method, path, statusCode)

				alertBuilder := func() interface{} {
					// This closure captures the current evt/result — safe because
					// buildAlert already snapshots everything
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
				// Non-HTTP or REC disabled — dispatch immediately, no evidence possible
				log.Printf("[ALERT] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s Line=%s",
					evt.ID, evt.ScopeKey(), result.Reason, result.Source, evt.Hash,
					truncate(evt.Line, 200))
				dispatch.Dispatch(ctx, buildAlert(notifSeverity, nil))
			}

		case patternstore.VerdictUnknown:
			if result.Source == "error" {
				log.Printf("[LLM_ERROR] Source=%s Line=%s", evt.ScopeKey(), truncate(evt.Line, 100))
			}
		}
	}

	// ------- Start watching -------
	w := watcher.New(dockerSocket, handler)
	w.SetSelfID(selfID)

	log.Println("[observer] Starting container log watcher...")
	if err := w.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("[observer] Watcher error: %v", err)
	}

	// Final persist on shutdown
	if err := a.Persist(); err != nil {
		log.Printf("[observer] Failed final persist: %v", err)
	}

	aStats := a.GetStats()
	log.Printf("[observer] Final stats: processed=%d pattern_hits=%d llm_calls=%d learned=%d",
		aStats.TotalProcessed, aStats.PatternHits, aStats.LLMCalls, aStats.PatternsLearned)
	log.Println("[observer] Shutdown complete")
}

// seedDenyPatterns adds curated attack indicators to the global deny list.
// These are seeded (manually chosen), not learned — they apply to all sources.
func seedDenyPatterns(store *patternstore.Store) {
	patterns := []struct {
		pattern string
		reason  string
	}{
		{"rm -rf /", "Destructive filesystem command"},
		{"chmod 777", "Overly permissive file permissions"},
		{"/etc/shadow", "Shadow password file access"},
		{"/etc/passwd", "Password file access"},
		{"reverse shell", "Reverse shell keyword"},
		{"nc -e /bin/sh", "Netcat reverse shell"},
		{"bash -i >& /dev/tcp", "Bash reverse shell"},
		{"curl | sh", "Remote code execution via curl pipe"},
		{"wget | sh", "Remote code execution via wget pipe"},
		{"base64 -d | bash", "Encoded command execution"},
		{"python -c 'import socket", "Python reverse shell"},
		{"perl -e 'use Socket", "Perl reverse shell"},
		{"phpinfo()", "PHP information disclosure"},
		{"../../etc/passwd", "Path traversal attack"},
		{"UNION SELECT", "SQL injection"},
		{"DROP TABLE", "SQL injection / destructive query"},
		{"; ls -la", "Command injection"},
		{"&& cat /etc", "Command injection"},
		{"curl ifconfig.me", "External IP reconnaissance"},
		{"wget -q -O-", "Stealthy remote download"},
		{".bash_history", "History file access"},
		{"authorized_keys", "SSH key manipulation"},
		{"crontab -e", "Cron job modification"},
		{"iptables -F", "Firewall flush"},
	}
	for _, p := range patterns {
		store.SeedDenyPattern(p.pattern, p.reason)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// reNormalizedHTTPHosted matches normalized nginx access log format WITH hostname prefix:
//   HOST METHOD /path?query HTTP/X.X STATUS
// Example: "api.admin.kovicloud.com GET /?q=UNION+SELECT HTTP/2.0 200"
var reNormalizedHTTPHosted = regexp.MustCompile(
	`^(\S+)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/\S+\s+(\d{3})`)

// reNormalizedHTTPQuoted finds an HTTP request line inside quotes anywhere in the line.
// Matches the request inside "METHOD /path HTTP/X.X" and a status code after.
// Handles both generic-normalized lines (where the method is buried mid-line inside quotes)
// and bare lines where the method is at the start.
// Example: `<IP> - - [<TS>] "GET /?q=UNION+SELECT HTTP/1.0" 200 <NUM>`
var reNormalizedHTTPQuoted = regexp.MustCompile(
	`"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/\S+"\s+(\d{3})`)

// reNormalizedHTTPBare matches when the method is at the start of the line (no hostname, no quotes).
// Example: "GET /?q=UNION+SELECT+1,2,3 HTTP/1.0 200"
var reNormalizedHTTPBare = regexp.MustCompile(
	`^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/\S+\s+(\d{3})`)

// parseNormalizedLine extracts HTTP components from a normalized log line.
// Handles three formats (tried in order):
//   1. Hostname-prefixed (CapRover nginx): "host.com GET /path HTTP/2.0 200"
//   2. Quoted request line (generic normalizer): `<IP> ... "GET /path HTTP/1.0" 200`
//   3. Bare (no hostname, no quotes): "GET /path HTTP/1.0 200"
// Returns method, path, host, statusCode. Zero values for non-HTTP logs.
func parseNormalizedLine(normalized string) (method, path, host string, statusCode int) {
	// Try hostname-prefixed format first (CapRover nginx normalizer)
	m := reNormalizedHTTPHosted.FindStringSubmatch(normalized)
	if m != nil {
		code, _ := strconv.Atoi(m[4])
		return m[2], m[3], m[1], code
	}

	// Try quoted request line (generic normalizer wraps request in quotes)
	m = reNormalizedHTTPQuoted.FindStringSubmatch(normalized)
	if m != nil {
		code, _ := strconv.Atoi(m[3])
		return m[1], m[2], "", code
	}

	// Try bare format (no hostname, no quotes)
	m = reNormalizedHTTPBare.FindStringSubmatch(normalized)
	if m != nil {
		code, _ := strconv.Atoi(m[3])
		return m[1], m[2], "", code
	}

	return "", "", "", 0
}

// =============================================================================
// Re-Classification Cache
// =============================================================================
//
// When the LLM re-classifies an alert with response evidence, we cache the
// result keyed on the REDACTED BODY PREVIEW HASH.
//
// WHY BODY HASH:
//   The response body IS the evidence. Same body = same conclusion.
//   The Laravel welcome page is always the Laravel welcome page, whether
//   the attack was SQL injection, path traversal, or command injection.
//   If the body changes (app update, different error page, or the attack
//   actually succeeded and returned real data), the hash changes and we
//   call the LLM fresh.
//
// COST IMPACT:
//   Without cache: 100 identical attacks × 2 LLM calls each = 200 calls/day
//   With cache: 1 LLM classify + 1 LLM re-classify + 198 cache hits = 2 calls/day
//   At $1.35/500K tokens, this is the difference between pennies and dollars.
//
// MEMORY:
//   Bounded to 1000 entries. In practice, a server has a small number of
//   distinct response bodies (welcome page, 404 page, API status, etc.)
//   so this rarely exceeds a dozen entries.

const maxReclassCacheEntries = 1000

type reclassCacheEntry struct {
	downgraded bool
	reason     string
}

type reclassCache struct {
	mu      sync.RWMutex
	entries map[string]reclassCacheEntry // bodyPreviewHash → result
}

func newReclassCache() *reclassCache {
	return &reclassCache{
		entries: make(map[string]reclassCacheEntry),
	}
}

func (c *reclassCache) get(bodyHash string) (reclassCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[bodyHash]
	return entry, ok
}

func (c *reclassCache) put(bodyHash string, downgraded bool, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Bounded: if cache is full, clear it and start fresh.
	// In practice this almost never happens — distinct response bodies
	// are a small set (welcome page, 404, API status, etc.)
	if len(c.entries) >= maxReclassCacheEntries {
		c.entries = make(map[string]reclassCacheEntry)
	}

	c.entries[bodyHash] = reclassCacheEntry{
		downgraded: downgraded,
		reason:     reason,
	}
}