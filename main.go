package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vaultguardian/logwatch/internal/analyzer"
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
	if iface := getEnv("REC_INTERFACE", ""); iface != "" {
		recCfg.Interface = iface
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
			}
		}
	}()

	// ------- Log handler: the core pipeline -------
	handler := func(line watcher.LogLine) {
		// Skip excluded containers (prevents feedback loops)
		if excludeContainers[line.ContainerName] {
			return
		}

		// Convert watcher.LogLine → event.Event
		// (The watcher still uses its own struct; this bridges until
		// we refactor it to emit Events directly.)
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
		// All fields come from the same goroutine-local variables — no cross-event contamination.
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

		// lookupEvidence performs REC correlation for alert/deny verdicts.
		// Enrichment-only — never changes the verdict, just attaches evidence.
		lookupEvidence := func() *rec.Evidence {
			method, path, host, statusCode := parseNormalizedLine(evt.NormalizedLine)
			evidence := collector.Lookup(rec.LookupRequest{
				Method:          method,
				Path:            path,
				Host:            host,
				SourceContainer: evt.SourceName,
				StatusCode:      statusCode,
				Timestamp:       evt.Timestamp,
			})
			return evidence
		}

		switch result.Verdict {
		case patternstore.VerdictAllow:
			// Known-good, skip silently
			return

		case patternstore.VerdictSuppress:
			// Known-noise, skip silently
			return

		case patternstore.VerdictDeny:
			// ALERT! Known-bad or LLM-classified malicious
			evidence := lookupEvidence()
			log.Printf("[ALERT] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s %s Line=%s",
				evt.ID, evt.ScopeKey(), result.Reason, result.Source, evt.Hash,
				evidence.ForJournal(), truncate(evt.Line, 200))

			dispatch.Dispatch(ctx, buildAlert(notifier.SeverityMalicious, evidence))

		case patternstore.VerdictAlert:
			// SUSPICIOUS — LLM flagged as suspicious, or memoized repeat of same.
			evidence := lookupEvidence()
			log.Printf("[SUSPICIOUS] EventID=%s Source=%s Reason=%s MatchedVia=%s Hash=%s %s Line=%s",
				evt.ID, evt.ScopeKey(), result.Reason, result.Source, evt.Hash,
				evidence.ForJournal(), truncate(evt.Line, 200))

			dispatch.Dispatch(ctx, buildAlert(notifier.SeveritySuspicious, evidence))

		case patternstore.VerdictUnknown:
			// LLM had an error, was dropped by backpressure, or returned
			// an unrecognized action. Log for debugging but don't alert.
			if result.Source == "error" {
				log.Printf("[LLM_ERROR] Source=%s Line=%s", evt.ScopeKey(), truncate(evt.Line, 100))
			} else if result.Source == "backpressure" {
				// Semaphore was full — line was dropped. Already counted in LLMDropped stat.
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

// reNormalizedHTTP matches the v0.9 normalized nginx access log format:
//   HOST METHOD /path?query HTTP/X.X STATUS
// Example: "api.admin.kovicloud.com GET /?q=UNION+SELECT HTTP/2.0 200"
var reNormalizedHTTP = regexp.MustCompile(
	`^(\S+)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/\S+\s+(\d{3})`)

// parseNormalizedLine extracts HTTP components from a normalized log line.
// Returns method, path (raw with query string), host, and status code.
// For non-HTTP logs (error logs, syslog, etc.), returns zero values — REC
// will return no_match, which is the correct behavior.
func parseNormalizedLine(normalized string) (method, path, host string, statusCode int) {
	m := reNormalizedHTTP.FindStringSubmatch(normalized)
	if m == nil {
		return "", "", "", 0
	}
	code, _ := strconv.Atoi(m[4])
	return m[2], m[3], m[1], code
}