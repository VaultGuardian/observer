package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all Observer configuration loaded from environment variables.
type Config struct {
	// Core
	DockerSocket      string
	DataDir           string
	LLMURL            string
	LLMModel          string
	LLMAPIKey         string
	SelfID            string
	ExcludeContainers map[string]bool

	// Response Evidence Capture
	RECEnabled     bool
	RECInterface   string
	RECVXLANPort   uint16 // 0 = auto-detect
	RECNSContainer string
	RECVerbose     bool

	// RECExcludeContainers is the REC_EXCLUDE_CONTAINERS set (comma-separated
	// container names). Session 2: dry-run inventory annotation only.
	RECExcludeContainers map[string]bool

	// RECMaxNamespaces caps how many discovered public-facing containers
	// auto-detect mode monitors concurrently. Default 16. Excess containers
	// are dropped (sorted by name) and logged as security blind spots.
	RECMaxNamespaces int

	// REC port discovery.
	//
	// RECPorts seeds the port set REC treats as HTTP-bearing. The sniffer
	// also learns ports at runtime from payload prefixes, so this is a
	// hint, not a hard gate. Default {80, 8080} covers the common case
	// (nginx → backend on 80). Override with REC_PORTS=80,8080,3000,...
	// to seed non-default backends explicitly.
	RECPorts []int

	// RECLearnedPortCap bounds runtime port learning. Once this many
	// ports have been learned beyond the seeded set, additional learns
	// are silently refused. Set REC_LEARNED_PORT_CAP=0 to disable
	// runtime learning entirely.
	RECLearnedPortCap int

	// REC evidence buffer tuning (v1.0 burst hardening).
	// Overridable via REC_BUFFER_* env vars so operators can tune
	// without rebuilds.
	//
	// Memory pressure is now the primary eviction trigger: the byte ceiling
	// is min(RECBufferMaxBytes, RECBufferMaxMB*1MB), and entries live up to
	// RECBufferMaxAge (10m) as a relaxed safety backstop. The long age window
	// is deliberate — during scanner bursts the LLM inference pipeline can
	// queue 30–60s+ of work, so a tight 30s age cap evicted REC responses
	// before the coordinator's evidence check could read them. RECBufferMaxMB
	// (default 64) is the preferred operator dial and tightens the effective
	// ceiling vs. the legacy 128MB to offset the 20× longer retention window.
	RECBufferMaxEntries int
	RECBufferMaxBytes   int64
	RECBufferMaxMB      int
	RECBufferMaxAge     time.Duration
	RECBufferMaxBody    int

	// REC reassembly tuning (response-only as of v0.42.7)
	RECReassemblyMaxBody                 int
	RECReassemblyStreamTTL               time.Duration
	RECReassemblyIdleTimeout             time.Duration
	RECReassemblyMaxBufferedPagesTotal   int
	RECReassemblyMaxBufferedPagesPerConn int
	RECReassemblyMaxActiveStreams        int

	// REC flow pairing bounds (v0.42.7)
	RECFlowMaxStates         int
	RECFlowMaxReqPerFlow     int
	RECFlowMaxRespPerFlow    int
	RECFlowRespOrphanTimeout time.Duration
	RECFlowReqExpireTimeout  time.Duration

	// LLM concurrency
	MaxConcurrentLLM int

	// Journald watcher
	JournaldEnabled bool
	ExcludeUnits    map[string]bool

	// LLM reasoning effort per tier
	Tier1Effort string // "low", "medium", "high" — default "low"
	Tier2Effort string // "low", "medium", "high" — default "medium"

	// Dashboard API
	DashboardPort           int
	DashboardKeyFile        string
	DashboardBindAddr       string
	DashboardAllowedOrigins []string
}

// LoadConfig reads configuration from environment variables with sane defaults.
func LoadConfig() Config {
	cfg := Config{
		DockerSocket:     getEnv("DOCKER_SOCKET", "/var/run/docker.sock"),
		DataDir:          getEnv("DATA_DIR", "/data"),
		LLMURL:           getEnv("LLM_URL", "http://llm:11434"),
		LLMModel:         getEnv("LLM_MODEL", "qwen2.5:7b"),
		LLMAPIKey:        getEnv("LLM_API_KEY", ""),
		SelfID:           getEnv("HOSTNAME", ""),
		RECEnabled:       getEnv("REC_ENABLED", "") == "true",
		RECInterface:     getEnv("REC_INTERFACE", ""),
		RECNSContainer:   getEnv("REC_NS_CONTAINER", ""),
		RECVerbose:       getEnv("REC_VERBOSE", "") == "true",
		RECMaxNamespaces: getEnvInt("REC_MAX_NAMESPACES", 16),
		// REC_LEARNED_PORT_CAP allows zero (= disable learning).
		// Resolved below since getEnvInt rejects non-positive values.
		RECLearnedPortCap: 64,

		// REC evidence buffer (v1.0 burst hardening).
		RECBufferMaxEntries: getEnvInt("REC_BUFFER_MAX_ENTRIES", 10000),
		RECBufferMaxBytes:   getEnvInt64("REC_BUFFER_MAX_BYTES", 128*1024*1024),
		RECBufferMaxMB:      getEnvInt("REC_BUFFER_MAX_MB", 64),
		RECBufferMaxAge:     getEnvDuration("REC_BUFFER_MAX_AGE", 10*time.Minute),
		RECBufferMaxBody:    getEnvInt("REC_BUFFER_MAX_BODY", 2048),
		MaxConcurrentLLM:    getEnvInt("LLM_SLOTS", 4),
		Tier1Effort:         getEnv("LLM_TIER1_EFFORT", "low"),
		Tier2Effort:         getEnv("LLM_TIER2_EFFORT", "medium"),
		DashboardPort:       9090,
		DashboardKeyFile:    getEnv("DASHBOARD_KEY_FILE", "/etc/vaultguardian/dashboard.key"),
		DashboardBindAddr:   getEnv("DASHBOARD_BIND_ADDR", "127.0.0.1"),

		// REC reassembly tuning — response-only, bounds are tunable.
		RECReassemblyMaxBody:   getEnvInt("REC_REASSEMBLY_MAX_BODY", 2048),
		RECReassemblyStreamTTL: getEnvDuration("REC_REASSEMBLY_STREAM_TTL", 5*time.Second),
		// 250ms (was 2s): a completed response should not wait on a 2s idle
		// flush before REC emits it — fast pattern-path finalizes were beating
		// the evidence into the coordinator, yielding "no response captured".
		// This SHRINKS the race window (worst case ~450ms with the 200ms
		// flushLoop tick); it does not make races impossible. Idle-only flush
		// means active/large transfers are never truncated. Env-overridable via
		// REC_REASSEMBLY_IDLE_TIMEOUT.
		RECReassemblyIdleTimeout:             getEnvDuration("REC_REASSEMBLY_IDLE_TIMEOUT", 250*time.Millisecond),
		RECReassemblyMaxBufferedPagesTotal:   getEnvInt("REC_REASSEMBLY_MAX_BUFFERED_PAGES_TOTAL", 4096),
		RECReassemblyMaxBufferedPagesPerConn: getEnvInt("REC_REASSEMBLY_MAX_BUFFERED_PAGES_PER_CONN", 16),
		RECReassemblyMaxActiveStreams:        getEnvInt("REC_REASSEMBLY_MAX_ACTIVE_STREAMS", 10000),

		// REC flow pairing bounds.
		RECFlowMaxStates:         getEnvInt("REC_FLOW_MAX_STATES", 50000),
		RECFlowMaxReqPerFlow:     getEnvInt("REC_FLOW_MAX_REQ_PER_FLOW", 64),
		RECFlowMaxRespPerFlow:    getEnvInt("REC_FLOW_MAX_RESP_PER_FLOW", 64),
		RECFlowRespOrphanTimeout: getEnvDuration("REC_FLOW_RESP_ORPHAN_TIMEOUT", 2*time.Second),
		RECFlowReqExpireTimeout:  getEnvDuration("REC_FLOW_REQ_EXPIRE_TIMEOUT", 30*time.Second),
	}

	// Parse dashboard port
	if portStr := getEnv("DASHBOARD_PORT", ""); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port < 65536 {
			cfg.DashboardPort = port
		}
	}

	// Parse dashboard CORS allowlist (comma-separated origins).
	// Empty default = no CORS headers set on responses (safer than wildcard).
	// Set to e.g. "https://vaultguardian.io,http://localhost:3000" for hosted dashboards.
	if raw := getEnv("DASHBOARD_ALLOWED_ORIGINS", ""); raw != "" {
		for _, origin := range strings.Split(raw, ",") {
			if o := strings.TrimSpace(origin); o != "" {
				cfg.DashboardAllowedOrigins = append(cfg.DashboardAllowedOrigins, o)
			}
		}
	}

	// Build exclusion set from comma-separated container names
	cfg.ExcludeContainers = make(map[string]bool)
	if raw := getEnv("EXCLUDE_CONTAINERS", ""); raw != "" {
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.ExcludeContainers[name] = true
			}
		}
		log.Printf("[observer] Excluding containers: %s", raw)
	}

	// REC_EXCLUDE_CONTAINERS — containers to exclude from REC namespace
	// monitoring. Session 2 uses this only to annotate the dry-run discovery
	// inventory; matching normalizes both sides (base name, lowercased) inside
	// the rec package, so a Swarm-suffixed or differently-cased name still matches.
	cfg.RECExcludeContainers = make(map[string]bool)
	if raw := getEnv("REC_EXCLUDE_CONTAINERS", ""); raw != "" {
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.RECExcludeContainers[name] = true
			}
		}
		log.Printf("[rec] REC_EXCLUDE_CONTAINERS: %s", raw)
	}

	// Parse VXLAN port
	if portStr := getEnv("REC_VXLAN_PORT", ""); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port < 65536 {
			cfg.RECVXLANPort = uint16(port)
		} else {
			log.Printf("[observer] Invalid REC_VXLAN_PORT=%q — using auto-detect", portStr)
		}
	}

	// Parse REC HTTP port set.
	//
	// Default {80, 8080} matches the historical hardcoded behavior.
	// Operators with backends on non-default ports (e.g. CapRover's
	// captain-captain on 3000, app servers on 5000/8000) can seed
	// the registry explicitly: REC_PORTS=80,8080,3000.
	//
	// The sniffer learns additional ports at runtime from payload
	// prefixes, so this list is a seed/hint — getting it exactly
	// right is not required for correctness.
	cfg.RECPorts = []int{80, 8080}
	if raw := getEnv("REC_PORTS", ""); raw != "" {
		var parsed []int
		var bad []string
		for _, p := range strings.Split(raw, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				bad = append(bad, p)
				continue
			}
			parsed = append(parsed, n)
		}
		if len(parsed) > 0 {
			cfg.RECPorts = parsed
			log.Printf("[observer] REC_PORTS override: %v", cfg.RECPorts)
		}
		if len(bad) > 0 {
			log.Printf("[observer] REC_PORTS skipped invalid entries: %v", bad)
		}
	}

	// Parse REC learned-port cap. Allows zero (= disable runtime
	// learning entirely; configured set becomes a hard gate again).
	if raw := getEnv("REC_LEARNED_PORT_CAP", ""); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			cfg.RECLearnedPortCap = n
		} else {
			log.Printf("[observer] Invalid REC_LEARNED_PORT_CAP=%q — using default %d", raw, cfg.RECLearnedPortCap)
		}
	}

	// Journald watcher
	cfg.JournaldEnabled = getEnv("JOURNALD_ENABLED", "") == "true"
	cfg.ExcludeUnits = make(map[string]bool)
	if raw := getEnv("JOURNALD_EXCLUDE_UNITS", ""); raw != "" {
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.ExcludeUnits[name] = true
			}
		}
		log.Printf("[observer] Additional journald exclude units: %s", raw)
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func getEnvInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return fallback
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
