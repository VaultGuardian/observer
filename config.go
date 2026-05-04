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
	RECEnabled    bool
	RECInterface  string
	RECVXLANPort  uint16 // 0 = auto-detect
	RECNSContainer string
	RECVerbose     bool

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
	DashboardPort int
	DashboardKeyFile string
	DashboardBindAddr string
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
		MaxConcurrentLLM: getEnvInt("LLM_SLOTS", 4),
		Tier1Effort:      getEnv("LLM_TIER1_EFFORT", "low"),
		Tier2Effort:      getEnv("LLM_TIER2_EFFORT", "medium"),
		DashboardPort:    9090,
		DashboardKeyFile: getEnv("DASHBOARD_KEY_FILE", "/etc/vaultguardian/dashboard.key"),
		DashboardBindAddr: getEnv("DASHBOARD_BIND_ADDR", "127.0.0.1"),

		// REC reassembly tuning — response-only, bounds are tunable.
		RECReassemblyMaxBody:                 getEnvInt("REC_REASSEMBLY_MAX_BODY", 2048),
		RECReassemblyStreamTTL:               getEnvDuration("REC_REASSEMBLY_STREAM_TTL", 5*time.Second),
		RECReassemblyIdleTimeout:             getEnvDuration("REC_REASSEMBLY_IDLE_TIMEOUT", 2*time.Second),
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

	// Parse VXLAN port
	if portStr := getEnv("REC_VXLAN_PORT", ""); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port < 65536 {
			cfg.RECVXLANPort = uint16(port)
		} else {
			log.Printf("[observer] Invalid REC_VXLAN_PORT=%q — using auto-detect", portStr)
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