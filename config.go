package main

import (
	"log"
	"os"
	"strconv"
	"strings"
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
		MaxConcurrentLLM: 2,
		Tier1Effort:      getEnv("LLM_TIER1_EFFORT", "low"),
		Tier2Effort:      getEnv("LLM_TIER2_EFFORT", "medium"),
		DashboardPort:    9090,
		DashboardKeyFile: getEnv("DASHBOARD_KEY_FILE", "/etc/vaultguardian/dashboard.key"),
	}

	// Parse dashboard port
	if portStr := getEnv("DASHBOARD_PORT", ""); portStr != "" {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port < 65536 {
			cfg.DashboardPort = port
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}