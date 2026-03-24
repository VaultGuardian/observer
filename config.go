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

	// LLM concurrency
	MaxConcurrentLLM int
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
		MaxConcurrentLLM: 2,
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
