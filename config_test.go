// config_test.go
package main

import (
	"slices"
	"testing"
	"time"
)

// Fix 2: the REC reassembly idle timeout default dropped from 2s to 250ms so a
// completed response is emitted promptly (worst case ~450ms with the 200ms
// flushLoop tick) instead of waiting on the old 2s idle flush, which fast
// pattern-path finalizes could beat. The operator override must still win.
//
// TODO(rec): the end-to-end emit-latency behavior ("a complete Content-Length
// response lands in the buffer within ~IdleTimeout of the last packet, and a
// still-streaming response is not truncated") is not asserted here - it needs a
// packet-injection harness to drive the gopacket assembler + flushLoop
// deterministically. That harness is also the prerequisite for testing the
// eager-emit hardening noted in sniffer.go's flushLoop TODO.
func TestRECReassemblyIdleTimeoutDefault(t *testing.T) {
	// Force-unset so a real operator env can't leak into the default check.
	t.Setenv("REC_REASSEMBLY_IDLE_TIMEOUT", "")

	cfg := LoadConfig()
	if cfg.RECReassemblyIdleTimeout != 250*time.Millisecond {
		t.Errorf("default RECReassemblyIdleTimeout = %s; want 250ms", cfg.RECReassemblyIdleTimeout)
	}
}

func TestRECReassemblyIdleTimeoutEnvOverride(t *testing.T) {
	t.Setenv("REC_REASSEMBLY_IDLE_TIMEOUT", "2s")

	cfg := LoadConfig()
	if cfg.RECReassemblyIdleTimeout != 2*time.Second {
		t.Errorf("REC_REASSEMBLY_IDLE_TIMEOUT=2s → %s; want 2s (env override must win)", cfg.RECReassemblyIdleTimeout)
	}
}

// SLOW_RESPONSE_THRESHOLD_MS must accept explicit zero/negative (= gate
// disabled) - getEnvInt rejects non-positive values, so this field is
// resolved by a dedicated block like REC_LEARNED_PORT_CAP.
func TestSlowResponseThresholdMs(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want int
	}{
		{"default", "", 3000},
		{"zero_disables", "0", 0},
		{"negative_disables", "-5", -5},
		{"override", "5000", 5000},
		{"garbage_falls_back", "abc", 3000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SLOW_RESPONSE_THRESHOLD_MS", tc.env)
			cfg := LoadConfig()
			if cfg.SlowResponseThresholdMs != tc.want {
				t.Errorf("SLOW_RESPONSE_THRESHOLD_MS=%q → %d; want %d", tc.env, cfg.SlowResponseThresholdMs, tc.want)
			}
		})
	}
}

// REC_PORTS parsing must collapse duplicates and sort: the parsed list seeds a
// set (the sniffer's port registry dedupes internally, so capture behavior was
// never affected), but it is printed verbatim by the override log and the
// collector startup line, where REC_PORTS=80,80 rendered as [80 80].
func TestRECPortsDedupeAndSort(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want []int
	}{
		{"default", "", []int{80, 8080}},
		{"duplicate_collapses", "80,80", []int{80}},
		{"duplicate_with_spaces", "80, 80", []int{80}},
		{"distinct_sorted", "8080,80,3000", []int{80, 3000, 8080}},
		{"duplicate_among_distinct", "80,3000,80", []int{80, 3000}},
		{"invalid_entries_skipped", "80,abc,80", []int{80}},
		{"all_invalid_falls_back", "abc,-1", []int{80, 8080}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REC_PORTS", tc.env)
			cfg := LoadConfig()
			if !slices.Equal(cfg.RECPorts, tc.want) {
				t.Errorf("REC_PORTS=%q → %v; want %v", tc.env, cfg.RECPorts, tc.want)
			}
		})
	}
}

// [A11] SYNC_URL must be HTTPS. The ingest endpoint carries a bearer token and
// this host's entire security telemetry, so plain HTTP is refused - except
// against loopback, which is how tests and local development point Observer at
// a fake ingest server. A rejected URL disables sync; it never downgrades to
// sending anyway.
func TestSyncURLTransportEnforcement(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		token   string
		enabled bool
	}{
		{"https_allowed", "https://vaultguardian.io", "tok", true},
		{"https_with_path", "https://vaultguardian.io/observer", "tok", true},
		{"plain_http_rejected", "http://example.com", "tok", false},
		{"plain_http_ip_rejected", "http://198.51.100.10", "tok", false},
		{"loopback_ip_allowed", "http://127.0.0.1:9999", "tok", true},
		{"loopback_name_allowed", "http://localhost:3000", "tok", true},
		{"loopback_v6_allowed", "http://[::1]:3000", "tok", true},
		{"other_scheme_rejected", "ftp://example.com", "tok", false},
		{"garbage_rejected", "not a url", "tok", false},
		{"url_without_token_disabled", "https://vaultguardian.io", "", false},
		{"token_without_url_disabled", "", "tok", false},
		{"neither_disabled", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SYNC_URL", tc.url)
			t.Setenv("SYNC_TOKEN", tc.token)

			cfg := LoadConfig()
			if cfg.SyncEnabled != tc.enabled {
				t.Errorf("SYNC_URL=%q SYNC_TOKEN=%q → SyncEnabled=%t; want %t",
					tc.url, tc.token, cfg.SyncEnabled, tc.enabled)
			}
		})
	}
}

// A trailing slash on SYNC_URL must not produce "//api/ingest/..." paths.
func TestSyncURLTrailingSlashTrimmed(t *testing.T) {
	t.Setenv("SYNC_URL", "https://vaultguardian.io/")
	t.Setenv("SYNC_TOKEN", "tok")

	cfg := LoadConfig()
	if cfg.SyncURL != "https://vaultguardian.io" {
		t.Errorf("SyncURL = %q; want the trailing slash trimmed", cfg.SyncURL)
	}
}

// Sync cadences have defaults and honor overrides.
func TestSyncIntervalDefaults(t *testing.T) {
	t.Setenv("SYNC_INTERVAL", "")
	t.Setenv("SYNC_SNAPSHOT_INTERVAL", "")
	t.Setenv("SYNC_HEARTBEAT_INTERVAL", "")

	cfg := LoadConfig()
	if cfg.SyncInterval != 15*time.Second {
		t.Errorf("SyncInterval = %s; want 15s", cfg.SyncInterval)
	}
	if cfg.SyncSnapshotInterval != 5*time.Minute {
		t.Errorf("SyncSnapshotInterval = %s; want 5m", cfg.SyncSnapshotInterval)
	}
	if cfg.SyncHeartbeatInterval != 60*time.Second {
		t.Errorf("SyncHeartbeatInterval = %s; want 60s", cfg.SyncHeartbeatInterval)
	}

	t.Setenv("SYNC_INTERVAL", "45s")
	if got := LoadConfig().SyncInterval; got != 45*time.Second {
		t.Errorf("SYNC_INTERVAL=45s → %s; want 45s", got)
	}
}
