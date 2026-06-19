// hostlabel_test.go
package main

import (
	"net"
	"os"
	"testing"
)

// TestConfigHostnameResolution verifies the alert-label hostname equals
// HOSTNAME when set, and falls back to a non-empty system hostname when unset.
// It deliberately does not assert a specific os.Hostname() value.
func TestConfigHostnameResolution(t *testing.T) {
	prev, had := os.LookupEnv("HOSTNAME")
	t.Cleanup(func() {
		if had {
			os.Setenv("HOSTNAME", prev)
		} else {
			os.Unsetenv("HOSTNAME")
		}
	})

	os.Setenv("HOSTNAME", "edge-99")
	if got := LoadConfig().Hostname; got != "edge-99" {
		t.Errorf("Hostname = %q, want %q", got, "edge-99")
	}

	os.Unsetenv("HOSTNAME")
	if got := LoadConfig().Hostname; got == "" {
		t.Error("Hostname should fall back to a non-empty system hostname when HOSTNAME is unset")
	}
}

// TestDetectPrimaryIP asserts the helper is fail-open: it never panics and
// returns either "" or a parseable IP. No network connectivity is required.
func TestDetectPrimaryIP(t *testing.T) {
	ip := detectPrimaryIP()
	if ip != "" && net.ParseIP(ip) == nil {
		t.Errorf("detectPrimaryIP returned non-empty, non-parseable value: %q", ip)
	}
}
