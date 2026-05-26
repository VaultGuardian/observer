// config_test.go
package main

import (
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
// still-streaming response is not truncated") is not asserted here — it needs a
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
