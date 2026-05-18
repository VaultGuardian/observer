package policy

import (
	"regexp"
	"testing"

	"github.com/vaultguardian/observer/internal/event"
)

func TestNormalizeUnit(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ssh.service", "ssh"},
		{"sshd.service", "sshd"},
		{"sshd@1.2.3.4-22.service", "sshd"},
		{"user@1000.service", "user"},
		{"docker-abc123.scope", "docker-abc123"},
		{"session-42.scope", "session-42"},
		{"systemd-resolved.service", "systemd-resolved"},
		{"SSH.SERVICE", "ssh"},
		{"", ""},
		{"plain-no-suffix", "plain-no-suffix"},
	}
	for _, c := range cases {
		got := normalizeUnit(c.in)
		if got != c.want {
			t.Errorf("normalizeUnit(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUnitMatches(t *testing.T) {
	allowed := []string{"ssh", "sshd"}

	yes := []string{
		"ssh.service",
		"sshd.service",
		"sshd@1.2.3.4-22.service",
		"SSH.SERVICE",
	}
	for _, u := range yes {
		if !unitMatches(u, allowed) {
			t.Errorf("unitMatches(%q, %v) = false, want true", u, allowed)
		}
	}

	no := []string{
		"",
		"docker-abc.scope",
		"user@1000.service",
		"nginx.service",
		"sudo",
	}
	for _, u := range no {
		if unitMatches(u, allowed) {
			t.Errorf("unitMatches(%q, %v) = true, want false", u, allowed)
		}
	}
}

// TestEvaluate_KernelUnitFilter exercises the anti-spoof path: a journald
// event with the right SYSLOG_IDENTIFIER but the wrong kernel unit must
// NOT trigger the ssh_login rule.
func TestEvaluate_KernelUnitFilter(t *testing.T) {
	// Build a minimal engine with just one rule so we don't have to
	// worry about trust-check DB lookups.
	rule := Rule{
		ID:               "ssh_login_test",
		SourceType:       "journal",
		MatchKernelUnits: []string{"ssh", "sshd"},
		Pattern:          regexp.MustCompile(`Accepted\s+password\s+for\s+(\S+)\s+from\s+(\S+)`),
		Extract: func(m []string) Result {
			return Result{Username: m[1], SourceIP: m[2], Reason: "test"}
		},
		DefaultAction: "alert",
	}
	e := &Engine{rules: []Rule{rule}}

	tests := []struct {
		name    string
		unit    string
		wantHit bool
	}{
		{"legit ssh.service", "ssh.service", true},
		{"legit sshd.service", "sshd.service", true},
		{"sshd per-connection unit", "sshd@1.2.3.4-22.service", true},
		{"container spoofing — different unit", "docker-abc123.scope", false},
		{"no unit (non-journald event)", "", false},
		{"nginx unit", "nginx.service", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := &event.Event{
				SourceType: "journal",
				SourceName: "sshd", // spoofable — set the same in every case
				Line:       "Accepted password for root from 1.2.3.4 port 22 ssh2",
				Metadata:   map[string]string{"unit": tt.unit},
			}
			result := e.Evaluate(evt)
			if result.Matched != tt.wantHit {
				t.Errorf("unit=%q: Matched=%v, want %v", tt.unit, result.Matched, tt.wantHit)
			}
		})
	}
}
