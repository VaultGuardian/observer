package normalizer

import (
	"testing"

	"github.com/vaultguardian/logwatch/internal/event"
)

// TestDockerFramingStrip verifies that Docker framing is stripped upstream
// in NormalizeEvent, so normalizers never see it.
func TestDockerFramingStrip(t *testing.T) {
	reg := NewRegistry()

	tests := []struct {
		name     string
		raw      string // raw line as received from Docker watcher (with timestamp)
		stripped string // what the normalizer should see (no Docker framing)
	}{
		{
			name:     "ISO timestamp with nanoseconds",
			raw:      "2026-03-18T22:32:28.411683956Z 172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
			stripped: "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
		},
		{
			name:     "ISO timestamp with fewer decimal places",
			raw:      "2026-03-18T22:32:28.41168Z 172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
			stripped: "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
		},
		{
			name:     "No Docker timestamp (non-Docker source)",
			raw:      "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
			stripped: "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripCollectorFraming(tt.raw)
			if result != tt.stripped {
				t.Errorf("stripCollectorFraming()\ngot:  %q\nwant: %q", result, tt.stripped)
			}
		})
	}

	// Verify that two lines differing ONLY in Docker timestamp precision
	// produce the SAME normalized output and hash.
	t.Run("timestamp precision does not affect hash", func(t *testing.T) {
		e1 := &event.Event{
			SourceType: "docker",
			SourceName: "demo-nginx",
			Line:       "2026-03-18T22:32:28.411683956Z 172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /;ls+-la HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\" \"-\"",
		}
		e2 := &event.Event{
			SourceType: "docker",
			SourceName: "demo-nginx",
			Line:       "2026-03-18T22:33:17.987654321Z 172.19.0.1 - - [18/Mar/2026:22:33:17 +0000] \"GET /;ls+-la HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\" \"-\"",
		}

		reg.NormalizeEvent(e1)
		reg.NormalizeEvent(e2)

		if e1.Hash != e2.Hash {
			t.Errorf("Same access log with different timestamps produced different hashes!\n  e1.Normalized: %q\n  e2.Normalized: %q\n  e1.Hash: %s\n  e2.Hash: %s",
				e1.NormalizedLine, e2.NormalizedLine, e1.Hash, e2.Hash)
		}
	})
}

// TestNginxAccessLogStability verifies that structurally identical nginx
// access logs produce identical normalized output regardless of variable fields.
func TestNginxAccessLogStability(t *testing.T) {
	reg := NewRegistry()

	tests := []struct {
		name  string
		lines []string // all of these should produce the same hash
	}{
		{
			name: "same GET with different timestamps and PIDs",
			lines: []string{
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
				"172.19.0.1 - - [18/Mar/2026:22:33:17 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
				"10.0.0.5 - - [19/Mar/2026:01:00:00 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
			},
		},
		{
			name: "same GET with different byte counts",
			lines: []string{
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 1024 \"-\" \"curl/8.5.0\" \"-\"",
			},
		},
		{
			name: "same GET with different user-agents",
			lines: []string{
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\" \"-\"",
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"python-requests/2.31.0\" \"-\"",
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"some-unknown-bot/1.0\" \"-\"",
			},
		},
		{
			name: "same GET with different referrers",
			lines: []string{
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"https://google.com/search?q=test\" \"curl/8.5.0\" \"-\"",
			},
		},
		{
			name: "attack: command injection from different clients",
			lines: []string{
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /;ls+-la HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\" \"-\"",
				"10.0.0.99 - - [19/Mar/2026:03:15:42 +0000] \"GET /;ls+-la HTTP/1.1\" 404 153 \"-\" \"Mozilla/5.0\" \"-\"",
			},
		},
		{
			name: "attack: path traversal from different IPs",
			lines: []string{
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /../../etc/passwd HTTP/1.1\" 400 157 \"-\" \"curl/8.5.0\" \"-\"",
				"192.168.1.50 - - [20/Mar/2026:10:00:00 +0000] \"GET /../../etc/passwd HTTP/1.1\" 400 163 \"-\" \"wget/1.21\" \"-\"",
			},
		},
		{
			name: "attack: SQL injection with different params",
			lines: []string{
				"172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /?q=UNION+SELECT+1,2,3 HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
				"172.19.0.1 - - [18/Mar/2026:22:34:00 +0000] \"GET /?q=UNION+SELECT+1,2,3 HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var firstHash, firstNorm string
			for i, line := range tt.lines {
				evt := &event.Event{
					SourceType: "docker",
					SourceName: "demo-nginx",
					Line:       line,
				}
				reg.NormalizeEvent(evt)

				if i == 0 {
					firstHash = evt.Hash
					firstNorm = evt.NormalizedLine
					t.Logf("Normalized: %q", evt.NormalizedLine)
				} else if evt.Hash != firstHash {
					t.Errorf("Line %d produced different hash!\n  line[0] normalized: %q\n  line[%d] normalized: %q",
						i, firstNorm, i, evt.NormalizedLine)
				}
			}
		})
	}
}

// TestNginxErrorLogStability verifies error log normalization consistency.
func TestNginxErrorLogStability(t *testing.T) {
	reg := NewRegistry()

	tests := []struct {
		name  string
		lines []string
	}{
		{
			name: "same error with different PIDs and connection numbers",
			lines: []string{
				"2026/03/18 22:32:28 [error] 31#31: *2 open() \"/usr/share/nginx/html/;ls+-la\" failed (2: No such file or directory), client: 172.19.0.1, server: localhost, request: \"GET /;ls+-la HTTP/1.1\", host: \"localhost:8080\"",
				"2026/03/18 22:33:17 [error] 35#35: *5 open() \"/usr/share/nginx/html/;ls+-la\" failed (2: No such file or directory), client: 172.19.0.1, server: localhost, request: \"GET /;ls+-la HTTP/1.1\", host: \"localhost:8080\"",
			},
		},
		{
			name: "same error with different client IPs",
			lines: []string{
				"2026/03/18 22:32:28 [error] 31#31: *2 open() \"/usr/share/nginx/html/favicon.ico\" failed (2: No such file or directory), client: 172.19.0.1, server: localhost, request: \"GET /favicon.ico HTTP/1.1\", host: \"localhost:8080\"",
				"2026/03/18 22:32:28 [error] 31#31: *2 open() \"/usr/share/nginx/html/favicon.ico\" failed (2: No such file or directory), client: 10.0.0.99, server: localhost, request: \"GET /favicon.ico HTTP/1.1\", host: \"localhost:8080\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var firstHash, firstNorm string
			for i, line := range tt.lines {
				evt := &event.Event{
					SourceType: "docker",
					SourceName: "demo-nginx",
					Line:       line,
				}
				reg.NormalizeEvent(evt)

				if i == 0 {
					firstHash = evt.Hash
					firstNorm = evt.NormalizedLine
					t.Logf("Normalized: %q", evt.NormalizedLine)
				} else if evt.Hash != firstHash {
					t.Errorf("Line %d produced different hash!\n  line[0] normalized: %q\n  line[%d] normalized: %q",
						i, firstNorm, i, evt.NormalizedLine)
				}
			}
		})
	}
}

// TestNginxWorkerProcessNormalization verifies that nginx startup logs like
// "start worker process 31" and "start worker process 32" hash the same.
// This was a known issue — the generic normalizer only strips 4+ digit numbers.
func TestNginxWorkerProcessNormalization(t *testing.T) {
	reg := NewRegistry()

	lines := []string{
		"2026/03/18 22:31:10 [notice] 1#1: start worker process 30",
		"2026/03/18 22:31:10 [notice] 1#1: start worker process 31",
		"2026/03/18 22:31:10 [notice] 1#1: start worker process 32",
	}

	var firstHash, firstNorm string
	for i, line := range lines {
		evt := &event.Event{
			SourceType: "docker",
			SourceName: "demo-nginx",
			Line:       line,
		}
		reg.NormalizeEvent(evt)

		if i == 0 {
			firstHash = evt.Hash
			firstNorm = evt.NormalizedLine
			t.Logf("Normalized: %q", evt.NormalizedLine)
		} else if evt.Hash != firstHash {
			t.Errorf("Worker process %d produced different hash!\n  line[0] normalized: %q\n  line[%d] normalized: %q",
				i, firstNorm, i, evt.NormalizedLine)
		}
	}
}

// TestDockerTimestampPlusNginxAccess is the specific bug that was caught in testing:
// nginx access log WITH Docker timestamp prefix produced inconsistent hashes.
func TestDockerTimestampPlusNginxAccess(t *testing.T) {
	reg := NewRegistry()

	// These are the exact lines that come from Docker with timestamps=true
	lines := []string{
		"2026-03-18T22:32:28.411683956Z 172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /;ls+-la HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\" \"-\"",
		"2026-03-18T22:33:17.987654321Z 172.19.0.1 - - [18/Mar/2026:22:33:17 +0000] \"GET /;ls+-la HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\" \"-\"",
	}

	var firstHash, firstNorm string
	for i, line := range lines {
		evt := &event.Event{
			SourceType: "docker",
			SourceName: "demo-nginx",
			Line:       line,
		}
		reg.NormalizeEvent(evt)

		if i == 0 {
			firstHash = evt.Hash
			firstNorm = evt.NormalizedLine
			t.Logf("Normalized: %q", evt.NormalizedLine)
		} else if evt.Hash != firstHash {
			t.Errorf("REGRESSION: Docker timestamp prefix caused hash instability!\n  line[0] normalized: %q\n  line[%d] normalized: %q",
				firstNorm, i, evt.NormalizedLine)
		}
	}
}

// TestDockerTimestampPlusNginxError — same test for error logs.
func TestDockerTimestampPlusNginxError(t *testing.T) {
	reg := NewRegistry()

	lines := []string{
		"2026-03-18T22:32:28.411683956Z 2026/03/18 22:32:28 [error] 31#31: *2 open() \"/usr/share/nginx/html/;ls+-la\" failed (2: No such file or directory), client: 172.19.0.1, server: localhost, request: \"GET /;ls+-la HTTP/1.1\", host: \"localhost:8080\"",
		"2026-03-18T22:33:17.123456789Z 2026/03/18 22:33:17 [error] 35#35: *5 open() \"/usr/share/nginx/html/;ls+-la\" failed (2: No such file or directory), client: 172.19.0.1, server: localhost, request: \"GET /;ls+-la HTTP/1.1\", host: \"localhost:8080\"",
	}

	var firstHash, firstNorm string
	for i, line := range lines {
		evt := &event.Event{
			SourceType: "docker",
			SourceName: "demo-nginx",
			Line:       line,
		}
		reg.NormalizeEvent(evt)

		if i == 0 {
			firstHash = evt.Hash
			firstNorm = evt.NormalizedLine
			t.Logf("Normalized: %q", evt.NormalizedLine)
		} else if evt.Hash != firstHash {
			t.Errorf("REGRESSION: Docker timestamp prefix caused hash instability!\n  line[0] normalized: %q\n  line[%d] normalized: %q",
				firstNorm, i, evt.NormalizedLine)
		}
	}
}

// TestRegistryFuzzyLookup verifies that "demo-nginx" routes to NginxNormalizer.
func TestRegistryFuzzyLookup(t *testing.T) {
	reg := NewRegistry()

	tests := []struct {
		sourceType string
		sourceName string
		wantFamily string
	}{
		{"docker", "nginx", "nginx"},
		{"docker", "demo-nginx", "nginx"},
		{"docker", "my-postgres-db", "postgres"},
		{"docker", "prod-nginx-proxy", "nginx"},
		{"docker", "unknown-app", "docker"},       // falls to source type
		{"systemd", "sshd", "sshd"},               // exact match
		{"systemd", "unknown-service", "generic"},  // no match, no "systemd" normalizer in registry... wait, there is no systemd normalizer. Falls to generic.
	}

	for _, tt := range tests {
		t.Run(tt.sourceType+":"+tt.sourceName, func(t *testing.T) {
			evt := &event.Event{
				SourceType: tt.sourceType,
				SourceName: tt.sourceName,
			}
			n := reg.Lookup(evt)
			if n.Family() != tt.wantFamily {
				t.Errorf("Lookup(%s:%s) = %q, want %q", tt.sourceType, tt.sourceName, n.Family(), tt.wantFamily)
			}
		})
	}
}

// TestDifferentAttacksShouldNotMatch verifies that different attack types
// produce DIFFERENT hashes (we don't want over-normalization).
func TestDifferentAttacksShouldNotMatch(t *testing.T) {
	reg := NewRegistry()

	attacks := []struct {
		name string
		line string
	}{
		{"command injection", "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /;ls+-la HTTP/1.1\" 404 153 \"-\" \"curl/8.5.0\" \"-\""},
		{"path traversal", "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /../../etc/passwd HTTP/1.1\" 400 157 \"-\" \"curl/8.5.0\" \"-\""},
		{"SQL injection", "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET /?q=UNION+SELECT+1,2,3 HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\""},
		{"normal GET", "172.19.0.1 - - [18/Mar/2026:22:32:28 +0000] \"GET / HTTP/1.1\" 200 896 \"-\" \"curl/8.5.0\" \"-\""},
	}

	hashes := make(map[string]string) // hash → name
	for _, atk := range attacks {
		evt := &event.Event{
			SourceType: "docker",
			SourceName: "demo-nginx",
			Line:       atk.line,
		}
		reg.NormalizeEvent(evt)
		t.Logf("%s → %q", atk.name, evt.NormalizedLine)

		if prevName, exists := hashes[evt.Hash]; exists {
			t.Errorf("COLLISION: %q and %q produced the same hash! Over-normalization.", atk.name, prevName)
		}
		hashes[evt.Hash] = atk.name
	}
}
