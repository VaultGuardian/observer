// internal/rec/autodetect_test.go
package rec

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync/atomic"
	"testing"
)

// pubContainer builds a dockerContainer with one external TCP publish, so it
// classifies as public-facing.
func pubContainer(name string, public, private int) dockerContainer {
	return dockerContainer{
		ID:    name + "-id",
		Names: []string{"/" + name},
		Ports: []dockerPort{{IP: "0.0.0.0", PublicPort: public, PrivatePort: private, Type: "tcp"}},
	}
}

// captureLogs redirects the standard logger to a buffer for the duration of fn,
// returning everything logged.
func captureLogs(fn func()) string {
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()
	fn()
	return buf.String()
}

// autoCtx returns a cancellable context plus a cleanup that cancels it and joins
// capture goroutines (Close), and cancels the parent so vipCleanupLoop exits too.
func autoCtx(t *testing.T, lc *liveCollector) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		lc.Close()
		cancel()
	})
	return ctx
}

// TestAutoDetectPartialFailureAndAggregate: two public containers, one opener
// succeeds and one fails. Both captures exist; one runs, one carries lastError;
// Enabled() is true; Start returns nil; Stats aggregates across both sniffers.
func TestAutoDetectPartialFailureAndAggregate(t *testing.T) {
	lc := bareCollector()
	lc.config.Ports = []int{80}
	lc.config.MaxNamespaces = 16
	ctx := autoCtx(t, lc)

	deps := autoDetectDeps{
		fetch: func() ([]dockerContainer, error) {
			return []dockerContainer{pubContainer("svc-a", 8080, 80), pubContainer("svc-b", 9090, 3000)}, nil
		},
		openerFor: func(pc publicContainer, nc *namespaceCapture) func() (int, error) {
			if pc.Name == "svc-a" {
				return func() (int, error) { return dgramFD(t), nil }
			}
			return func() (int, error) { return -1, errors.New("setns denied") }
		},
		hostOpen: func(nc *namespaceCapture) (int, error) {
			t.Fatal("host fallback must not run when one namespace started")
			return -1, nil
		},
	}

	if err := lc.startAutoDetect(ctx, "", DefaultVXLANPort, deps); err != nil {
		t.Fatalf("startAutoDetect returned error: %v", err)
	}

	if len(lc.captures) != 2 {
		t.Fatalf("captures = %d, want 2", len(lc.captures))
	}
	a, b := lc.captures["svc-a"], lc.captures["svc-b"]
	if a == nil || b == nil {
		t.Fatalf("missing captures: %v", capKeys(lc))
	}
	if !a.running.Load() || a.lastError != "" {
		t.Fatalf("svc-a should be running with no error (running=%v err=%q)", a.running.Load(), a.lastError)
	}
	if b.running.Load() || b.lastError == "" {
		t.Fatalf("svc-b should be stopped with lastError (running=%v err=%q)", b.running.Load(), b.lastError)
	}
	if !lc.Enabled() {
		t.Fatal("Enabled() = false; want true (svc-a active)")
	}

	// Seed the container-side port and confirm it made it into the sniffer's
	// registry (the crux: REC inside svc-b's namespace must watch private 3000).
	if !b.sniffer.ports.has(3000) {
		t.Fatal("svc-b sniffer not seeded with its container-side port 3000")
	}

	// Stats aggregate across both instances' sniffers.
	atomic.AddInt64(&a.sniffer.inlineRequests, 5)
	atomic.AddInt64(&b.sniffer.inlineRequests, 7)
	if got := lc.Stats().InlineRequests; got != 12 {
		t.Fatalf("Stats().InlineRequests = %d, want 12 (aggregate across instances)", got)
	}
}

// TestAutoDetectCap: more public containers than REC_MAX_NAMESPACES → exactly N
// monitored, deterministically by name; the rest dropped (and logged).
func TestAutoDetectCap(t *testing.T) {
	lc := bareCollector()
	lc.config.Ports = []int{80}
	lc.config.MaxNamespaces = 2
	ctx := autoCtx(t, lc)

	deps := autoDetectDeps{
		fetch: func() ([]dockerContainer, error) {
			// Out of order to prove deterministic by-name selection.
			return []dockerContainer{
				pubContainer("d", 80, 80), pubContainer("b", 80, 80),
				pubContainer("a", 80, 80), pubContainer("c", 80, 80),
			}, nil
		},
		openerFor: func(pc publicContainer, nc *namespaceCapture) func() (int, error) {
			return func() (int, error) { return dgramFD(t), nil }
		},
		hostOpen: func(nc *namespaceCapture) (int, error) { t.Fatal("no host fallback expected"); return -1, nil },
	}

	out := captureLogs(func() {
		if err := lc.startAutoDetect(ctx, "", DefaultVXLANPort, deps); err != nil {
			t.Fatalf("startAutoDetect: %v", err)
		}
	})

	if len(lc.captures) != 2 {
		t.Fatalf("captures = %d, want 2 (%v)", len(lc.captures), capKeys(lc))
	}
	if lc.captures["a"] == nil || lc.captures["b"] == nil {
		t.Fatalf("want a,b monitored; got %v", capKeys(lc))
	}
	if lc.captures["c"] != nil || lc.captures["d"] != nil {
		t.Fatalf("c,d must be dropped; got %v", capKeys(lc))
	}
	for _, dropped := range []string{`"c"`, `"d"`} {
		if !strings.Contains(out, "REC_MAX_NAMESPACES=2") || !strings.Contains(out, dropped) {
			t.Fatalf("expected cap-drop log for %s; got:\n%s", dropped, out)
		}
	}
}

// TestAutoDetectFallbacks: Docker-query-fail and zero-public both fall back to a
// single host capture (benign, no degraded warning).
func TestAutoDetectFallbacks(t *testing.T) {
	cases := []struct {
		name  string
		fetch func() ([]dockerContainer, error)
	}{
		{"docker-query-fail", func() ([]dockerContainer, error) { return nil, errors.New("dial unix: no such file") }},
		{"zero-public", func() ([]dockerContainer, error) {
			return []dockerContainer{{
				ID: "dns", Names: []string{"/coredns"},
				Ports: []dockerPort{{IP: "0.0.0.0", PublicPort: 53, PrivatePort: 53, Type: "udp"}},
			}}, nil
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lc := bareCollector()
			lc.config.Ports = []int{80}
			ctx := autoCtx(t, lc)

			hostInvoked := false
			deps := autoDetectDeps{
				fetch: tc.fetch,
				openerFor: func(pc publicContainer, nc *namespaceCapture) func() (int, error) {
					t.Fatal("no namespace opener expected")
					return nil
				},
				hostOpen: func(nc *namespaceCapture) (int, error) { hostInvoked = true; return dgramFD(t), nil },
			}

			out := captureLogs(func() {
				if err := lc.startAutoDetect(ctx, "", DefaultVXLANPort, deps); err != nil {
					t.Fatalf("startAutoDetect: %v", err)
				}
			})

			if !hostInvoked {
				t.Fatal("host fallback opener was not invoked")
			}
			if h := lc.captures["host"]; h == nil || !h.running.Load() {
				t.Fatalf("host capture not running (%v)", capKeys(lc))
			}
			// The benign fallbacks must NOT emit the degraded all-NS-failed warning.
			if strings.Contains(out, "DEGRADED/BLIND") {
				t.Fatalf("benign fallback %s emitted the degraded warning:\n%s", tc.name, out)
			}
		})
	}
}

// TestAutoDetectAllNamespacesFail: public containers exist but EVERY namespace
// opener fails → host fallback, and a DISTINCT degraded warning is emitted that
// the benign fallbacks do not produce.
func TestAutoDetectAllNamespacesFail(t *testing.T) {
	lc := bareCollector()
	lc.config.Ports = []int{80}
	lc.config.MaxNamespaces = 16
	ctx := autoCtx(t, lc)

	hostInvoked := false
	deps := autoDetectDeps{
		fetch: func() ([]dockerContainer, error) {
			return []dockerContainer{pubContainer("svc-a", 8080, 80), pubContainer("svc-b", 9090, 80)}, nil
		},
		openerFor: func(pc publicContainer, nc *namespaceCapture) func() (int, error) {
			return func() (int, error) { return -1, errors.New("setns: operation not permitted") }
		},
		hostOpen: func(nc *namespaceCapture) (int, error) { hostInvoked = true; return dgramFD(t), nil },
	}

	var err error
	out := captureLogs(func() { err = lc.startAutoDetect(ctx, "", DefaultVXLANPort, deps) })
	if err != nil {
		t.Fatalf("startAutoDetect returned error: %v", err)
	}

	if !hostInvoked {
		t.Fatal("host fallback opener was not invoked after all namespaces failed")
	}
	if h := lc.captures["host"]; h == nil || !h.running.Load() {
		t.Fatalf("host capture not running after all-NS-fail (%v)", capKeys(lc))
	}
	// Distinct degraded warning, not the benign fallback wording.
	if !strings.Contains(out, "DEGRADED/BLIND") || !strings.Contains(out, "FAILED to open") {
		t.Fatalf("expected distinct degraded all-NS-failed warning; got:\n%s", out)
	}
}

func capKeys(lc *liveCollector) []string {
	out := make([]string, 0, len(lc.captures))
	for k := range lc.captures {
		out = append(out, k)
	}
	return out
}
