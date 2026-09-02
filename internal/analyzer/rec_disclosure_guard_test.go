package analyzer

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/patternstore"
)

// failedProbeReason is the exact reason string step 1.6 emits for the shared
// test line. Asserted verbatim so a reword is a deliberate, visible change.
const failedProbeReason = "Deterministic: HTTP 404 - no HTTP-visible impact observed"

// hashOf normalizes a copy of the line the same way Analyze does, so a test
// can pre-learn a hash pattern for an event it has not analyzed yet.
func hashOf(t *testing.T, sourceName, line string) string {
	t.Helper()
	evt := testEvent(sourceName, line)
	normalizer.NewRegistry().NormalizeEvent(evt)
	return evt.Hash
}

// TestStep16_RECDisclosureOverrideSkipsSuppression: a line that isFailedProbe
// matches on status alone is NOT suppressed when REC reports a captured body
// with a deterministically disclosing format. The event must continue into
// normal analysis (pattern store, then T1) - the guard skips the suppression
// return, it does not decide a verdict of its own.
func TestStep16_RECDisclosureOverrideSkipsSuppression(t *testing.T) {
	a, patterns := newScopeTestAnalyzer(t, "http://unused.invalid", newCountingScheduler(1))

	// Pre-learn an alert hash for the probe line. Reaching it proves the event
	// fell through step 1.6 into the pattern store.
	if err := patterns.Learn(scopeTestKey, patternstore.VerdictAlert, patternstore.LearnedPattern{
		Type:      patternstore.PatternHash,
		Value:     hashOf(t, scopeTestSource, failedProbeLine),
		Source:    "human",
		Reason:    "operator flagged this probe shape",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Learn: %v", err)
	}

	var calls atomic.Int64
	a.SetRECDisclosureCheck(func(evt *event.Event) (bool, string) {
		calls.Add(1)
		return true, "Captured response body discloses sensitive data despite rejection status: /etc/passwd contents (3 sensitive values redacted)"
	})

	result := a.Analyze(context.Background(), testEvent(scopeTestSource, failedProbeLine))

	if calls.Load() != 1 {
		t.Fatalf("recDisclosureCheck called %d times, want 1", calls.Load())
	}
	if result.Source == "noise_filter" || result.Verdict == patternstore.VerdictSuppress {
		t.Fatalf("event was suppressed despite REC disclosure: %+v", result)
	}
	if result.Verdict != patternstore.VerdictAlert || result.Source != "human" {
		t.Fatalf("verdict=%q source=%q, want alert via the pattern store", result.Verdict, result.Source)
	}

	ss := findScope(t, a, scopeTestKey)
	if ss.DeterministicResolvedTotal != 0 {
		t.Errorf("deterministic_resolved_total = %d, want 0 (suppression was overridden)", ss.DeterministicResolvedTotal)
	}
	if ss.InitialPatternHits != 1 {
		t.Errorf("initial_pattern_hits = %d, want 1 (event must reach the pattern store)", ss.InitialPatternHits)
	}
	if got := a.stats.NoiseSuppressed.Load(); got != 0 {
		t.Errorf("NoiseSuppressed = %d, want 0", got)
	}
}

// TestStep16_SuppressesWhenNoRECDisclosure: with the check returning false, and
// with no check wired at all, step 1.6 suppresses exactly as it did before the
// guard existed - same verdict, same source, same reason string.
func TestStep16_SuppressesWhenNoRECDisclosure(t *testing.T) {
	tests := []struct {
		name      string
		wire      bool
		wantCalls int64
	}{
		{name: "check returns false", wire: true, wantCalls: 1},
		{name: "no check wired", wire: false, wantCalls: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _ := newScopeTestAnalyzer(t, "http://unused.invalid", newCountingScheduler(1))

			var calls atomic.Int64
			if tt.wire {
				a.SetRECDisclosureCheck(func(evt *event.Event) (bool, string) {
					calls.Add(1)
					return false, ""
				})
			}

			result := a.Analyze(context.Background(), testEvent(scopeTestSource, failedProbeLine))

			if calls.Load() != tt.wantCalls {
				t.Errorf("recDisclosureCheck called %d times, want %d", calls.Load(), tt.wantCalls)
			}
			if result.Verdict != patternstore.VerdictSuppress {
				t.Errorf("verdict = %q, want suppress", result.Verdict)
			}
			if result.Source != "noise_filter" {
				t.Errorf("source = %q, want noise_filter", result.Source)
			}
			if result.Reason != failedProbeReason {
				t.Errorf("reason = %q, want %q", result.Reason, failedProbeReason)
			}

			ss := findScope(t, a, scopeTestKey)
			if ss.DeterministicResolvedTotal != 1 {
				t.Errorf("deterministic_resolved_total = %d, want 1", ss.DeterministicResolvedTotal)
			}
			if got := a.stats.NoiseSuppressed.Load(); got != 1 {
				t.Errorf("NoiseSuppressed = %d, want 1", got)
			}
		})
	}
}
