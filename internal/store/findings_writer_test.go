package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func countFindings(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&n); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

func writerFinding(id string) *Finding {
	return &Finding{
		EventID:    id,
		Timestamp:  time.Now(),
		SourceType: "nginx",
		SourceName: "docker:test",
		Verdict:    "malicious",
		HTTPMethod: "GET",
		HTTPPath:   "/api/.env",
		HTTPStatus: 200,
	}
}

// TestFindingsWriterFlushesAfterContextCancel: on clean shutdown the app
// context is already canceled when the writer drains. The final flush must
// still persist every buffered finding (shielded drain context), instead of
// failing BeginTx and the RecordFinding fallback with "context canceled".
func TestFindingsWriterFlushesAfterContextCancel(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	w := NewFindingsWriter(s, 100)
	go w.Run(ctx)

	const n = 5
	for i := 0; i < n; i++ {
		w.Submit(writerFinding(fmt.Sprintf("evt_shutdown_%d", i)))
	}

	// Cancel first (the SIGINT/SIGTERM ordering), then stop.
	cancel()
	w.Stop()

	if got := countFindings(t, s); got != n {
		t.Fatalf("persisted %d findings after canceled-context shutdown; want %d", got, n)
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("evt_shutdown_%d", i)
		if _, err := s.GetFindingByEventID(context.Background(), id); err != nil {
			t.Fatalf("finding %s not persisted: %v", id, err)
		}
	}
}

// TestFindingsWriterSteadyStateFlush: with a live context, buffered findings
// are flushed by the periodic timer without any shutdown signal.
func TestFindingsWriterSteadyStateFlush(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w := NewFindingsWriter(s, 100)
	go w.Run(ctx)
	defer w.Stop()

	const n = 3
	for i := 0; i < n; i++ {
		w.Submit(writerFinding(fmt.Sprintf("evt_steady_%d", i)))
	}

	// The flush timer fires every 200ms; poll for the rows to land.
	deadline := time.Now().Add(3 * time.Second)
	for countFindings(t, s) < n {
		if time.Now().After(deadline) {
			t.Fatalf("persisted %d findings via steady-state flush; want %d", countFindings(t, s), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
