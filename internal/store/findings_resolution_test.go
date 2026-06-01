package store

import (
	"context"
	"testing"
	"time"
)

// =============================================================================
// P1: resolution transitions are monotonic by trust. A trusted resolved/
// downgraded outcome may heal an evidence_unavailable row; the timeout
// reconciler may never clobber a resolved row.
// =============================================================================

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// insertPending writes a fresh malicious finding with empty resolution_status,
// timestamped in the past so QueryUnresolvedMalicious can see it.
func insertPending(t *testing.T, s *Store, eventID string) {
	t.Helper()
	err := s.RecordFinding(context.Background(), &Finding{
		EventID:    eventID,
		Timestamp:  time.Now().Add(-time.Hour),
		SourceType: "nginx",
		SourceName: "docker:test",
		Verdict:    "malicious",
		HTTPMethod: "GET",
		HTTPPath:   "/api/.env",
		HTTPStatus: 200,
	})
	if err != nil {
		t.Fatalf("record finding %s: %v", eventID, err)
	}
}

func resolutionOf(t *testing.T, s *Store, eventID string) *Finding {
	t.Helper()
	f, err := s.GetFindingByEventID(context.Background(), eventID)
	if err != nil {
		t.Fatalf("get finding %s: %v", eventID, err)
	}
	return f
}

// TestTrustedResolutionOverridesEvidenceUnavailable is the core P1 backstop:
// once the timeout reconciler has stamped evidence_unavailable, a later
// trusted resolved/downgraded verdict must still be able to heal the row.
func TestTrustedResolutionOverridesEvidenceUnavailable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const id = "evt_late_downgrade"
	insertPending(t, s, id)

	// Reconciler gives up → evidence_unavailable.
	if err := s.UpdateFindingResolution(ctx, id, "evidence_unavailable", "timeout", ""); err != nil {
		t.Fatalf("timeout finalize: %v", err)
	}
	if got := resolutionOf(t, s, id).ResolutionStatus; got != "evidence_unavailable" {
		t.Fatalf("after timeout, resolution_status = %q; want evidence_unavailable", got)
	}

	// A trusted downgrade arrives afterwards — it must override.
	if err := s.UpdateFindingResolution(ctx, id, "resolved", "rec_evidence", "downgraded"); err != nil {
		t.Fatalf("trusted override: %v", err)
	}
	f := resolutionOf(t, s, id)
	if f.ResolutionStatus != "resolved" {
		t.Fatalf("resolution_status = %q; want resolved", f.ResolutionStatus)
	}
	if f.Verdict != "downgraded" {
		t.Fatalf("verdict = %q; want downgraded", f.Verdict)
	}
	if !f.Downgraded {
		t.Fatalf("downgraded flag not set after trusted downgrade")
	}
}

// TestTimeoutCannotClobberResolved: the timeout reconciler must never move a
// resolved row back to evidence_unavailable.
func TestTimeoutCannotClobberResolved(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const id = "evt_already_resolved"
	insertPending(t, s, id)

	if err := s.UpdateFindingResolution(ctx, id, "resolved", "rec_evidence", "downgraded"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// Timeout attempt must be a no-op (no matching row) → returns the
	// "not found or already resolved" error and leaves the row resolved.
	err := s.UpdateFindingResolution(ctx, id, "evidence_unavailable", "timeout", "")
	if err == nil {
		t.Fatalf("expected timeout update to be rejected on a resolved row")
	}
	if got := resolutionOf(t, s, id).ResolutionStatus; got != "resolved" {
		t.Fatalf("resolution_status = %q; want resolved (timeout clobbered it)", got)
	}
}

// TestTimeoutStampsPending_NoRegression: the unchanged common path — timeout
// still moves a pending row to evidence_unavailable, and that row then leaves
// the QueryUnresolvedMalicious set.
func TestTimeoutStampsPending_NoRegression(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const id = "evt_pending_timeout"
	insertPending(t, s, id)

	// Visible to the reconciler before finalization.
	got, err := s.QueryUnresolvedMalicious(ctx, time.Minute, 50)
	if err != nil {
		t.Fatalf("query unresolved: %v", err)
	}
	if !containsEvent(got, id) {
		t.Fatalf("pending finding %s not returned by QueryUnresolvedMalicious", id)
	}

	if err := s.UpdateFindingResolution(ctx, id, "evidence_unavailable", "timeout", ""); err != nil {
		t.Fatalf("timeout finalize: %v", err)
	}
	if r := resolutionOf(t, s, id).ResolutionStatus; r != "evidence_unavailable" {
		t.Fatalf("resolution_status = %q; want evidence_unavailable", r)
	}

	// No longer eligible for the reconciler.
	got, err = s.QueryUnresolvedMalicious(ctx, time.Minute, 50)
	if err != nil {
		t.Fatalf("query unresolved (post): %v", err)
	}
	if containsEvent(got, id) {
		t.Fatalf("finding %s still returned after evidence_unavailable", id)
	}
}

// TestTrustedResolutionFromPending_NoRegression: trusted resolved still moves
// a plain pending row to resolved.
func TestTrustedResolutionFromPending_NoRegression(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	const id = "evt_pending_resolve"
	insertPending(t, s, id)

	if err := s.UpdateFindingResolution(ctx, id, "resolved", "rec_evidence", "downgraded"); err != nil {
		t.Fatalf("resolve from pending: %v", err)
	}
	if r := resolutionOf(t, s, id).ResolutionStatus; r != "resolved" {
		t.Fatalf("resolution_status = %q; want resolved", r)
	}
}

func containsEvent(fs []Finding, eventID string) bool {
	for _, f := range fs {
		if f.EventID == eventID {
			return true
		}
	}
	return false
}
