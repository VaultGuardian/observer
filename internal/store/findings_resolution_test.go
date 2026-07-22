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

	// A trusted downgrade arrives afterwards - it must override.
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

// TestTimeoutStampsPending_NoRegression: the unchanged common path - timeout
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

// TestQueryRecentUnresolvedFilter: unresolvedOnly restricts results to
// findings still eligible for resolution; off by default.
func TestQueryRecentUnresolvedFilter(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	insertPending(t, s, "evt_uf_pending")
	insertPending(t, s, "evt_uf_resolved")
	if err := s.UpdateFindingResolution(ctx, "evt_uf_resolved", "resolved", "rec_evidence", ""); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	all, err := s.QueryRecent(ctx, 50, false)
	if err != nil {
		t.Fatalf("query recent (all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("unfiltered query returned %d findings; want 2", len(all))
	}

	unresolved, err := s.QueryRecent(ctx, 50, true)
	if err != nil {
		t.Fatalf("query recent (unresolved): %v", err)
	}
	if len(unresolved) != 1 || unresolved[0].EventID != "evt_uf_pending" {
		t.Fatalf("unresolved query = %+v; want only evt_uf_pending", unresolved)
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

// =============================================================================
// P1 follow-up: the timeout path must skip findings whose evidence state
// machine reports evidence is available. Only genuinely evidence-less rows
// (explicit not_available_* or legacy empty/NULL) stay eligible.
// =============================================================================

// insertPendingWithEvidence writes a fresh pending malicious finding carrying
// the given evidence_status, timestamped in the past.
func insertPendingWithEvidence(t *testing.T, s *Store, eventID, evidenceStatus string) {
	t.Helper()
	err := s.RecordFinding(context.Background(), &Finding{
		EventID:        eventID,
		Timestamp:      time.Now().Add(-time.Hour),
		SourceType:     "nginx",
		SourceName:     "docker:test",
		Verdict:        "alert",
		HTTPMethod:     "GET",
		HTTPPath:       "/api/.env",
		HTTPStatus:     200,
		EvidenceStatus: evidenceStatus,
	})
	if err != nil {
		t.Fatalf("record finding %s: %v", eventID, err)
	}
}

// TestQueryUnresolvedMaliciousSkipsAvailableEvidence: findings whose evidence
// is available (high or low confidence) are never returned by the timeout
// query; evidence-less findings (empty or explicit not_available_*) are.
func TestQueryUnresolvedMaliciousSkipsAvailableEvidence(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	insertPendingWithEvidence(t, s, "evt_high", "available_high_confidence")
	insertPendingWithEvidence(t, s, "evt_low", "available_low_confidence")
	insertPendingWithEvidence(t, s, "evt_nomatch", "not_available_no_match")
	insertPending(t, s, "evt_empty") // empty evidence_status

	got, err := s.QueryUnresolvedMalicious(ctx, time.Minute, 50)
	if err != nil {
		t.Fatalf("query unresolved: %v", err)
	}

	if containsEvent(got, "evt_high") {
		t.Fatalf("evt_high (available_high_confidence) must be excluded from timeout query")
	}
	if containsEvent(got, "evt_low") {
		t.Fatalf("evt_low (available_low_confidence) must be excluded from timeout query")
	}
	if !containsEvent(got, "evt_nomatch") {
		t.Fatalf("evt_nomatch (not_available_no_match) is evidence-less and must remain eligible")
	}
	if !containsEvent(got, "evt_empty") {
		t.Fatalf("evt_empty (no evidence_status) is evidence-less and must remain eligible")
	}
}

// resolutionCols reads the four resolution columns directly (GetFindingByEventID
// only surfaces resolution_status).
func resolutionCols(t *testing.T, s *Store, eventID string) (status, method, prevVerdict, resolvedAt string) {
	t.Helper()
	err := s.DB().QueryRow(`SELECT
		COALESCE(resolution_status,''), COALESCE(resolution_method,''),
		COALESCE(previous_verdict,''), COALESCE(resolved_at,'')
		FROM findings WHERE event_id = ? ORDER BY id DESC LIMIT 1`, eventID).
		Scan(&status, &method, &prevVerdict, &resolvedAt)
	if err != nil {
		t.Fatalf("read resolution cols for %s: %v", eventID, err)
	}
	return
}

// insertFinalized writes a finding already stamped by a resolution writer, used
// to seed the historical state the repair migration operates on.
func insertFinalized(t *testing.T, s *Store, eventID, resolutionStatus, method, evidenceStatus string) {
	t.Helper()
	resolvedAt := time.Now().Add(-30 * time.Minute)
	err := s.RecordFinding(context.Background(), &Finding{
		EventID:          eventID,
		Timestamp:        time.Now().Add(-time.Hour),
		SourceType:       "nginx",
		SourceName:       "docker:test",
		Verdict:          "alert",
		HTTPMethod:       "GET",
		HTTPPath:         "/api/.env",
		HTTPStatus:       200,
		EvidenceStatus:   evidenceStatus,
		ResolutionStatus: resolutionStatus,
		ResolutionMethod: method,
		ResolvedAt:       &resolvedAt,
		PreviousVerdict:  "alert",
	})
	if err != nil {
		t.Fatalf("record finalized finding %s: %v", eventID, err)
	}
}

// TestMigration14RepairsMislabeledFindings: the repair migration resets only
// timeout-stamped evidence_unavailable rows whose evidence is available; it
// leaves evidence-less timeout rows and human decisions untouched.
func TestMigration14RepairsMislabeledFindings(t *testing.T) {
	s := newTestStore(t)

	// (a) mislabeled: timeout + high-confidence evidence -> should be repaired.
	insertFinalized(t, s, "evt_repair_high", "evidence_unavailable", "timeout", "available_high_confidence")
	// (a2) mislabeled: timeout + low-confidence evidence -> should be repaired.
	insertFinalized(t, s, "evt_repair_low", "evidence_unavailable", "timeout", "available_low_confidence")
	// (b) genuine: timeout + no available evidence -> untouched.
	insertFinalized(t, s, "evt_keep_nomatch", "evidence_unavailable", "timeout", "not_available_no_match")
	// (c) human decision -> untouched.
	insertFinalized(t, s, "evt_keep_human", "resolved", "human_override", "available_high_confidence")

	// Re-run the migration by removing its schema_version row and calling
	// migrate() again; this exercises the real migration SQL.
	if _, err := s.DB().Exec(`DELETE FROM schema_version WHERE version = 14`); err != nil {
		t.Fatalf("reset schema_version: %v", err)
	}
	if err := s.migrate(); err != nil {
		t.Fatalf("re-run migrate: %v", err)
	}

	// (a) and (a2) reset to pending with cleared resolution metadata.
	for _, id := range []string{"evt_repair_high", "evt_repair_low"} {
		status, method, prev, resolvedAt := resolutionCols(t, s, id)
		if status != "pending" {
			t.Fatalf("%s resolution_status = %q; want pending", id, status)
		}
		if method != "" || prev != "" || resolvedAt != "" {
			t.Fatalf("%s metadata not cleared: method=%q prev=%q resolvedAt=%q", id, method, prev, resolvedAt)
		}
	}

	// (b) evidence-less timeout row untouched.
	if status, _, _, _ := resolutionCols(t, s, "evt_keep_nomatch"); status != "evidence_unavailable" {
		t.Fatalf("evt_keep_nomatch resolution_status = %q; want evidence_unavailable (untouched)", status)
	}

	// (c) human decision untouched.
	status, method, _, _ := resolutionCols(t, s, "evt_keep_human")
	if status != "resolved" || method != "human_override" {
		t.Fatalf("evt_keep_human = (%q,%q); want (resolved,human_override) untouched", status, method)
	}
}
