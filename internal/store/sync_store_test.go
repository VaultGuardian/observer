package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// countDirty returns the number of journal rows of one kind.
func countDirty(t *testing.T, s *Store, kind string) int {
	t.Helper()
	var n int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM sync_dirty WHERE kind = ?", kind).Scan(&n); err != nil {
		t.Fatalf("count sync_dirty %s: %v", kind, err)
	}
	return n
}

func seedDecision(t *testing.T, s *Store, eventID string) {
	t.Helper()
	err := s.RecordLLMDecision(context.Background(), &LLMDecision{
		EventID:        eventID,
		Timestamp:      time.Now(),
		Tier:           "classify",
		Model:          "qwen2.5:7b",
		Classification: "malicious",
		Action:         "alert",
	})
	if err != nil {
		t.Fatalf("record decision: %v", err)
	}
}

// =============================================================================
// Test 12: journal gating
// =============================================================================

// With the journal off (the default, and the only state an unpaired Observer
// is ever in), the three mutation methods must write nothing to sync_dirty.
func TestMutationsDoNotJournalWhenDisabled(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	insertPending(t, s, "evt-1")
	seedDecision(t, s, "evt-1")

	if err := s.UpdateFindingResolution(ctx, "evt-1", "resolved", "rec_evidence", "recon"); err != nil {
		t.Fatalf("UpdateFindingResolution: %v", err)
	}
	if err := s.UpdateFindingVerdict(ctx, "evt-1", "suppress", "operator"); err != nil {
		t.Fatalf("UpdateFindingVerdict: %v", err)
	}
	if err := s.UpdateLLMDecisionReview(ctx, 1, LLMReview{Status: "confirmed", ReviewedBy: "operator"}); err != nil {
		t.Fatalf("UpdateLLMDecisionReview: %v", err)
	}

	if n := countDirty(t, s, SyncKindFinding); n != 0 {
		t.Errorf("finding journal rows with journaling off = %d; want 0", n)
	}
	if n := countDirty(t, s, SyncKindDecision); n != 0 {
		t.Errorf("decision journal rows with journaling off = %d; want 0", n)
	}
}

// Enabling the journal must not change any caller-visible error, and a
// mutation that matches zero rows must never leave a journal row behind - the
// dirty lane would then re-send a row that never changed.
func TestMutationErrorSemanticsUnchanged(t *testing.T) {
	ctx := context.Background()

	for _, journaling := range []bool{false, true} {
		name := "journal_off"
		if journaling {
			name = "journal_on"
		}
		t.Run(name, func(t *testing.T) {
			s := newTestStore(t)
			if journaling {
				s.EnableSyncJournal()
			}

			// Missing finding: the audit-trail lookup fails first.
			err := s.UpdateFindingResolution(ctx, "ghost", "resolved", "rec_evidence", "recon")
			if err == nil || !strings.Contains(err.Error(), "lookup current verdict for ghost") {
				t.Errorf("UpdateFindingResolution on a missing event = %v; want a lookup error", err)
			}
			err = s.UpdateFindingVerdict(ctx, "ghost", "suppress", "operator")
			if err == nil || !strings.Contains(err.Error(), "lookup current verdict for ghost") {
				t.Errorf("UpdateFindingVerdict on a missing event = %v; want a lookup error", err)
			}

			// Missing decision.
			err = s.UpdateLLMDecisionReview(ctx, 4242, LLMReview{Status: "confirmed"})
			if err == nil || err.Error() != "llm_decision 4242 not found" {
				t.Errorf("UpdateLLMDecisionReview on a missing id = %v; want \"llm_decision 4242 not found\"", err)
			}

			// Ineligible row: present, but the timeout path may not clobber a
			// terminal resolution.
			insertPending(t, s, "evt-x")
			if err := s.UpdateFindingResolution(ctx, "evt-x", "evidence_unavailable", "timeout", ""); err != nil {
				t.Fatalf("first resolution: %v", err)
			}
			err = s.UpdateFindingResolution(ctx, "evt-x", "evidence_unavailable", "timeout", "")
			if err == nil || err.Error() != "finding evt-x not found or already resolved" {
				t.Errorf("second resolution = %v; want \"finding evt-x not found or already resolved\"", err)
			}

			if !journaling {
				if n := countDirty(t, s, SyncKindFinding); n != 0 {
					t.Errorf("journal rows with journaling off = %d; want 0", n)
				}
				return
			}
			// Exactly one journal row: the successful first resolution. The
			// zero-row second attempt must not have added one.
			if n := countDirty(t, s, SyncKindFinding); n != 1 {
				t.Errorf("finding journal rows = %d; want 1 (only the successful mutation)", n)
			}
			if n := countDirty(t, s, SyncKindDecision); n != 0 {
				t.Errorf("decision journal rows = %d; want 0", n)
			}
		})
	}
}

// With journaling on, each successful mutation records its own key.
func TestMutationsJournalWhenEnabled(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.EnableSyncJournal()

	insertPending(t, s, "evt-1")
	seedDecision(t, s, "evt-1")

	if err := s.UpdateFindingResolution(ctx, "evt-1", "resolved", "rec_evidence", "recon"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateFindingVerdict(ctx, "evt-1", "suppress", "operator"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateLLMDecisionReview(ctx, 1, LLMReview{Status: "corrected", ReviewedBy: "operator"}); err != nil {
		t.Fatal(err)
	}

	entries, err := s.TakeSyncDirty(ctx, SyncKindFinding, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("finding journal rows = %d; want 2", len(entries))
	}
	for _, e := range entries {
		if e.Ref != "evt-1" {
			t.Errorf("finding journal ref = %q; want the event id", e.Ref)
		}
	}

	decisions, err := s.TakeSyncDirty(ctx, SyncKindDecision, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 || decisions[0].Ref != "1" {
		t.Fatalf("decision journal = %+v; want one row with ref \"1\"", decisions)
	}
}

// [A8] The delete is kind-scoped: both kinds share one autoincrement id space.
func TestDeleteSyncDirtyThroughIsKindScoped(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.EnableSyncJournal()

	insertPending(t, s, "evt-1")
	seedDecision(t, s, "evt-1")
	if err := s.UpdateFindingVerdict(ctx, "evt-1", "suppress", "a"); err != nil { // id 1
		t.Fatal(err)
	}
	if err := s.UpdateLLMDecisionReview(ctx, 1, LLMReview{Status: "confirmed"}); err != nil { // id 2
		t.Fatal(err)
	}
	if err := s.UpdateFindingVerdict(ctx, "evt-1", "allow", "b"); err != nil { // id 3
		t.Fatal(err)
	}

	if err := s.DeleteSyncDirtyThrough(ctx, SyncKindFinding, 3); err != nil {
		t.Fatal(err)
	}
	if n := countDirty(t, s, SyncKindFinding); n != 0 {
		t.Errorf("finding journal rows = %d; want 0", n)
	}
	if n := countDirty(t, s, SyncKindDecision); n != 1 {
		t.Errorf("decision journal rows = %d; want 1 (a findings delete must not touch them)", n)
	}

	// A non-positive boundary is a no-op, never a table wipe.
	if err := s.DeleteSyncDirtyThrough(ctx, SyncKindDecision, 0); err != nil {
		t.Fatal(err)
	}
	if n := countDirty(t, s, SyncKindDecision); n != 1 {
		t.Errorf("decision journal rows after a zero boundary = %d; want 1", n)
	}
}

// Cursors and metadata round-trip, and absent keys read as zero values.
func TestSyncCursorsAndMeta(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if got, err := s.GetSyncCursor(ctx, SyncStreamFindings); err != nil || got != 0 {
		t.Fatalf("unset cursor = (%d, %v); want (0, nil)", got, err)
	}
	if err := s.SetSyncCursor(ctx, SyncStreamFindings, 1234); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSyncCursor(ctx, SyncStreamDecisions, 99); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetSyncCursor(ctx, SyncStreamFindings); got != 1234 {
		t.Errorf("findings cursor = %d; want 1234", got)
	}
	if got, _ := s.GetSyncCursor(ctx, SyncStreamDecisions); got != 99 {
		t.Errorf("decisions cursor = %d; want 99 (streams must not share a key)", got)
	}

	if got, err := s.GetSyncMeta(ctx, SyncMetaTarget); err != nil || got != "" {
		t.Fatalf("unset meta = (%q, %v); want (\"\", nil)", got, err)
	}
	if err := s.SetSyncMeta(ctx, SyncMetaTarget, "abc"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSyncMeta(ctx, SyncMetaTarget, "def"); err != nil {
		t.Fatal(err) // must overwrite, not conflict
	}
	if got, _ := s.GetSyncMeta(ctx, SyncMetaTarget); got != "def" {
		t.Errorf("meta after overwrite = %q; want def", got)
	}
}

// High-water marks back the rollback check; an empty table reads as 0.
func TestMaxRowIDs(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if got, err := s.MaxFindingRowID(ctx); err != nil || got != 0 {
		t.Fatalf("empty findings max = (%d, %v); want (0, nil)", got, err)
	}
	if got, err := s.MaxLLMDecisionRowID(ctx); err != nil || got != 0 {
		t.Fatalf("empty decisions max = (%d, %v); want (0, nil)", got, err)
	}

	insertPending(t, s, "evt-1")
	insertPending(t, s, "evt-2")
	seedDecision(t, s, "evt-1")

	if got, _ := s.MaxFindingRowID(ctx); got != 2 {
		t.Errorf("findings max = %d; want 2", got)
	}
	if got, _ := s.MaxLLMDecisionRowID(ctx); got != 1 {
		t.Errorf("decisions max = %d; want 1", got)
	}
}

// =============================================================================
// Test 15 [A4]: full-row transport round-trip - the drift tripwire
// =============================================================================
//
// Every field is populated, written through the normal write path, read back
// through the transport scanners, and compared as JSON - which IS the wire
// format. A column added to Finding or LLMDecision without being added to
// findingTransportColumns / decisionTransportColumns comes back as a zero
// value and fails here, before it can silently null out a hosted column via
// the overwrite-upsert.

func TestSyncTransportRoundTripFinding(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	resolvedAt := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	want := Finding{
		EventID:              "evt-full",
		Timestamp:            time.Now().UTC().Truncate(time.Second),
		SourceType:           "docker",
		SourceName:           "docker:captain-nginx",
		SourceIP:             "203.0.113.9",
		DestHost:             "app.example.com",
		HTTPMethod:           "POST",
		HTTPPath:             "/admin/login",
		HTTPStatus:           401,
		ResponseBytes:        4096,
		UserAgent:            "curl/8.5.0",
		Verdict:              "malicious",
		Classification:       "malicious",
		Confidence:           0.875,
		Reason:               "credential stuffing against admin login",
		MatchedVia:           "llm",
		MatchedPatternScope:  "docker:captain-nginx",
		MatchedPatternBucket: "malicious",
		MatchedPatternValue:  "POST /admin/login",
		OriginEventID:        "evt-origin",
		RawLine:              `203.0.113.9 - - "POST /admin/login" 401 4096`,
		NormalizedLine:       `POST /admin/login 401`,
		NormalizedHash:       "a1b2c3d4",
		EvidenceStatus:       "available_high_confidence",
		EvidenceStatusCode:   401,
		EvidenceContentType:  "application/json",
		EvidenceBodyHash:     "deadbeef",
		EvidenceCaptureMode:  "namespace",
		CoordinatorKey:       "203.0.113.9|app.example.com",
		CoordinatorEvents:    7,
		Downgraded:           true,
		DowngradeReason:      "rec evidence showed a 401",
		Notified:             true,
		ResolutionStatus:     "resolved",
		ResolvedAt:           &resolvedAt,
		ResolutionMethod:     "rec_evidence",
		PreviousVerdict:      "alert",
	}
	if err := s.RecordFinding(ctx, &want); err != nil {
		t.Fatalf("record: %v", err)
	}

	rows, err := s.ListFindingsAfterIDFull(ctx, 0, 10)
	if err != nil {
		t.Fatalf("ListFindingsAfterIDFull: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	if rows[0].Rowid != 1 {
		t.Errorf("rowid = %d; want 1", rows[0].Rowid)
	}
	assertWireEqual(t, "finding", want, rows[0].F)

	// The dirty lane's reader must return the same complete row.
	rowid, latest, err := s.LatestFindingForEventIDFull(ctx, "evt-full")
	if err != nil {
		t.Fatalf("LatestFindingForEventIDFull: %v", err)
	}
	if rowid != 1 || latest == nil {
		t.Fatalf("latest = (%d, %v); want (1, non-nil)", rowid, latest)
	}
	assertWireEqual(t, "finding (dirty reader)", want, *latest)

	// A pruned event is reported as absent, not as an error.
	missingRowid, missing, err := s.LatestFindingForEventIDFull(ctx, "never-existed")
	if err != nil || missing != nil || missingRowid != 0 {
		t.Errorf("missing event = (%d, %v, %v); want (0, nil, nil)", missingRowid, missing, err)
	}
}

func TestSyncTransportRoundTripDecision(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	want := LLMDecision{
		EventID:          "evt-full",
		Timestamp:        time.Now().UTC().Truncate(time.Second),
		Tier:             "reclassify",
		Model:            "qwen2.5:7b",
		ReasoningEffort:  "medium",
		PromptTokens:     1024,
		CompletionTokens: 128,
		LatencyMs:        2400,
		SourceScope:      "docker:captain-nginx",
		RawLine:          `203.0.113.9 - - "POST /admin/login" 401`,
		NormalizedLine:   `POST /admin/login 401`,
		NormalizedHash:   "a1b2c3d4",
		EvidencePreview:  `{"error":"invalid credentials"}`,
		EvidenceStatus:   401,
		EvidenceType:     "application/json",
		EvidenceHash:     "deadbeef",
		LLMResponseRaw:   `{"classification":"malicious","action":"alert"}`,
		Classification:   "malicious",
		Action:           "alert",
		Confidence:       0.93,
		Reason:           "credential stuffing",
		PatternType:      "regex",
		PatternValue:     `POST /admin/login`,
		SourceHint:       "nginx access log",
		PatternLearned:   true,
		PatternBucket:    "malicious",
		CacheKey:         "cafebabe",
		FinalVerdict:     "malicious",
		Escalated:        true,
		Downgraded:       true,
		FindingID:        "evt-full",
		Notified:         true,
		PromptVersion:    "p7",
		CodeVersion:      "v1.0.3",
	}
	if err := s.RecordLLMDecision(ctx, &want); err != nil {
		t.Fatalf("record: %v", err)
	}

	// The review columns are only reachable through the review path.
	review := LLMReview{
		Status:             "corrected",
		ReviewedBy:         "operator",
		Verdict:            "recon",
		Reason:             "the 401 proves the attempt failed",
		PatternDeleted:     true,
		ReplacementPattern: "POST /admin/login 401",
	}
	if err := s.UpdateLLMDecisionReview(ctx, 1, review); err != nil {
		t.Fatalf("review: %v", err)
	}
	want.ReviewStatus = review.Status
	want.ReviewedBy = review.ReviewedBy
	want.ReviewerVerdict = review.Verdict
	want.ReviewerReason = review.Reason
	want.PatternDeleted = review.PatternDeleted
	want.ReplacementPattern = review.ReplacementPattern
	want.ID = 1

	rows, err := s.ListDecisionsAfterIDFull(ctx, 0, 10)
	if err != nil {
		t.Fatalf("ListDecisionsAfterIDFull: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d; want 1", len(rows))
	}
	// reviewed_at is stamped by the store, so it is asserted rather than
	// predicted; everything else must match exactly.
	if rows[0].ReviewedAt == "" {
		t.Error("reviewed_at is empty after a review")
	}
	want.ReviewedAt = rows[0].ReviewedAt
	assertWireEqual(t, "decision", want, rows[0])

	single, err := s.GetDecisionByIDFull(ctx, 1)
	if err != nil {
		t.Fatalf("GetDecisionByIDFull: %v", err)
	}
	if single == nil {
		t.Fatal("GetDecisionByIDFull returned nil for an existing id")
	}
	assertWireEqual(t, "decision (dirty reader)", want, *single)

	pruned, err := s.GetDecisionByIDFull(ctx, 9999)
	if err != nil || pruned != nil {
		t.Errorf("missing decision = (%v, %v); want (nil, nil)", pruned, err)
	}
}

// assertWireEqual compares two rows as the JSON they become on the wire,
// field by field, so a drift report names the column that broke.
func assertWireEqual(t *testing.T, label string, want, got any) {
	t.Helper()
	wantMap := wireMap(t, want)
	gotMap := wireMap(t, got)

	for key, wantValue := range wantMap {
		gotValue, ok := gotMap[key]
		if !ok {
			t.Errorf("%s: wire field %q is missing from the transport scanner's output "+
				"(add the column to the transport column list)", label, key)
			continue
		}
		if string(wantValue) != string(gotValue) {
			t.Errorf("%s: wire field %q = %s; want %s", label, key, gotValue, wantValue)
		}
	}
	for key := range gotMap {
		if _, ok := wantMap[key]; !ok {
			t.Errorf("%s: transport scanner produced unexpected wire field %q "+
				"(the round-trip fixture needs updating)", label, key)
		}
	}
}

func wireMap(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}
