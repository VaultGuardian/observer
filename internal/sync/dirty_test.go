package sync

import (
	"context"
	"testing"

	"github.com/vaultguardian/observer/internal/store"
)

// Test 8 [A2/A9]: a correction on an event with several local rows sends ONLY
// the newest row, and the journal is retired only on a validated success.
func TestDirtySendsNewestRowOnly(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()
	st.EnableSyncJournal()

	// Two rows for one event, both mirrored by the cursor lane.
	for _, reason := range []string{"first", "second"} {
		f := testFinding("evt")
		f.Reason = reason
		if err := st.RecordFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	e := newTestEngine(t, st, ingest)
	drainLaneA(t, e)
	if got := cursor(t, st, store.SyncStreamFindings); got != 2 {
		t.Fatalf("cursor = %d; want 2", got)
	}
	ingest.reset()

	// An operator correction mutates in place - invisible to the cursor lane.
	if err := st.UpdateFindingVerdict(ctx, "evt", "suppress", "operator says benign"); err != nil {
		t.Fatalf("correction: %v", err)
	}
	if n := dirtyCount(t, st, store.SyncKindFinding); n == 0 {
		t.Fatal("correction wrote no journal row")
	}

	drainLaneA(t, e)

	posts := ingest.postsTo(pathFindings)
	if len(posts) != 1 {
		t.Fatalf("POSTs = %d; want 1", len(posts))
	}
	if len(posts[0].Items) != 1 {
		t.Fatalf("items = %d; want exactly 1 (the newest row, never history)", len(posts[0].Items))
	}
	if got := itemField(t, posts[0].Items[0], "verdict"); got != "suppress" {
		t.Errorf("wire verdict = %q; want suppress", got)
	}
	if got := itemField(t, posts[0].Items[0], "resolution_status"); got != "resolved" {
		t.Errorf("wire resolution_status = %q; want resolved", got)
	}
	if n := dirtyCount(t, st, store.SyncKindFinding); n != 0 {
		t.Errorf("journal rows remaining after success = %d; want 0", n)
	}
}

// The journal is the only record that a mutation still needs mirroring, so a
// failed POST must leave it completely intact.
func TestDirtyJournalSurvivesFailure(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()
	st.EnableSyncJournal()

	if err := st.RecordFinding(ctx, testFinding("evt")); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, st, ingest)
	drainLaneA(t, e)

	if err := st.UpdateFindingVerdict(ctx, "evt", "suppress", "operator says benign"); err != nil {
		t.Fatal(err)
	}
	before := dirtyCount(t, st, store.SyncKindFinding)

	ingest.setResponder(func(string, int) (int, string) { return 503, `{"error":"down"}` })
	if _, _, err := e.laneACycle(ctx); err == nil {
		t.Fatal("cycle succeeded despite a 503")
	}
	if after := dirtyCount(t, st, store.SyncKindFinding); after != before {
		t.Errorf("journal rows after failure = %d; want %d (unchanged)", after, before)
	}

	// And it drains once the mirror recovers.
	ingest.setResponder(nil)
	drainLaneA(t, e)
	if after := dirtyCount(t, st, store.SyncKindFinding); after != 0 {
		t.Errorf("journal rows after recovery = %d; want 0", after)
	}
}

// Test 9 [A2]: when the newest row is still AHEAD of the cursor, the dirty
// pass defers to the cursor lane and leaves its journal rows in place.
func TestDirtyDefersRowsAheadOfCursor(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()
	st.EnableSyncJournal()

	if err := st.RecordFinding(ctx, testFinding("evt")); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, st, ingest)

	// Mutate before the cursor lane has ever run: rowid 1 > cursor 0.
	if err := st.UpdateFindingVerdict(ctx, "evt", "suppress", "operator says benign"); err != nil {
		t.Fatal(err)
	}

	// Dirty pass in isolation: nothing sent, nothing retired.
	if _, progressed, err := e.syncFindingsDirty(ctx); err != nil {
		t.Fatalf("dirty pass: %v", err)
	} else if progressed {
		t.Error("dirty pass reported progress while everything was deferred")
	}
	if n := len(ingest.postsTo(pathFindings)); n != 0 {
		t.Errorf("deferred ref produced %d POSTs; want 0", n)
	}
	if n := dirtyCount(t, st, store.SyncKindFinding); n != 1 {
		t.Fatalf("journal rows after defer = %d; want 1 (left for later)", n)
	}

	// The cursor lane catches up...
	if _, _, err := e.syncFindingsCursor(ctx); err != nil {
		t.Fatalf("cursor pass: %v", err)
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 1 {
		t.Fatalf("cursor = %d; want 1", got)
	}

	// ...and now the dirty pass owns the ref and retires it.
	if _, _, err := e.syncFindingsDirty(ctx); err != nil {
		t.Fatalf("second dirty pass: %v", err)
	}
	if n := dirtyCount(t, st, store.SyncKindFinding); n != 0 {
		t.Errorf("journal rows after catch-up = %d; want 0", n)
	}
}

// Test 10 [A8]: findings and decisions share one autoincrement id space, so a
// findings drain must delete ONLY kind='finding' rows in its range.
func TestDirtyDeleteIsKindScoped(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()
	st.EnableSyncJournal()

	if err := st.RecordFinding(ctx, testFinding("evt")); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordLLMDecision(ctx, testDecision("evt")); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, st, ingest)
	drainLaneA(t, e)

	// Interleave journal rows: finding(1), decision(2), finding(3), decision(4).
	review := store.LLMReview{Status: "confirmed", ReviewedBy: "operator"}
	for i := 0; i < 2; i++ {
		if err := st.UpdateFindingVerdict(ctx, "evt", "suppress", "correction"); err != nil {
			t.Fatal(err)
		}
		if err := st.UpdateLLMDecisionReview(ctx, 1, review); err != nil {
			t.Fatal(err)
		}
	}
	if got := dirtyCount(t, st, store.SyncKindFinding); got != 2 {
		t.Fatalf("finding journal rows = %d; want 2", got)
	}
	if got := dirtyCount(t, st, store.SyncKindDecision); got != 2 {
		t.Fatalf("decision journal rows = %d; want 2", got)
	}

	if _, _, err := e.syncFindingsDirty(ctx); err != nil {
		t.Fatalf("findings dirty: %v", err)
	}
	if got := dirtyCount(t, st, store.SyncKindFinding); got != 0 {
		t.Errorf("finding journal rows after drain = %d; want 0", got)
	}
	if got := dirtyCount(t, st, store.SyncKindDecision); got != 2 {
		t.Errorf("decision journal rows after a FINDINGS drain = %d; want 2 (untouched)", got)
	}

	// The decisions pass then retires its own.
	if _, _, err := e.syncDecisionsDirty(ctx); err != nil {
		t.Fatalf("decisions dirty: %v", err)
	}
	if got := dirtyCount(t, st, store.SyncKindDecision); got != 0 {
		t.Errorf("decision journal rows after their own drain = %d; want 0", got)
	}
}

// A ref whose row was pruned locally is satisfied, not stuck: the journal row
// retires with nothing sent.
func TestDirtyPrunedRowIsSatisfied(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()
	st.EnableSyncJournal()

	if err := st.RecordFinding(ctx, testFinding("evt")); err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, st, ingest)
	drainLaneA(t, e)
	if err := st.UpdateFindingVerdict(ctx, "evt", "suppress", "correction"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, "DELETE FROM findings WHERE event_id = ?", "evt"); err != nil {
		t.Fatal(err)
	}
	ingest.reset()

	if _, _, err := e.syncFindingsDirty(ctx); err != nil {
		t.Fatalf("dirty pass: %v", err)
	}
	if n := len(ingest.postsTo(pathFindings)); n != 0 {
		t.Errorf("pruned ref produced %d POSTs; want 0", n)
	}
	if n := dirtyCount(t, st, store.SyncKindFinding); n != 0 {
		t.Errorf("journal rows for a pruned ref = %d; want 0", n)
	}
}

// deleteBoundary is the [A8] safety property in miniature: a deferred entry
// caps the boundary below its own journal id, even for refs already sent.
func TestDeleteBoundary(t *testing.T) {
	entries := []store.SyncDirtyEntry{{ID: 5}, {ID: 9}, {ID: 12}}

	if got := deleteBoundary(entries, 0); got != 12 {
		t.Errorf("no deferrals: boundary = %d; want 12", got)
	}
	if got := deleteBoundary(entries, 9); got != 8 {
		t.Errorf("deferral at 9: boundary = %d; want 8", got)
	}
	if got := deleteBoundary(entries, 5); got != 4 {
		t.Errorf("deferral at the first entry: boundary = %d; want 4 (nothing deletable)", got)
	}
}
