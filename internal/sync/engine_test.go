package sync

import (
	"context"
	"errors"
	"testing"

	"github.com/vaultguardian/observer/internal/store"
)

// Test 13 [A1]: a boot with sync disabled breaks journal continuity, so the
// next enable must full-resync rather than trusting stale cursors.
func TestContinuityBreakForcesFullResync(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()

	insertFindings(t, st, 5, "evt")
	insertDecisions(t, st, 3, "evt")
	drainLaneA(t, newTestEngine(t, st, ingest))

	if cursor(t, st, store.SyncStreamFindings) == 0 || cursor(t, st, store.SyncStreamDecisions) == 0 {
		t.Fatal("cursors did not advance during setup")
	}

	// A mutation the unpaired boot would leave unjournaled.
	st.EnableSyncJournal()
	if err := st.UpdateFindingVerdict(ctx, "evt-000", "suppress", "correction"); err != nil {
		t.Fatal(err)
	}
	if dirtyCount(t, st, store.SyncKindFinding) == 0 {
		t.Fatal("setup wrote no journal row")
	}

	// Boot with sync disabled.
	if err := NoteDisabled(ctx, st); err != nil {
		t.Fatalf("NoteDisabled: %v", err)
	}
	if got, _ := st.GetSyncMeta(ctx, store.SyncMetaContinuous); got != "0" {
		t.Fatalf("continuity flag = %q; want \"0\"", got)
	}

	// Boot with sync enabled again.
	newTestEngine(t, st, ingest)

	if got := cursor(t, st, store.SyncStreamFindings); got != 0 {
		t.Errorf("findings cursor after continuity break = %d; want 0", got)
	}
	if got := cursor(t, st, store.SyncStreamDecisions); got != 0 {
		t.Errorf("decisions cursor after continuity break = %d; want 0", got)
	}
	if got := dirtyCount(t, st, store.SyncKindFinding); got != 0 {
		t.Errorf("journal rows after full resync = %d; want 0 (everything is being re-sent)", got)
	}
	if got, _ := st.GetSyncMeta(ctx, store.SyncMetaContinuous); got != "1" {
		t.Errorf("continuity flag after re-enable = %q; want \"1\"", got)
	}
}

// [A1] Pointing an existing database at a different hosted mirror also forces
// a full resync - the new target holds none of our history.
func TestTargetChangeForcesFullResync(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)

	insertFindings(t, st, 4, "evt")
	drainLaneA(t, newTestEngine(t, st, ingest))
	if cursor(t, st, store.SyncStreamFindings) != 4 {
		t.Fatal("setup cursor did not advance")
	}

	// Same URL, different token => different fingerprint.
	if _, err := newTestEngineErr(t, st, ingest, "a-different-token"); err != nil {
		t.Fatalf("new engine with rotated token: %v", err)
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 0 {
		t.Errorf("cursor after target change = %d; want 0", got)
	}
}

// A never-paired database must be left completely untouched by NoteDisabled -
// the overwhelmingly common self-hosted case writes nothing at all.
func TestNoteDisabledLeavesNeverPairedDBAlone(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()

	if err := NoteDisabled(ctx, st); err != nil {
		t.Fatalf("NoteDisabled: %v", err)
	}
	var rows int
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM sync_state").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("sync_state rows on a never-paired DB = %d; want 0", rows)
	}
}

// Test 14 [A6]: a database that regressed relative to the sync state fails
// closed. Resetting the cursors would be destructive - new local rows reuse
// ids from the abandoned timeline and would overwrite unrelated hosted rows.
func TestRollbackFailsClosed(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()

	insertFindings(t, st, 3, "evt")
	drainLaneA(t, newTestEngine(t, st, ingest))

	// Simulate a restore from an older backup: sync_state survived, the rows
	// did not.
	if err := st.SetSyncCursor(ctx, store.SyncStreamFindings, 999); err != nil {
		t.Fatal(err)
	}

	engine, err := newTestEngineErr(t, st, ingest, testToken)
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("New error = %v; want ErrRolledBack", err)
	}
	if engine != nil {
		t.Error("New returned an engine alongside the rollback error")
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 999 {
		t.Errorf("cursor = %d; want 999 (untouched - never auto-reset)", got)
	}
}

// The same guard covers the decisions stream.
func TestRollbackFailsClosedOnDecisionsCursor(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()

	insertDecisions(t, st, 2, "evt")
	drainLaneA(t, newTestEngine(t, st, ingest))
	if err := st.SetSyncCursor(ctx, store.SyncStreamDecisions, 500); err != nil {
		t.Fatal(err)
	}

	if _, err := newTestEngineErr(t, st, ingest, testToken); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("New error = %v; want ErrRolledBack", err)
	}
}

// [A10] The lane B base URL must be a dialable address: a wildcard bind is
// "listening everywhere", not an address to connect to.
func TestLocalBaseURL(t *testing.T) {
	cases := []struct {
		bind string
		want string
	}{
		{"127.0.0.1", "http://127.0.0.1:9090"},
		{"", "http://127.0.0.1:9090"},
		{"0.0.0.0", "http://127.0.0.1:9090"},
		{"::", "http://127.0.0.1:9090"},
		{"10.1.2.3", "http://10.1.2.3:9090"},
		{"::1", "http://[::1]:9090"},
	}
	for _, tc := range cases {
		if got := LocalBaseURL(tc.bind, 9090); got != tc.want {
			t.Errorf("LocalBaseURL(%q) = %q; want %q", tc.bind, got, tc.want)
		}
	}
}

// Logs must never carry the token, including via URL userinfo.
func TestTargetHostStripsCredentials(t *testing.T) {
	cases := map[string]string{
		"https://vaultguardian.io":             "vaultguardian.io",
		"https://vaultguardian.io/base/path":   "vaultguardian.io",
		"https://user:secret@vaultguardian.io": "vaultguardian.io",
		"http://127.0.0.1:9999":                "127.0.0.1:9999",
	}
	for in, want := range cases {
		if got := targetHost(in); got != want {
			t.Errorf("targetHost(%q) = %q; want %q", in, got, want)
		}
	}
}

// The fingerprint must move when either half of the pairing moves.
func TestTargetFingerprint(t *testing.T) {
	base := targetFingerprint("https://a.example", "tok")
	if targetFingerprint("https://a.example", "tok") != base {
		t.Error("fingerprint is not stable for identical inputs")
	}
	if targetFingerprint("https://b.example", "tok") == base {
		t.Error("fingerprint ignored a URL change")
	}
	if targetFingerprint("https://a.example", "tok2") == base {
		t.Error("fingerprint ignored a token change")
	}
}
