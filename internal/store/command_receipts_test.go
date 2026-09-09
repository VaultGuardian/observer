package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func receiptStore(t *testing.T) *Store {
	t.Helper()
	st, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func seenReceipt(id string, nowMS int64) *CommandReceipt {
	return &CommandReceipt{
		CommandID:   id,
		CommandType: "pattern_delete",
		PayloadSHA:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Epoch:       "epoch-7",
		Signature:   "c2lnbmF0dXJl",
		ExpiresAt:   nowMS + 60_000,
		FirstSeenAt: nowMS,
	}
}

// An unknown command has no receipt - that is how lane C tells "never seen"
// from "seen and decided".
func TestGetCommandReceiptMissing(t *testing.T) {
	st := receiptStore(t)
	r, err := st.GetCommandReceipt(context.Background(), "nope")
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if r != nil {
		t.Errorf("receipt = %+v; want nil for an unknown command", r)
	}
	if r.Terminal() {
		t.Error("a nil receipt must not report itself terminal")
	}
}

// RecordCommandSeen stores the signed tuple and is idempotent: a redelivery
// must not move first_seen_at or disturb a recorded outcome.
func TestRecordCommandSeenIsIdempotent(t *testing.T) {
	st := receiptStore(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()

	first := seenReceipt("cmd-1", now)
	if err := st.RecordCommandSeen(ctx, first); err != nil {
		t.Fatalf("record: %v", err)
	}

	stored := seenReceipt("cmd-1", now+5_000)
	stored.CommandType = "trusted_ip_add"
	if err := st.RecordCommandSeen(ctx, stored); err != nil {
		t.Fatalf("re-record: %v", err)
	}

	got, err := st.GetCommandReceipt(ctx, "cmd-1")
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if got.FirstSeenAt != now {
		t.Errorf("first_seen_at = %d; want the original %d", got.FirstSeenAt, now)
	}
	if got.CommandType != "pattern_delete" {
		t.Errorf("command_type = %q; want the first record's %q", got.CommandType, "pattern_delete")
	}
	if got.Terminal() {
		t.Errorf("outcome = %q; a seen-only receipt is not terminal", got.Outcome)
	}
	if got.ExecutedAt != 0 || got.HTTPStatus != 0 || got.Result != "" {
		t.Errorf("non-terminal receipt has execution fields set: %+v", got)
	}
}

func TestRecordCommandSeenRequiresID(t *testing.T) {
	st := receiptStore(t)
	if err := st.RecordCommandSeen(context.Background(), &CommandReceipt{}); err == nil {
		t.Error("recording a receipt with no command id should fail")
	}
	if err := st.RecordCommandSeen(context.Background(), nil); err == nil {
		t.Error("recording a nil receipt should fail")
	}
}

// The first terminal outcome is authoritative: it is what was acked, so a
// second finalize must be refused rather than silently overwrite it.
func TestFinalizeCommandReceiptRefusesOverwrite(t *testing.T) {
	st := receiptStore(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()

	if err := st.RecordCommandSeen(ctx, seenReceipt("cmd-1", now)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := st.FinalizeCommandReceipt(ctx, "cmd-1", now+10, 200, `{"status":"deleted"}`, CommandOutcomeExecuted); err != nil {
		t.Fatalf("finalize: %v", err)
	}

	got, err := st.GetCommandReceipt(ctx, "cmd-1")
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if !got.Terminal() || got.Outcome != CommandOutcomeExecuted {
		t.Errorf("outcome = %q; want %q", got.Outcome, CommandOutcomeExecuted)
	}
	if got.ExecutedAt != now+10 || got.HTTPStatus != 200 || got.Result != `{"status":"deleted"}` {
		t.Errorf("finalized receipt = %+v; want the execution fields recorded", got)
	}

	err = st.FinalizeCommandReceipt(ctx, "cmd-1", now+20, 404, "Pattern not found", CommandOutcomeConverged)
	if !errors.Is(err, ErrCommandReceiptTerminal) {
		t.Fatalf("second finalize error = %v; want ErrCommandReceiptTerminal", err)
	}

	after, err := st.GetCommandReceipt(ctx, "cmd-1")
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if after.Outcome != CommandOutcomeExecuted || after.HTTPStatus != 200 {
		t.Errorf("receipt after refused overwrite = %+v; want the original outcome intact", after)
	}
}

func TestFinalizeCommandReceiptRequiresRowAndOutcome(t *testing.T) {
	st := receiptStore(t)
	ctx := context.Background()

	if err := st.FinalizeCommandReceipt(ctx, "ghost", 1, 200, "", CommandOutcomeExecuted); err == nil {
		t.Error("finalizing a command with no receipt should fail")
	} else if errors.Is(err, ErrCommandReceiptTerminal) {
		t.Errorf("missing receipt reported as terminal: %v", err)
	}

	if err := st.RecordCommandSeen(ctx, seenReceipt("cmd-1", 1)); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := st.FinalizeCommandReceipt(ctx, "cmd-1", 2, 200, "", ""); err == nil {
		t.Error("finalizing without an outcome should fail")
	}
}

// The stored result is bounded - it becomes an ack's result_message.
func TestFinalizeCommandReceiptTruncatesResult(t *testing.T) {
	st := receiptStore(t)
	ctx := context.Background()

	if err := st.RecordCommandSeen(ctx, seenReceipt("cmd-1", 1)); err != nil {
		t.Fatalf("record: %v", err)
	}
	long := strings.Repeat("x", maxCommandResult*3)
	if err := st.FinalizeCommandReceipt(ctx, "cmd-1", 2, 500, long, CommandOutcomeRejected); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	got, err := st.GetCommandReceipt(ctx, "cmd-1")
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	if len(got.Result) != maxCommandResult {
		t.Errorf("stored result length = %d; want it capped at %d", len(got.Result), maxCommandResult)
	}
}

// Receipts are retention-pruned at 90 days, and a recent one survives.
func TestPruneCommandReceipts(t *testing.T) {
	st := receiptStore(t)
	ctx := context.Background()
	now := time.Now()

	old := seenReceipt("cmd-old", now.AddDate(0, 0, -91).UnixMilli())
	recent := seenReceipt("cmd-recent", now.AddDate(0, 0, -89).UnixMilli())
	for _, r := range []*CommandReceipt{old, recent} {
		if err := st.RecordCommandSeen(ctx, r); err != nil {
			t.Fatalf("record %s: %v", r.CommandID, err)
		}
	}

	if err := st.Prune(ctx); err != nil {
		t.Fatalf("prune: %v", err)
	}

	if r, _ := st.GetCommandReceipt(ctx, "cmd-old"); r != nil {
		t.Error("a receipt older than 90 days should have been pruned")
	}
	if r, _ := st.GetCommandReceipt(ctx, "cmd-recent"); r == nil {
		t.Error("a receipt inside the retention window was pruned")
	}
}
