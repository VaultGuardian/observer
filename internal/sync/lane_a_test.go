package sync

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

// Test 1: a cursor drain walks the whole backlog in rowid order, one full
// scan window at a time, and lands the cursor on the last row.
func TestCursorAdvanceAndDrain(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	insertFindings(t, st, 450, "evt")

	e := newTestEngine(t, st, ingest)
	drainLaneA(t, e)

	posts := ingest.postsTo(pathFindings)
	if len(posts) != 3 {
		t.Fatalf("findings POSTs = %d; want 3 (200/200/50)", len(posts))
	}
	want := []int{200, 200, 50}
	for i, post := range posts {
		if len(post.Items) != want[i] {
			t.Errorf("POST %d carried %d items; want %d", i, len(post.Items), want[i])
		}
	}

	// Rowid order across the whole drain: event ids were generated in
	// insertion order, so the wire order must be monotonically increasing.
	var seen []string
	for _, post := range posts {
		for _, item := range post.Items {
			seen = append(seen, itemField(t, item, "event_id"))
		}
	}
	if len(seen) != 450 {
		t.Fatalf("sent %d items; want 450", len(seen))
	}
	for i := 1; i < len(seen); i++ {
		if seen[i-1] >= seen[i] {
			t.Fatalf("wire order not ascending at %d: %q then %q", i, seen[i-1], seen[i])
		}
	}

	if got := cursor(t, st, store.SyncStreamFindings); got != 450 {
		t.Errorf("findings cursor = %d; want 450", got)
	}
}

// Test 2: a restarted engine resumes from the stored cursor instead of
// replaying everything.
func TestCursorResumeAcrossRestart(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	insertFindings(t, st, 10, "first")

	drainLaneA(t, newTestEngine(t, st, ingest))
	if got := cursor(t, st, store.SyncStreamFindings); got != 10 {
		t.Fatalf("cursor after first run = %d; want 10", got)
	}

	// New engine, same store and same target: must resume, not resync.
	ingest.reset()
	insertFindings(t, st, 5, "second")
	drainLaneA(t, newTestEngine(t, st, ingest))

	posts := ingest.postsTo(pathFindings)
	if len(posts) != 1 {
		t.Fatalf("POSTs after restart = %d; want 1", len(posts))
	}
	if len(posts[0].Items) != 5 {
		t.Errorf("items after restart = %d; want 5 (only the new rows)", len(posts[0].Items))
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 15 {
		t.Errorf("cursor after restart = %d; want 15", got)
	}
}

// Test 3: a 5xx leaves the cursor alone and the same rows are retried.
func TestRetryWithoutAdvanceOn500(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	insertFindings(t, st, 5, "evt")
	e := newTestEngine(t, st, ingest)

	ingest.setResponder(func(string, int) (int, string) {
		return 500, `{"error":"boom"}`
	})
	if _, _, err := e.laneACycle(context.Background()); err == nil {
		t.Fatal("cycle succeeded despite HTTP 500")
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 0 {
		t.Fatalf("cursor advanced to %d on failure; want 0", got)
	}

	ingest.setResponder(nil)
	drainLaneA(t, e)
	if got := cursor(t, st, store.SyncStreamFindings); got != 5 {
		t.Errorf("cursor after recovery = %d; want 5", got)
	}
	if n := len(ingest.postsTo(pathFindings)); n != 2 {
		t.Errorf("findings POSTs = %d; want 2 (failed attempt + retry)", n)
	}
}

// Backoff grows on repeated failure and resets to the base interval on the
// first validated success.
func TestBackoffGrowsAndResets(t *testing.T) {
	base := 15 * time.Second

	current := base
	for _, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, maxBackoff, maxBackoff} {
		current = nextBackoff(current, base)
		if current != want {
			t.Fatalf("nextBackoff = %s; want %s", current, want)
		}
	}
	// The loop resets to the base interval on success; the helper must
	// never return anything below it.
	if got := nextBackoff(time.Millisecond, base); got != 2*base {
		t.Errorf("nextBackoff below base = %s; want %s", got, 2*base)
	}
}

// Test 4 [A3]: a 2xx that reports skipped rows is a FAILURE. After local
// pre-validation, hosted skips mean contract drift - advancing past those
// rows would lose them permanently.
func TestAckWithSkippedDoesNotAdvance(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	insertFindings(t, st, 5, "evt")
	e := newTestEngine(t, st, ingest)

	ingest.setResponder(func(_ string, n int) (int, string) {
		return 200, fmt.Sprintf(`{"ok":true,"upserted":%d,"skipped":1}`, n-1)
	})
	_, _, err := e.laneACycle(context.Background())
	if err == nil {
		t.Fatal("cycle succeeded on an ack reporting skipped rows")
	}
	if !strings.Contains(err.Error(), "skipped=1") {
		t.Errorf("error %q does not report the skipped count", err)
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 0 {
		t.Fatalf("cursor advanced to %d on a skipped ack; want 0", got)
	}

	// The same batch is retried and succeeds once the mirror behaves.
	ingest.setResponder(nil)
	drainLaneA(t, e)
	posts := ingest.postsTo(pathFindings)
	if len(posts) != 2 || len(posts[1].Items) != 5 {
		t.Fatalf("retry did not re-send the same 5 rows: %d posts, last had %d items",
			len(posts), len(posts[len(posts)-1].Items))
	}
}

// An ack whose upserted count disagrees with what we sent is equally a
// failure, even with skipped == 0.
func TestAckWithWrongUpsertedCountDoesNotAdvance(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	insertFindings(t, st, 4, "evt")
	e := newTestEngine(t, st, ingest)

	ingest.setResponder(func(string, int) (int, string) {
		return 200, `{"ok":true,"upserted":1,"skipped":0}`
	})
	if _, _, err := e.laneACycle(context.Background()); err == nil {
		t.Fatal("cycle succeeded on an under-counted ack")
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 0 {
		t.Errorf("cursor = %d; want 0", got)
	}
}

// Test 5 [A3]: a row the hosted ingest could never accept is skipped locally
// and the cursor still moves past it, so one bad row cannot wedge the stream.
func TestPreValidationSkipsUnsendableRow(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()

	if err := st.RecordLLMDecision(ctx, testDecision("dec-1")); err != nil {
		t.Fatal(err)
	}
	bad := testDecision("")
	if err := st.RecordLLMDecision(ctx, bad); err != nil { // empty event_id
		t.Fatal(err)
	}
	if err := st.RecordLLMDecision(ctx, testDecision("dec-3")); err != nil {
		t.Fatal(err)
	}

	drainLaneA(t, newTestEngine(t, st, ingest))

	posts := ingest.postsTo(pathDecisions)
	if len(posts) != 1 {
		t.Fatalf("decision POSTs = %d; want 1", len(posts))
	}
	if len(posts[0].Items) != 2 {
		t.Fatalf("sent %d decisions; want 2 (the empty event_id row is skipped)", len(posts[0].Items))
	}
	for _, item := range posts[0].Items {
		if itemField(t, item, "event_id") == "" {
			t.Error("an item with an empty event_id reached the wire")
		}
	}
	if got := cursor(t, st, store.SyncStreamDecisions); got != 3 {
		t.Errorf("decisions cursor = %d; want 3 (past the skipped row)", got)
	}
}

// Test 6 [A5]: an oversized scan window splits into several POSTs, each under
// the byte budget, with the cursor advancing per-POST to what was sent.
func TestByteBudgetSplitsBatches(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()

	// Each row carries ~20KB of (already capped) text, so one 200-row window
	// exceeds the 3MB budget and must split.
	for i := 0; i < scanWindow; i++ {
		f := testFinding(fmt.Sprintf("big-%03d", i))
		f.RawLine = strings.Repeat("a", capRawLine)
		f.NormalizedLine = strings.Repeat("b", capNormalizedLine)
		f.Reason = strings.Repeat("c", capReason)
		if err := st.RecordFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
	}

	e := newTestEngine(t, st, ingest)
	// One cycle, so the per-POST cursor advancement inside a single scan
	// window is what we observe.
	if _, _, err := e.laneACycle(ctx); err != nil {
		t.Fatalf("cycle: %v", err)
	}

	posts := ingest.postsTo(pathFindings)
	if len(posts) < 2 {
		t.Fatalf("POSTs = %d; want the window split across at least 2", len(posts))
	}
	total := 0
	for i, post := range posts {
		if len(post.Body) > maxBatchBytes {
			t.Errorf("POST %d body = %d bytes; over the %d budget", i, len(post.Body), maxBatchBytes)
		}
		total += len(post.Items)
	}
	if total != scanWindow {
		t.Errorf("sent %d items across the split; want %d", total, scanWindow)
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != int64(scanWindow) {
		t.Errorf("cursor after split window = %d; want %d", got, scanWindow)
	}
}

// splitBatches is the budget primitive; check it directly at the boundaries.
func TestSplitBatchesRespectsBudgets(t *testing.T) {
	// Item-count boundary.
	small := make([]preparedItem, maxBatchItems+1)
	for i := range small {
		small[i] = preparedItem{rowid: int64(i + 1), encoded: []byte(`{"a":1}`)}
	}
	batches := splitBatches(keyFindings, small)
	if len(batches) != 2 || len(batches[0]) != maxBatchItems || len(batches[1]) != 1 {
		t.Fatalf("item-count split = %d batches (%v); want 200 + 1", len(batches), batchSizes(batches))
	}

	// Byte boundary: two items that individually fit but together do not.
	half := append([]byte(`"`), append([]byte(strings.Repeat("x", maxBatchBytes*2/3)), '"')...)
	big := []preparedItem{{rowid: 1, encoded: half}, {rowid: 2, encoded: half}}
	batches = splitBatches(keyFindings, big)
	if len(batches) != 2 {
		t.Fatalf("byte split = %d batches; want 2", len(batches))
	}

	// A single item over budget still ships rather than being dropped.
	huge := []preparedItem{{rowid: 1, encoded: append([]byte(`"`), append([]byte(strings.Repeat("x", maxBatchBytes+10)), '"')...)}}
	if got := splitBatches(keyFindings, huge); len(got) != 1 || len(got[0]) != 1 {
		t.Fatalf("over-budget single item = %v; want one batch of one", batchSizes(got))
	}

	if got := splitBatches(keyFindings, nil); got != nil {
		t.Errorf("empty input = %v; want nil", got)
	}
}

func batchSizes(batches [][]preparedItem) []int {
	out := make([]int, len(batches))
	for i, b := range batches {
		out[i] = len(b)
	}
	return out
}

// Test 7 [A5]: oversized text arrives at the ingest already capped, with the
// exact hosted marker.
func TestPreTruncationUsesHostedMarker(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)

	f := testFinding("huge")
	f.RawLine = strings.Repeat("z", capRawLine*3)
	if err := st.RecordFinding(context.Background(), f); err != nil {
		t.Fatal(err)
	}

	drainLaneA(t, newTestEngine(t, st, ingest))

	posts := ingest.postsTo(pathFindings)
	if len(posts) != 1 || len(posts[0].Items) != 1 {
		t.Fatalf("want exactly one item on the wire, got %v", batchSizes(nil))
	}
	got := itemField(t, posts[0].Items[0], "raw_line")
	want := strings.Repeat("z", capRawLine) + truncationMarker
	if got != want {
		t.Errorf("raw_line on the wire = %d bytes ending %q; want %d bytes ending %q",
			len(got), tail(got, 30), len(want), tail(want, 30))
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// Truncation must be idempotent: the hosted ingest re-applying its own cap to
// our already-capped value has to converge on the same bytes, or the two
// sides would never agree.
func TestTruncationIsIdempotent(t *testing.T) {
	once := truncateField(strings.Repeat("q", 20000), capRawLine)
	twice := truncateField(once, capRawLine)
	if once != twice {
		t.Errorf("truncation not idempotent: %d bytes then %d bytes", len(once), len(twice))
	}
}

// Truncation must never split a multi-byte rune, which the JSON encoder would
// rewrite as U+FFFD - different bytes than the hosted side would store.
func TestTruncationKeepsValidUTF8(t *testing.T) {
	// "é" is two bytes, so a cap landing mid-character is guaranteed.
	input := strings.Repeat("é", capDefaultString)
	got := truncateField(input, capDefaultString+1)
	body := strings.TrimSuffix(got, truncationMarker)
	if body == got {
		t.Fatal("expected the value to be truncated")
	}
	if !utf8Valid(body) {
		t.Error("truncated value is not valid UTF-8")
	}
}

func utf8Valid(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// Test 11 [A2]: several rows of one event inside a single scan window collapse
// to the newest, but the cursor still covers the whole window.
func TestBatchCollapsesDuplicateEvents(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		f := testFinding("shared")
		f.Reason = fmt.Sprintf("version-%d", i)
		if err := st.RecordFinding(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordFinding(ctx, testFinding("other")); err != nil {
		t.Fatal(err)
	}

	drainLaneA(t, newTestEngine(t, st, ingest))

	posts := ingest.postsTo(pathFindings)
	if len(posts) != 1 {
		t.Fatalf("POSTs = %d; want 1", len(posts))
	}
	if len(posts[0].Items) != 2 {
		t.Fatalf("items = %d; want 2 (newest 'shared' plus 'other')", len(posts[0].Items))
	}
	var sharedReason string
	for _, item := range posts[0].Items {
		if itemField(t, item, "event_id") == "shared" {
			sharedReason = itemField(t, item, "reason")
		}
	}
	if sharedReason != "version-2" {
		t.Errorf("collapsed 'shared' carried reason %q; want the newest, version-2", sharedReason)
	}
	if got := cursor(t, st, store.SyncStreamFindings); got != 4 {
		t.Errorf("cursor = %d; want 4 (the scanned max, including collapsed rows)", got)
	}
}
