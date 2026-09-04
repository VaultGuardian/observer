package sync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	stdsync "sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

const testToken = "test-ingest-token"

// recordedPost is one request the fake hosted ingest received.
type recordedPost struct {
	Path  string
	Body  []byte
	Items []json.RawMessage // decoded from the batch envelope, if any
}

// fakeIngest is a scriptable stand-in for the hosted ingest routes.
type fakeIngest struct {
	*httptest.Server

	mu    stdsync.Mutex
	posts []recordedPost

	// respond overrides the default "accept everything" behavior. It returns
	// the HTTP status and the raw response body.
	respond func(path string, itemCount int) (int, string)
}

func newFakeIngest(t *testing.T) *fakeIngest {
	t.Helper()
	f := &fakeIngest{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("ingest auth header = %q; want bearer %q", got, testToken)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body := make([]byte, 0)
		buf := make([]byte, 32*1024)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}

		items := decodeBatchItems(body)
		f.mu.Lock()
		f.posts = append(f.posts, recordedPost{Path: r.URL.Path, Body: body, Items: items})
		respond := f.respond
		f.mu.Unlock()

		status, payload := http.StatusOK, fmt.Sprintf(`{"ok":true,"upserted":%d,"skipped":0}`, len(items))
		if respond != nil {
			status, payload = respond(r.URL.Path, len(items))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(payload))
	}))
	t.Cleanup(f.Close)
	return f
}

// decodeBatchItems pulls the item array out of a findings/decisions envelope.
// Non-batch bodies (heartbeat, stats, snapshot) decode to nil.
func decodeBatchItems(body []byte) []json.RawMessage {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(body, &envelope) != nil {
		return nil
	}
	for _, key := range []string{keyFindings, keyDecisions} {
		raw, ok := envelope[key]
		if !ok {
			continue
		}
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) == nil {
			return items
		}
	}
	return nil
}

func (f *fakeIngest) setResponder(fn func(path string, itemCount int) (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.respond = fn
}

func (f *fakeIngest) snapshotPosts() []recordedPost {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recordedPost, len(f.posts))
	copy(out, f.posts)
	return out
}

// postsTo returns only the requests aimed at one ingest route.
func (f *fakeIngest) postsTo(path string) []recordedPost {
	var out []recordedPost
	for _, p := range f.snapshotPosts() {
		if p.Path == path {
			out = append(out, p)
		}
	}
	return out
}

func (f *fakeIngest) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posts = nil
}

// --- store + engine construction -------------------------------------------

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func newTestEngine(t *testing.T, st *store.Store, ingest *fakeIngest) *Engine {
	t.Helper()
	e, err := newTestEngineErr(t, st, ingest, testToken)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return e
}

func newTestEngineErr(t *testing.T, st *store.Store, ingest *fakeIngest, token string) (*Engine, error) {
	t.Helper()
	return New(context.Background(), st, Config{
		BaseURL:           ingest.URL,
		Token:             token,
		Interval:          50 * time.Millisecond,
		SnapshotInterval:  time.Hour,
		HeartbeatInterval: time.Hour,
	})
}

// --- row fixtures -----------------------------------------------------------

func testFinding(eventID string) *store.Finding {
	return &store.Finding{
		EventID:        eventID,
		Timestamp:      time.Now().UTC().Truncate(time.Second),
		SourceType:     "docker",
		SourceName:     "docker:nginx",
		SourceIP:       "203.0.113.7",
		HTTPMethod:     "GET",
		HTTPPath:       "/.env",
		HTTPStatus:     404,
		Verdict:        "recon",
		Classification: "recon_failed",
		MatchedVia:     "pattern",
	}
}

func insertFindings(t *testing.T, st *store.Store, n int, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.RecordFinding(context.Background(), testFinding(fmt.Sprintf("%s-%03d", prefix, i))); err != nil {
			t.Fatalf("record finding %d: %v", i, err)
		}
	}
}

func testDecision(eventID string) *store.LLMDecision {
	return &store.LLMDecision{
		EventID:        eventID,
		Timestamp:      time.Now().UTC().Truncate(time.Second),
		Tier:           "classify",
		Model:          "qwen2.5:7b",
		Classification: "malicious",
		Action:         "alert",
		Confidence:     0.91,
		Reason:         "credential probe",
		LLMResponseRaw: `{"classification":"malicious"}`,
	}
}

func insertDecisions(t *testing.T, st *store.Store, n int, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.RecordLLMDecision(context.Background(), testDecision(fmt.Sprintf("%s-%03d", prefix, i))); err != nil {
			t.Fatalf("record decision %d: %v", i, err)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// drainLaneA runs lane A cycles until there is no more queued work, mirroring
// runLaneA's drain loop without its timer.
func drainLaneA(t *testing.T, e *Engine) {
	t.Helper()
	for i := 0; i < 100; i++ {
		more, _, err := e.laneACycle(context.Background())
		if err != nil {
			t.Fatalf("lane A cycle: %v", err)
		}
		if !more {
			return
		}
	}
	t.Fatal("lane A drain did not converge in 100 cycles")
}

func cursor(t *testing.T, st *store.Store, stream string) int64 {
	t.Helper()
	c, err := st.GetSyncCursor(context.Background(), stream)
	if err != nil {
		t.Fatalf("get cursor %s: %v", stream, err)
	}
	return c
}

func dirtyCount(t *testing.T, st *store.Store, kind string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRow("SELECT COUNT(*) FROM sync_dirty WHERE kind = ?", kind).Scan(&n); err != nil {
		t.Fatalf("count sync_dirty %s: %v", kind, err)
	}
	return n
}

// itemField pulls one string field out of a recorded wire item.
func itemField(t *testing.T, item json.RawMessage, field string) string {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(item, &decoded); err != nil {
		t.Fatalf("decode wire item: %v", err)
	}
	value, ok := decoded[field]
	if !ok {
		return ""
	}
	s, ok := value.(string)
	if !ok {
		t.Fatalf("wire field %q is %T, want string", field, value)
	}
	return s
}
