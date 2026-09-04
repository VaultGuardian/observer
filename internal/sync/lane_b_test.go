package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	stdsync "sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

const localToken = "local-dashboard-token"

// fakeLocalAPI stands in for Observer's own dashboard API, which lane B reads
// so the hosted mirror receives byte-identical payloads.
type fakeLocalAPI struct {
	*httptest.Server

	mu   stdsync.Mutex
	fail map[string]int // path -> status to return instead of the body
	hits []string
}

func newFakeLocalAPI(t *testing.T) *fakeLocalAPI {
	t.Helper()
	l := &fakeLocalAPI{fail: map[string]int{}}
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+localToken {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}

		l.mu.Lock()
		l.hits = append(l.hits, r.URL.RequestURI())
		status := l.fail[r.URL.Path]
		l.mu.Unlock()

		if status != 0 {
			w.WriteHeader(status)
			w.Write([]byte(`{"error":"unavailable"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/stats":
			w.Write([]byte(`{"processed":42,"pattern_hits":7}`))
		case "/api/patterns":
			if scope := r.URL.Query().Get("scope"); scope != "" {
				w.Write([]byte(`{"scope":"` + scope + `","allow":[],"malicious":[]}`))
				return
			}
			w.Write([]byte(`[{"scope_key":"__global__","allow_count":1},{"scope_key":"docker:nginx","allow_count":2}]`))
		case "/api/trusted-ips":
			w.Write([]byte(`[{"ip_address":"198.51.100.4"}]`))
		case "/api/rec/coverage":
			w.Write([]byte(`{"mode":"namespace","containers":3}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not found"}`))
		}
	}))
	t.Cleanup(l.Close)
	return l
}

func (l *fakeLocalAPI) breakPath(path string, status int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail[path] = status
}

// newLaneBEngine wires an engine against both fakes, with a real key file so
// the [A10] "read the token once at construction" path is exercised.
func newLaneBEngine(t *testing.T, st *store.Store, ingest *fakeIngest, localURL string) *Engine {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "dashboard.key")
	if err := os.WriteFile(keyFile, []byte(localToken+"\n"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	e, err := New(context.Background(), st, Config{
		BaseURL:           ingest.URL,
		Token:             testToken,
		Interval:          50 * time.Millisecond,
		SnapshotInterval:  time.Hour,
		HeartbeatInterval: time.Hour,
		LocalBaseURL:      localURL,
		LocalKeyFile:      keyFile,
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return e
}

func decodeObject(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var out map[string]json.RawMessage
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode body %s: %v", snippet(body), err)
	}
	return out
}

// Test 16: the snapshot lane ships stats on its own route and merges the
// patterns composite, trusted IPs and REC coverage into one snapshot.
func TestSnapshotShipsAllSections(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	local := newFakeLocalAPI(t)

	e := newLaneBEngine(t, st, ingest, local.URL)
	e.sendSnapshot(context.Background())

	statsPosts := ingest.postsTo(pathIngestStats)
	if len(statsPosts) != 1 {
		t.Fatalf("stats POSTs = %d; want 1", len(statsPosts))
	}
	stats := decodeObject(t, statsPosts[0].Body)
	if string(stats["stats"]) != `{"processed":42,"pattern_hits":7}` {
		t.Errorf("stats body was not forwarded verbatim: %s", stats["stats"])
	}

	snapPosts := ingest.postsTo(pathIngestSnapshot)
	if len(snapPosts) != 1 {
		t.Fatalf("snapshot POSTs = %d; want 1", len(snapPosts))
	}
	snap := decodeObject(t, snapPosts[0].Body)
	for _, key := range []string{"patterns", "trusted_ips", "rec_coverage"} {
		if _, ok := snap[key]; !ok {
			t.Errorf("snapshot is missing %q", key)
		}
	}
	if string(snap["rec_coverage"]) != `{"mode":"namespace","containers":3}` {
		t.Errorf("rec_coverage not verbatim: %s", snap["rec_coverage"])
	}

	// The patterns composite: the scope list verbatim plus one entry per scope.
	patterns := decodeObject(t, snap["patterns"])
	if !strings.Contains(string(patterns["scopes"]), `"scope_key":"__global__"`) {
		t.Errorf("scopes not forwarded verbatim: %s", patterns["scopes"])
	}
	byScope := decodeObject(t, patterns["by_scope"])
	if len(byScope) != 2 {
		t.Fatalf("by_scope has %d entries; want 2", len(byScope))
	}
	if got := string(byScope["docker:nginx"]); !strings.Contains(got, `"scope":"docker:nginx"`) {
		t.Errorf("by_scope[docker:nginx] = %s; want the per-scope body verbatim", got)
	}
}

// A single failing local endpoint degrades that section only - the rest of the
// snapshot still ships.
func TestSnapshotSurvivesOneFailingLocalEndpoint(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	local := newFakeLocalAPI(t)
	local.breakPath("/api/rec/coverage", http.StatusInternalServerError)

	e := newLaneBEngine(t, st, ingest, local.URL)
	e.sendSnapshot(context.Background())

	snapPosts := ingest.postsTo(pathIngestSnapshot)
	if len(snapPosts) != 1 {
		t.Fatalf("snapshot POSTs = %d; want 1", len(snapPosts))
	}
	snap := decodeObject(t, snapPosts[0].Body)
	if _, ok := snap["rec_coverage"]; ok {
		t.Error("rec_coverage was included despite the local GET failing")
	}
	for _, key := range []string{"patterns", "trusted_ips"} {
		if _, ok := snap[key]; !ok {
			t.Errorf("snapshot is missing %q, which succeeded locally", key)
		}
	}
}

// [A10] A dead local API must cost lane B only, never lane A.
func TestDeadLocalAPILeavesLaneAWorking(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	ctx := context.Background()
	insertFindings(t, st, 3, "evt")

	// A local base URL nothing is listening on.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	e := newLaneBEngine(t, st, ingest, deadURL)
	e.sendSnapshot(ctx)

	if n := len(ingest.postsTo(pathIngestSnapshot)); n != 0 {
		t.Errorf("snapshot POSTs with nothing readable locally = %d; want 0 (skip, do not send an empty merge)", n)
	}
	if n := len(ingest.postsTo(pathIngestStats)); n != 0 {
		t.Errorf("stats POSTs with a dead local API = %d; want 0", n)
	}

	drainLaneA(t, e)
	if got := cursor(t, st, store.SyncStreamFindings); got != 3 {
		t.Errorf("findings cursor = %d; want 3 - lane A must be unaffected", got)
	}
}

// The heartbeat is a bare authenticated POST on its own clock.
func TestHeartbeatPostsEmptyObject(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	local := newFakeLocalAPI(t)

	e := newLaneBEngine(t, st, ingest, local.URL)
	e.sendHeartbeat(context.Background())

	posts := ingest.postsTo(pathIngestHeartbeat)
	if len(posts) != 1 {
		t.Fatalf("heartbeat POSTs = %d; want 1", len(posts))
	}
	if got := strings.TrimSpace(string(posts[0].Body)); got != "{}" {
		t.Errorf("heartbeat body = %q; want {}", got)
	}
}

// Start/Stop must be clean: three goroutines up, all down, twice-safe.
func TestStartStopIsClean(t *testing.T) {
	st := newTestStore(t)
	ingest := newFakeIngest(t)
	local := newFakeLocalAPI(t)
	insertFindings(t, st, 2, "evt")

	e := newLaneBEngine(t, st, ingest, local.URL)
	e.Start(context.Background())

	// The startup heartbeat is asynchronous; wait for it rather than racing.
	deadline := time.Now().Add(5 * time.Second)
	for len(ingest.postsTo(pathIngestHeartbeat)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no heartbeat within 5s of Start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	e.Stop()
	e.Stop() // idempotent
}
