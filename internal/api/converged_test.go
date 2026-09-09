package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/store"
)

// =============================================================================
// Pinned convergence strings + [A7] "2xx means durably done"
// =============================================================================

// The literal values are the contract with the hosted command channel. Editing
// one is a protocol change, so it has to fail here.
func TestConvergedStringsArePinned(t *testing.T) {
	want := map[string]string{
		"ConvergedPatternNotFound":   "Pattern not found",
		"ConvergedTrustedIPExists":   "already trusted",
		"ConvergedTrustedIPNotFound": "Trusted IP not found",
	}
	got := map[string]string{
		"ConvergedPatternNotFound":   ConvergedPatternNotFound,
		"ConvergedTrustedIPExists":   ConvergedTrustedIPExists,
		"ConvergedTrustedIPNotFound": ConvergedTrustedIPNotFound,
	}
	for name, wantValue := range want {
		if got[name] != wantValue {
			t.Errorf("%s = %q; want %q. This string is matched by internal/sync lane C to "+
				"decide that a 4xx means \"already in the desired state\". Changing it turns "+
				"convergence into a command failure - update both sides deliberately.",
				name, got[name], wantValue)
		}
	}
	if n := len(ConvergedResponses()); n != len(want) {
		t.Errorf("ConvergedResponses() has %d entries; want %d - a new pinned string must be listed", n, len(want))
	}
}

// --- test server construction -----------------------------------------------

// newPatternTestServer builds a Server with a real store and a real pattern
// store. When breakPersist is set, the pattern store's atomic write cannot
// succeed: a directory sits where its temp file needs to be. That is the
// fault injection for [A7].
func newPatternTestServer(t *testing.T, breakPersist bool) (*Server, *store.Store, *patternstore.Store) {
	t.Helper()
	dataDir := t.TempDir()

	st, err := store.Init(dataDir)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	patterns, err := patternstore.NewStore(dataDir)
	if err != nil {
		t.Fatalf("init pattern store: %v", err)
	}
	if breakPersist {
		// patternstore.Persist writes patternstore.json.tmp then renames it.
		// A directory at that path makes the write fail on every OS and for
		// every user, including root.
		if err := os.Mkdir(filepath.Join(dataDir, "patternstore.json.tmp"), 0700); err != nil {
			t.Fatalf("blocking pattern persist: %v", err)
		}
		if err := patterns.Persist(); err == nil {
			t.Fatal("pattern persist should fail once its temp path is a directory")
		}
	}

	return &Server{store: st, patterns: patterns}, st, patterns
}

func learnPattern(t *testing.T, patterns *patternstore.Store, scope, verdict, value string) {
	t.Helper()
	err := patterns.Learn(scope, patternstore.Verdict(verdict), patternstore.LearnedPattern{
		Type:      patternstore.PatternHash,
		Value:     value,
		Source:    "test",
		Reason:    "test fixture",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("learn pattern: %v", err)
	}
}

func postJSON(t *testing.T, handler http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func responseError(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil {
		return w.Body.String()
	}
	if msg, ok := decoded["error"].(string); ok {
		return msg
	}
	return w.Body.String()
}

// --- pattern_delete ---------------------------------------------------------

// A delete of a pattern that is not there must answer with the exact pinned
// string, so a redelivered delete command converges instead of failing.
func TestDeletePatternNotFoundUsesPinnedString(t *testing.T) {
	srv, _, _ := newPatternTestServer(t, false)

	w := postJSON(t, srv.handleDeletePattern, "/api/patterns/delete",
		`{"scope":"docker:nginx","verdict":"alert","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d; want 404", w.Code)
	}
	if msg := responseError(t, w); !strings.Contains(msg, ConvergedPatternNotFound) {
		t.Errorf("body = %q; want it to contain the pinned %q", msg, ConvergedPatternNotFound)
	}
}

// [A7] The delete happened in memory but could not be persisted, so it did not
// durably happen. That must be a 500 - a 2xx would tell a dashboard (or a
// hosted command) that the pattern is gone when a restart brings it back.
func TestDeletePatternPersistFailureIs500(t *testing.T) {
	srv, _, patterns := newPatternTestServer(t, true)
	learnPattern(t, patterns, "docker:nginx", "alert", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	w := postJSON(t, srv.handleDeletePattern, "/api/patterns/delete",
		`{"scope":"docker:nginx","verdict":"alert","value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 when the pattern store cannot persist (body: %s)",
			w.Code, w.Body.String())
	}
	if msg := responseError(t, w); !strings.Contains(msg, "persist") {
		t.Errorf("body = %q; want it to say the delete could not be persisted", msg)
	}
}

// The healthy path still returns 2xx.
func TestDeletePatternSuccess(t *testing.T) {
	srv, _, patterns := newPatternTestServer(t, false)
	learnPattern(t, patterns, "docker:nginx", "alert", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	w := postJSON(t, srv.handleDeletePattern, "/api/patterns/delete",
		`{"scope":"docker:nginx","verdict":"alert","value":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}
}

// --- confirm correction -----------------------------------------------------

// [A7] The human-validated mark is the whole durable effect of a confirm.
func TestConfirmCorrectionPersistFailureIs500(t *testing.T) {
	srv, st, patterns := newPatternTestServer(t, true)
	learnPattern(t, patterns, "docker:nginx", "alert", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

	ctx := context.Background()
	finding := &store.Finding{
		EventID:        "evt-confirm-1",
		Timestamp:      time.Now(),
		SourceType:     "docker",
		SourceName:     "nginx",
		Verdict:        "malicious",
		NormalizedHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if err := st.RecordFinding(ctx, finding); err != nil {
		t.Fatalf("record finding: %v", err)
	}

	w := httptest.NewRecorder()
	srv.handleConfirmCorrection(w, ctx, finding, nil, "docker:nginx")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 when the confirm cannot be persisted (body: %s)",
			w.Code, w.Body.String())
	}
}

func TestConfirmCorrectionSuccess(t *testing.T) {
	srv, st, patterns := newPatternTestServer(t, false)
	learnPattern(t, patterns, "docker:nginx", "alert", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

	ctx := context.Background()
	finding := &store.Finding{
		EventID:        "evt-confirm-2",
		Timestamp:      time.Now(),
		SourceType:     "docker",
		SourceName:     "nginx",
		Verdict:        "malicious",
		NormalizedHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	if err := st.RecordFinding(ctx, finding); err != nil {
		t.Fatalf("record finding: %v", err)
	}

	w := httptest.NewRecorder()
	srv.handleConfirmCorrection(w, ctx, finding, nil, "docker:nginx")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}
}

// --- trusted IPs ------------------------------------------------------------

// [A6/A7] Adding an address that is already trusted is a 400 carrying the
// pinned string; a genuinely bad address is a plain 400.
func TestAddTrustedIPResponses(t *testing.T) {
	srv, _, _ := newPatternTestServer(t, false)

	if w := postJSON(t, srv.addTrustedIP, "/api/trusted-ips", `{"ip":"203.0.113.9"}`); w.Code != http.StatusCreated {
		t.Fatalf("first add status = %d; want 201 (body: %s)", w.Code, w.Body.String())
	}

	w := postJSON(t, srv.addTrustedIP, "/api/trusted-ips", `{"ip":"203.0.113.9"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("duplicate add status = %d; want 400", w.Code)
	}
	if msg := responseError(t, w); !strings.Contains(msg, ConvergedTrustedIPExists) {
		t.Errorf("duplicate add body = %q; want the pinned %q", msg, ConvergedTrustedIPExists)
	}

	w = postJSON(t, srv.addTrustedIP, "/api/trusted-ips", `{"ip":"pancakes"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid IP status = %d; want 400", w.Code)
	}
	if msg := responseError(t, w); strings.Contains(msg, ConvergedTrustedIPExists) {
		t.Errorf("invalid IP body = %q; must not look like convergence", msg)
	}
}

// [A7] A delete that found nothing is 404 with the pinned string; a delete
// that failed for any other reason must be a 5xx, because a hosted command
// reads 404 as "already gone" and stops retrying.
func TestDeleteTrustedIPResponses(t *testing.T) {
	srv, st, _ := newPatternTestServer(t, false)

	id, err := st.AddTrustedIP(context.Background(), &store.TrustedIP{IPAddress: "203.0.113.10", AddedBy: "test"})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	body := `{"id":` + itoa(id) + `}`
	if w := postJSON(t, srv.handleDeleteTrustedIP, "/api/trusted-ips/delete", body); w.Code != http.StatusOK {
		t.Fatalf("delete status = %d; want 200 (body: %s)", w.Code, w.Body.String())
	}

	w := postJSON(t, srv.handleDeleteTrustedIP, "/api/trusted-ips/delete", body)
	if w.Code != http.StatusNotFound {
		t.Errorf("second delete status = %d; want 404", w.Code)
	}
	if msg := responseError(t, w); msg != ConvergedTrustedIPNotFound {
		t.Errorf("second delete body = %q; want exactly the pinned %q", msg, ConvergedTrustedIPNotFound)
	}

	// A broken database is not "not found".
	st.Close()
	w = postJSON(t, srv.handleDeleteTrustedIP, "/api/trusted-ips/delete", body)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("delete against a closed database = %d; want 500 (body: %s)", w.Code, w.Body.String())
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// [A7] "Not found" is convergence to the hosted command channel, so it must
// not be answered while the store's state is unpersistable. Otherwise this
// sequence lies: delete succeeds in memory -> persist fails (500) -> the
// command is retried -> memory says "not there" -> 404 -> reported as a
// completed delete, with the pattern still on disk waiting for a restart.
func TestDeletePatternNotFoundWithBrokenPersistIs500(t *testing.T) {
	srv, _, _ := newPatternTestServer(t, true)

	w := postJSON(t, srv.handleDeletePattern, "/api/patterns/delete",
		`{"scope":"docker:nginx","verdict":"alert","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; want 500 - absence is not durable while persist fails (body: %s)",
			w.Code, w.Body.String())
	}
	if msg := responseError(t, w); strings.Contains(msg, ConvergedPatternNotFound) {
		t.Errorf("body = %q; it must not look like convergence", msg)
	}
}
