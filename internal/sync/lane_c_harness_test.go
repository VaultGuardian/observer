package sync

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	stdsync "sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

// =============================================================================
// Lane C harness
// =============================================================================
//
// Same shape as the lane A/B harness: a scriptable stand-in for the hosted
// side, a scriptable stand-in for Observer's own local API, and a real store.
// Lane C is exercised by calling pollCommands directly - the goroutine around
// it is just a ticker, and driving the cycle synchronously keeps every
// assertion deterministic.

const (
	testInstanceID = "11111111-2222-3333-4444-555555555555"
	testEpoch      = "epoch-7"
	testLocalToken = "local-api-token-for-commands"
)

// --- hosted side -------------------------------------------------------------

// commandHost serves GET /api/ingest/commands and POST .../ack.
type commandHost struct {
	*httptest.Server

	mu stdsync.Mutex

	// batch is what the next poll serves, in order.
	batch []hostedCommand
	// rawBatch, when non-empty, is served verbatim instead of encoding batch
	// (for oversize and undecodable-response cases).
	rawBatch string
	// pollStatus overrides the poll's HTTP status when non-zero.
	pollStatus int

	polls int
	acks  []commandAck

	// ackStatus lets a test fail the ack endpoint. Returns 0 for "accept".
	ackStatus func(ack commandAck) int
}

func newCommandHost(t *testing.T) *commandHost {
	t.Helper()
	h := &commandHost{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("hosted auth header = %q; want bearer %q", got, testToken)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == pathIngestCommands:
			h.servePoll(w)
		case r.Method == http.MethodPost && r.URL.Path == pathIngestCommandsAck:
			h.serveAck(t, w, r)
		default:
			t.Errorf("unexpected hosted request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *commandHost) servePoll(w http.ResponseWriter) {
	h.mu.Lock()
	h.polls++
	batch := append([]hostedCommand(nil), h.batch...)
	raw := h.rawBatch
	status := h.pollStatus
	h.mu.Unlock()

	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if raw != "" {
		io.WriteString(w, raw)
		return
	}
	json.NewEncoder(w).Encode(commandBatch{Commands: batch})
}

func (h *commandHost) serveAck(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var ack commandAck
	if err := json.Unmarshal(body, &ack); err != nil {
		t.Errorf("ack body is not decodable: %v (%s)", err, body)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(ack.ResultMessage) > maxResultMessage {
		t.Errorf("ack result_message is %d bytes; contract caps it at %d",
			len(ack.ResultMessage), maxResultMessage)
	}
	if ack.Status != ackStatusAcked && ack.Status != ackStatusFailed {
		t.Errorf("ack status = %q; want %q or %q", ack.Status, ackStatusAcked, ackStatusFailed)
	}

	h.mu.Lock()
	override := h.ackStatus
	h.mu.Unlock()

	if override != nil {
		if status := override(ack); status != 0 {
			w.WriteHeader(status)
			io.WriteString(w, `{"error":"ack rejected"}`)
			return
		}
	}

	h.mu.Lock()
	h.acks = append(h.acks, ack)
	h.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `{"ok":true}`)
}

func (h *commandHost) serve(commands ...hostedCommand) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.batch = commands
	h.rawBatch = ""
}

func (h *commandHost) serveRaw(body string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rawBatch = body
}

func (h *commandHost) failAcks(fn func(ack commandAck) int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ackStatus = fn
}

func (h *commandHost) ackList() []commandAck {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]commandAck(nil), h.acks...)
}

// ackFor returns the ack recorded for one command id, if any.
func (h *commandHost) ackFor(id string) (commandAck, bool) {
	for _, a := range h.ackList() {
		if a.ID == id {
			return a, true
		}
	}
	return commandAck{}, false
}

func (h *commandHost) ackCount(id string) int {
	n := 0
	for _, a := range h.ackList() {
		if a.ID == id {
			n++
		}
	}
	return n
}

// --- local API ---------------------------------------------------------------

// localCall is one request lane C made against the local dashboard API.
type localCall struct {
	Path        string
	Body        []byte
	ContentType string
	Auth        string
	Method      string
}

// localCommandAPI stands in for Observer's own API server.
type localCommandAPI struct {
	*httptest.Server

	mu    stdsync.Mutex
	calls []localCall

	// respond returns the status and body for one call. Nil means 200 {}.
	respond func(call localCall, n int) (int, string)
}

func newLocalCommandAPI(t *testing.T) *localCommandAPI {
	t.Helper()
	l := &localCommandAPI{}
	l.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		call := localCall{
			Path:        r.URL.Path,
			Body:        body,
			ContentType: r.Header.Get("Content-Type"),
			Auth:        r.Header.Get("Authorization"),
			Method:      r.Method,
		}

		l.mu.Lock()
		l.calls = append(l.calls, call)
		n := len(l.calls)
		respond := l.respond
		l.mu.Unlock()

		status, payload := http.StatusOK, `{"status":"ok"}`
		if respond != nil {
			status, payload = respond(call, n)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, payload)
	}))
	t.Cleanup(l.Close)
	return l
}

func (l *localCommandAPI) setResponder(fn func(call localCall, n int) (int, string)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.respond = fn
}

func (l *localCommandAPI) callList() []localCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]localCall(nil), l.calls...)
}

func (l *localCommandAPI) paths() []string {
	var out []string
	for _, c := range l.callList() {
		out = append(out, c.Path)
	}
	return out
}

// --- signing -----------------------------------------------------------------

// commandSigner mints commands the way the hosted control plane will.
type commandSigner struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	instance string
	epoch    string
}

func newCommandSigner(t *testing.T) commandSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return commandSigner{priv: priv, pub: pub, instance: testInstanceID, epoch: testEpoch}
}

// command builds a valid, signed command for the given type and payload.
// Mutators run BEFORE signing, so they produce legitimately signed variants
// (a different epoch, a different instance); tampering after signing is done
// in the test itself.
func (s commandSigner) command(id, cmdType string, payload []byte, mutators ...func(*hostedCommand)) hostedCommand {
	now := time.Now().UnixMilli()
	cmd := hostedCommand{
		ID:          id,
		Type:        cmdType,
		PayloadB64:  base64.StdEncoding.EncodeToString(payload),
		Epoch:       s.epoch,
		IssuedAtMS:  now,
		ExpiresAtMS: now + int64(24*time.Hour/time.Millisecond),
	}
	for _, m := range mutators {
		m(&cmd)
	}
	s.sign(&cmd)
	return cmd
}

// sign (re)signs a command in place, using its current field values.
func (s commandSigner) sign(cmd *hostedCommand) {
	instance := cmd.InstanceID
	if instance == "" {
		instance = s.instance
	}
	payload, _ := base64.StdEncoding.DecodeString(cmd.PayloadB64)
	msg := commandSigMessage(cmd.ID, instance, cmd.Epoch, cmd.Type,
		sha256Hex(payload), cmd.IssuedAtMS, cmd.ExpiresAtMS)
	cmd.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, msg))
}

// --- engine ------------------------------------------------------------------

// newLaneCEngine wires an engine with lane C fully configured against both
// fakes, including a real dashboard key file (the [A10] read-token-once path).
func newLaneCEngine(t *testing.T, st *store.Store, host *commandHost, local *localCommandAPI, signer commandSigner) *Engine {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "dashboard.key")
	if err := os.WriteFile(keyFile, []byte(testLocalToken+"\n"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	e, err := New(context.Background(), st, Config{
		BaseURL:           host.URL,
		Token:             testToken,
		Interval:          time.Hour,
		SnapshotInterval:  time.Hour,
		HeartbeatInterval: time.Hour,
		LocalBaseURL:      local.URL,
		LocalKeyFile:      keyFile,
		InstanceID:        testInstanceID,
		VerifyKey:         signer.pub,
		Epoch:             testEpoch,
		CommandInterval:   time.Hour,
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if !e.commandsEnabled() {
		t.Fatal("lane C should be enabled with a full pairing")
	}
	return e
}

// --- assertions --------------------------------------------------------------

func receipt(t *testing.T, st *store.Store, id string) *store.CommandReceipt {
	t.Helper()
	r, err := st.GetCommandReceipt(context.Background(), id)
	if err != nil {
		t.Fatalf("get receipt %s: %v", id, err)
	}
	return r
}

// wantOutcome asserts a receipt exists and holds the expected outcome.
func wantOutcome(t *testing.T, st *store.Store, id, outcome string) *store.CommandReceipt {
	t.Helper()
	r := receipt(t, st, id)
	if r == nil {
		t.Fatalf("no receipt recorded for %s (want outcome %q)", id, outcome)
	}
	if r.Outcome != outcome {
		t.Errorf("receipt %s outcome = %q; want %q (result: %s)", id, r.Outcome, outcome, r.Result)
	}
	return r
}

// wantAck asserts exactly one ack with the expected status.
func wantAck(t *testing.T, host *commandHost, id, status string) commandAck {
	t.Helper()
	if n := host.ackCount(id); n != 1 {
		t.Fatalf("acks for %s = %d; want exactly 1 (%+v)", id, n, host.ackList())
	}
	ack, _ := host.ackFor(id)
	if ack.Status != status {
		t.Errorf("ack %s status = %q; want %q (message: %s)", id, ack.Status, status, ack.ResultMessage)
	}
	return ack
}

// drainNudges reports how many nudges are queued on each channel and empties
// them, so a test can assert "fired once".
func drainNudges(e *Engine) (dirty, snapshot int) {
	for {
		select {
		case <-e.dirtyNudge:
			dirty++
			continue
		default:
		}
		break
	}
	for {
		select {
		case <-e.snapshotNudge:
			snapshot++
			continue
		default:
		}
		break
	}
	return dirty, snapshot
}
