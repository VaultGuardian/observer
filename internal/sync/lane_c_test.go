package sync

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/api"
	"github.com/vaultguardian/observer/internal/store"
)

// Payloads are opaque to lane C; these are only realistic enough to read.
var (
	patternDeletePayload = []byte(`{"scope":"docker:nginx","verdict":"alert","value":"abc123"}`)
	trustedIPPayload     = []byte(`{"ip":"198.51.100.9","description":"office"}`)
	correctionPayload    = []byte(`{"type":"confirm","event_id":"evt-1"}`)
)

// =============================================================================
// Happy path
// =============================================================================

// A signed command executes against the local API, gets a terminal receipt,
// gets acked, and pokes lanes A and B exactly once.
func TestLaneCHappyPath(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	cmd := signer.command("cmd-1", "pattern_delete", patternDeletePayload)
	host.serve(cmd)

	e.pollCommands(context.Background())

	// --- the local API saw exactly the signed bytes, and nothing else
	calls := local.callList()
	if len(calls) != 1 {
		t.Fatalf("local calls = %d; want 1 (%v)", len(calls), local.paths())
	}
	call := calls[0]
	if call.Path != "/api/patterns/delete" {
		t.Errorf("local path = %q; want /api/patterns/delete", call.Path)
	}
	if call.Method != http.MethodPost {
		t.Errorf("local method = %q; want POST", call.Method)
	}
	if string(call.Body) != string(patternDeletePayload) {
		t.Errorf("local body = %q; want the exact signed payload %q", call.Body, patternDeletePayload)
	}
	if call.ContentType != "application/json" {
		t.Errorf("local content-type = %q; want application/json", call.ContentType)
	}
	if call.Auth != "Bearer "+testLocalToken {
		t.Errorf("local auth = %q; want the local dashboard bearer token", call.Auth)
	}

	// --- receipt is terminal and records what happened
	r := wantOutcome(t, st, "cmd-1", store.CommandOutcomeExecuted)
	if r.HTTPStatus != http.StatusOK {
		t.Errorf("receipt http_status = %d; want 200", r.HTTPStatus)
	}
	if r.ExecutedAt == 0 {
		t.Error("receipt executed_at is unset on a terminal receipt")
	}
	if r.PayloadSHA != sha256Hex(patternDeletePayload) {
		t.Errorf("receipt payload_sha = %q; want the digest of the payload", r.PayloadSHA)
	}
	if r.Epoch != testEpoch || r.Signature != cmd.SignatureB64 || r.ExpiresAt != cmd.ExpiresAtMS {
		t.Errorf("receipt did not store the signed tuple: %+v", r)
	}

	wantAck(t, host, "cmd-1", ackStatusAcked)

	// --- lanes A and B were nudged once each
	dirty, snapshot := drainNudges(e)
	if dirty != 1 || snapshot != 1 {
		t.Errorf("nudges = (dirty %d, snapshot %d); want exactly one of each", dirty, snapshot)
	}
}

// An empty batch is a no-op: no local traffic, no acks, no nudges.
func TestLaneCEmptyBatchIsQuiet(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	e := newLaneCEngine(t, st, host, local, newCommandSigner(t))

	e.pollCommands(context.Background())

	if calls := local.callList(); len(calls) != 0 {
		t.Errorf("local calls = %d; want 0", len(calls))
	}
	if acks := host.ackList(); len(acks) != 0 {
		t.Errorf("acks = %d; want 0", len(acks))
	}
	if dirty, snapshot := drainNudges(e); dirty != 0 || snapshot != 0 {
		t.Errorf("nudges = (%d, %d); want none", dirty, snapshot)
	}
}

// Lane C must stay completely dark when the pairing is incomplete - no poll,
// no goroutine that outlives the call.
func TestLaneCDisabledWithoutPairing(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)

	cases := map[string]Config{
		"no instance id": {InstanceID: "", Epoch: testEpoch, VerifyKey: make(ed25519.PublicKey, ed25519.PublicKeySize)},
		"no epoch":       {InstanceID: testInstanceID, Epoch: "", VerifyKey: make(ed25519.PublicKey, ed25519.PublicKeySize)},
		"no verify key":  {InstanceID: testInstanceID, Epoch: testEpoch},
		"short key":      {InstanceID: testInstanceID, Epoch: testEpoch, VerifyKey: ed25519.PublicKey("too-short")},
	}
	for name, partial := range cases {
		t.Run(name, func(t *testing.T) {
			e, err := New(context.Background(), st, Config{
				BaseURL:      host.URL,
				Token:        testToken,
				LocalBaseURL: local.URL,
				InstanceID:   partial.InstanceID,
				Epoch:        partial.Epoch,
				VerifyKey:    partial.VerifyKey,
			})
			if err != nil {
				t.Fatalf("new engine: %v", err)
			}
			if e.commandsEnabled() {
				t.Fatal("command channel reports enabled on an incomplete pairing")
			}

			before := host.polls
			e.runLaneC(context.Background()) // must return immediately
			if host.polls != before {
				t.Errorf("polls = %d; want %d - a disabled lane C must not poll", host.polls, before)
			}
		})
	}
}

// =============================================================================
// Integrity
// =============================================================================

// Every way a command can fail verification: integrity_failed, ack failed, no
// local contact - and the legitimate command queued behind it still runs.
func TestLaneCIntegrityFailures(t *testing.T) {
	cases := []struct {
		name    string
		wantMsg string
		build   func(t *testing.T, signer commandSigner) hostedCommand
	}{
		{
			name:    "signature not base64",
			wantMsg: "signature verification failed",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				cmd := s.command("bad-1", "pattern_delete", patternDeletePayload)
				cmd.SignatureB64 = "!!!not base64!!!"
				return cmd
			},
		},
		{
			name:    "signed by the wrong key",
			wantMsg: "signature verification failed",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				other := newCommandSigner(t)
				return other.command("bad-1", "pattern_delete", patternDeletePayload)
			},
		},
		{
			name:    "payload byte tampered after signing",
			wantMsg: "signature verification failed",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				cmd := s.command("bad-1", "pattern_delete", patternDeletePayload)
				tampered := append([]byte(nil), patternDeletePayload...)
				tampered[2] ^= 0x01
				cmd.PayloadB64 = base64.StdEncoding.EncodeToString(tampered)
				return cmd
			},
		},
		{
			name:    "issued_at tampered after signing",
			wantMsg: "signature verification failed",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				cmd := s.command("bad-1", "pattern_delete", patternDeletePayload)
				cmd.IssuedAtMS += 1000
				return cmd
			},
		},
		{
			name:    "expires_at tampered after signing",
			wantMsg: "signature verification failed",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				cmd := s.command("bad-1", "pattern_delete", patternDeletePayload)
				cmd.ExpiresAtMS += 90000
				return cmd
			},
		},
		{
			name:    "type swapped after signing",
			wantMsg: "signature verification failed",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				cmd := s.command("bad-1", "pattern_delete", patternDeletePayload)
				cmd.Type = "trusted_ip_add"
				return cmd
			},
		},
		{
			name:    "payload not decodable",
			wantMsg: "payload is not valid base64",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				cmd := s.command("bad-1", "pattern_delete", patternDeletePayload)
				cmd.PayloadB64 = "@@@@"
				return cmd
			},
		},
		{
			name:    "epoch from a previous pairing",
			wantMsg: "epoch mismatch",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				return s.command("bad-1", "pattern_delete", patternDeletePayload,
					func(c *hostedCommand) { c.Epoch = "epoch-6" })
			},
		},
		{
			name:    "minted for another instance",
			wantMsg: "instance mismatch",
			build: func(t *testing.T, s commandSigner) hostedCommand {
				return s.command("bad-1", "pattern_delete", patternDeletePayload,
					func(c *hostedCommand) { c.InstanceID = "99999999-9999-9999-9999-999999999999" })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			host := newCommandHost(t)
			local := newLocalCommandAPI(t)
			signer := newCommandSigner(t)
			e := newLaneCEngine(t, st, host, local, signer)

			// The good command is served SECOND: a refused command must not
			// be able to wedge the channel behind it.
			good := signer.command("good-1", "trusted_ip_add", trustedIPPayload)
			host.serve(tc.build(t, signer), good)

			e.pollCommands(context.Background())

			wantOutcome(t, st, "bad-1", store.CommandOutcomeIntegrityFailed)
			ack := wantAck(t, host, "bad-1", ackStatusFailed)
			if !strings.Contains(ack.ResultMessage, tc.wantMsg) {
				t.Errorf("ack message = %q; want it to mention %q", ack.ResultMessage, tc.wantMsg)
			}

			wantOutcome(t, st, "good-1", store.CommandOutcomeExecuted)
			wantAck(t, host, "good-1", ackStatusAcked)

			// Only the good command reached the local API.
			if got := local.paths(); len(got) != 1 || got[0] != "/api/trusted-ips" {
				t.Errorf("local calls = %v; want only the good command's /api/trusted-ips", got)
			}
		})
	}
}

// =============================================================================
// Replay
// =============================================================================

// Redelivery of an already-terminal command re-acks without re-executing.
func TestLaneCReplayReAcksWithoutExecuting(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	cmd := signer.command("cmd-replay", "pattern_delete", patternDeletePayload)
	host.serve(cmd)

	e.pollCommands(context.Background())
	e.pollCommands(context.Background()) // the hosted side never saw our ack

	if calls := local.callList(); len(calls) != 1 {
		t.Fatalf("local calls = %d; want 1 - a replay must not execute again", len(calls))
	}
	if n := host.ackCount("cmd-replay"); n != 2 {
		t.Errorf("acks = %d; want 2 (the replay is re-acked so the hosted side can move on)", n)
	}
	for _, ack := range host.ackList() {
		if ack.Status != ackStatusAcked {
			t.Errorf("ack status = %q; want the stored outcome's status %q", ack.Status, ackStatusAcked)
		}
	}
	wantOutcome(t, st, "cmd-replay", store.CommandOutcomeExecuted)
}

// Same id, different payload bytes: that is not a retry, and it is never
// executed.
func TestLaneCReplayWithDifferentPayloadIsIntegrityFailure(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	host.serve(signer.command("cmd-x", "pattern_delete", patternDeletePayload))
	e.pollCommands(context.Background())
	wantOutcome(t, st, "cmd-x", store.CommandOutcomeExecuted)

	// Reissued under the same id with different (legitimately signed) bytes.
	other := []byte(`{"scope":"docker:nginx","verdict":"allow","value":"deadbeef"}`)
	host.serve(signer.command("cmd-x", "pattern_delete", other))
	e.pollCommands(context.Background())

	if calls := local.callList(); len(calls) != 1 {
		t.Fatalf("local calls = %d; want 1 - the changed payload must not execute", len(calls))
	}
	// The recorded outcome stays the original one; the redelivery is acked
	// failed so the hosted side stops serving it.
	r := wantOutcome(t, st, "cmd-x", store.CommandOutcomeExecuted)
	if r.PayloadSHA != sha256Hex(patternDeletePayload) {
		t.Errorf("receipt payload_sha changed to %q; the first terminal record is authoritative", r.PayloadSHA)
	}
	acks := host.ackList()
	last := acks[len(acks)-1]
	if last.Status != ackStatusFailed || !strings.Contains(last.ResultMessage, "payload changed") {
		t.Errorf("last ack = %+v; want failed with a payload-changed message", last)
	}
}

// =============================================================================
// Expiry
// =============================================================================

// A command that arrives past its expiry is never executed.
func TestLaneCExpiredCommandIsNotExecuted(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	now := time.Now().UnixMilli()
	host.serve(signer.command("cmd-old", "pattern_delete", patternDeletePayload,
		func(c *hostedCommand) {
			c.IssuedAtMS = now - 120_000
			c.ExpiresAtMS = now - 60_000
		}))

	e.pollCommands(context.Background())

	if calls := local.callList(); len(calls) != 0 {
		t.Fatalf("local calls = %d; want 0 for an expired command", len(calls))
	}
	wantOutcome(t, st, "cmd-old", store.CommandOutcomeExpired)
	ack := wantAck(t, host, "cmd-old", ackStatusFailed)
	if !strings.Contains(ack.ResultMessage, "expired") {
		t.Errorf("ack message = %q; want it to say expired", ack.ResultMessage)
	}
}

// The 11:59:59 case: executed inside its window, redelivered after the window
// closed. The stored outcome is re-acked - it was executed in time, and
// reporting it as expired would be a lie about what this box did.
func TestLaneCTerminalReceiptRedeliveredAfterExpiry(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	now := time.Now().UnixMilli()
	expiresAt := now - 1_000        // the window closed a second ago
	executedAt := expiresAt - 1_000 // ...and we executed a second before that

	cmd := signer.command("cmd-edge", "pattern_delete", patternDeletePayload,
		func(c *hostedCommand) {
			c.IssuedAtMS = now - 120_000
			c.ExpiresAtMS = expiresAt
		})

	ctx := context.Background()
	if err := st.RecordCommandSeen(ctx, &store.CommandReceipt{
		CommandID:   cmd.ID,
		CommandType: cmd.Type,
		PayloadSHA:  sha256Hex(patternDeletePayload),
		Epoch:       cmd.Epoch,
		Signature:   cmd.SignatureB64,
		ExpiresAt:   cmd.ExpiresAtMS,
		FirstSeenAt: executedAt,
	}); err != nil {
		t.Fatalf("seed receipt: %v", err)
	}
	if err := st.FinalizeCommandReceipt(ctx, cmd.ID, executedAt, http.StatusOK,
		`{"status":"deleted"}`, store.CommandOutcomeExecuted); err != nil {
		t.Fatalf("seed terminal receipt: %v", err)
	}

	host.serve(cmd)
	e.pollCommands(ctx)

	if calls := local.callList(); len(calls) != 0 {
		t.Fatalf("local calls = %d; want 0 - the command was already executed", len(calls))
	}
	ack := wantAck(t, host, "cmd-edge", ackStatusAcked)
	if !strings.Contains(ack.ResultMessage, "deleted") {
		t.Errorf("ack message = %q; want the stored result", ack.ResultMessage)
	}
	wantOutcome(t, st, "cmd-edge", store.CommandOutcomeExecuted)
}

// =============================================================================
// Outcome mapping
// =============================================================================

// Every pinned "already in the desired state" response converges; any other
// 4xx is a rejection.
func TestLaneCFourXXMapping(t *testing.T) {
	cases := []struct {
		name        string
		cmdType     string
		status      int
		body        string
		wantOutcome string
		wantAck     string
	}{
		{"pattern already gone", "pattern_delete", http.StatusNotFound,
			fmt.Sprintf(`{"error":%q}`, api.ConvergedPatternNotFound),
			store.CommandOutcomeConverged, ackStatusAcked},
		{"ip already trusted", "trusted_ip_add", http.StatusBadRequest,
			fmt.Sprintf(`{"error":"IP 198.51.100.9 %s"}`, api.ConvergedTrustedIPExists),
			store.CommandOutcomeConverged, ackStatusAcked},
		{"trusted ip already gone", "trusted_ip_delete", http.StatusNotFound,
			fmt.Sprintf(`{"error":%q}`, api.ConvergedTrustedIPNotFound),
			store.CommandOutcomeConverged, ackStatusAcked},
		{"genuinely invalid", "trusted_ip_add", http.StatusBadRequest,
			`{"error":"Invalid IP address format"}`,
			store.CommandOutcomeRejected, ackStatusFailed},
		{"unauthorized", "pattern_delete", http.StatusUnauthorized,
			`{"error":"unauthorized"}`,
			store.CommandOutcomeRejected, ackStatusFailed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			host := newCommandHost(t)
			local := newLocalCommandAPI(t)
			signer := newCommandSigner(t)
			e := newLaneCEngine(t, st, host, local, signer)

			local.setResponder(func(localCall, int) (int, string) { return tc.status, tc.body })
			host.serve(signer.command("cmd-4xx", tc.cmdType, trustedIPPayload))

			e.pollCommands(context.Background())

			r := wantOutcome(t, st, "cmd-4xx", tc.wantOutcome)
			if r.HTTPStatus != tc.status {
				t.Errorf("receipt http_status = %d; want %d", r.HTTPStatus, tc.status)
			}
			ack := wantAck(t, host, "cmd-4xx", tc.wantAck)
			if !strings.Contains(ack.ResultMessage, "error") {
				t.Errorf("ack message = %q; want the local API's body", ack.ResultMessage)
			}

			// Converged commands changed nothing locally, but the dashboard
			// still needs to see the resulting state, so lanes A/B are nudged
			// for those too - and never for a rejection.
			dirty, snapshot := drainNudges(e)
			wantNudge := tc.wantOutcome == store.CommandOutcomeConverged
			if (dirty > 0) != wantNudge || (snapshot > 0) != wantNudge {
				t.Errorf("nudges = (%d, %d); want fired=%v", dirty, snapshot, wantNudge)
			}
		})
	}
}

// An unknown command type is refused without ANY local contact: a newer
// control plane must not be able to steer this at an arbitrary local path.
func TestLaneCUnknownTypeNeverTouchesLocalAPI(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	host.serve(signer.command("cmd-unknown", "reboot_the_host", []byte(`{}`)))
	e.pollCommands(context.Background())

	if calls := local.callList(); len(calls) != 0 {
		t.Fatalf("local calls = %v; want none for an unknown type", local.paths())
	}
	wantOutcome(t, st, "cmd-unknown", store.CommandOutcomeRejected)
	ack := wantAck(t, host, "cmd-unknown", ackStatusFailed)
	if !strings.Contains(ack.ResultMessage, "unknown command type") {
		t.Errorf("ack message = %q; want it to name the unknown type", ack.ResultMessage)
	}
}

// A payload past the cap is refused locally rather than sent for the API to
// truncate and misparse.
func TestLaneCOversizePayloadRejected(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	huge := []byte(`{"scope":"docker:nginx","verdict":"alert","value":"` +
		strings.Repeat("A", maxCommandPayload+1) + `"}`)
	host.serve(signer.command("cmd-huge", "pattern_delete", huge))

	e.pollCommands(context.Background())

	if calls := local.callList(); len(calls) != 0 {
		t.Fatalf("local calls = %d; want 0 for an oversize payload", len(calls))
	}
	wantOutcome(t, st, "cmd-huge", store.CommandOutcomeRejected)
	ack := wantAck(t, host, "cmd-huge", ackStatusFailed)
	if !strings.Contains(ack.ResultMessage, "limit is") {
		t.Errorf("ack message = %q; want it to name the payload limit", ack.ResultMessage)
	}
}

// =============================================================================
// Transient failure
// =============================================================================

// A local 5xx mid-batch stops the batch where it stands: nothing after it is
// acked, and the next tick resumes from the unacked command in the same order.
func TestLaneCLocal5xxStopsBatchAndResumes(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	first := signer.command("cmd-a", "pattern_delete", patternDeletePayload)
	second := signer.command("cmd-b", "trusted_ip_add", trustedIPPayload)
	third := signer.command("cmd-c", "correction", correctionPayload)
	host.serve(first, second, third)

	// The trusted-IP add fails with a 500 while the local store is unhappy.
	local.setResponder(func(call localCall, _ int) (int, string) {
		if call.Path == "/api/trusted-ips" {
			return http.StatusInternalServerError, `{"error":"database is locked"}`
		}
		return http.StatusOK, `{"status":"ok"}`
	})

	e.pollCommands(context.Background())

	wantOutcome(t, st, "cmd-a", store.CommandOutcomeExecuted)
	wantAck(t, host, "cmd-a", ackStatusAcked)

	// cmd-b was attempted but decided nothing; cmd-c was never reached.
	if r := receipt(t, st, "cmd-b"); r == nil || r.Terminal() {
		t.Errorf("receipt cmd-b = %+v; want a non-terminal receipt after a 5xx", r)
	}
	if r := receipt(t, st, "cmd-c"); r != nil {
		t.Errorf("receipt cmd-c = %+v; want none - the batch stopped before it", r)
	}
	if n := host.ackCount("cmd-b") + host.ackCount("cmd-c"); n != 0 {
		t.Errorf("acks after the stop = %d; want 0", n)
	}
	if got := local.paths(); len(got) != 2 {
		t.Errorf("local calls = %v; want the batch to stop at the failure", got)
	}

	// Next tick, with the local API healthy: the remainder runs in order.
	local.setResponder(nil)
	e.pollCommands(context.Background())

	wantOutcome(t, st, "cmd-b", store.CommandOutcomeExecuted)
	wantOutcome(t, st, "cmd-c", store.CommandOutcomeExecuted)
	wantAck(t, host, "cmd-b", ackStatusAcked)
	wantAck(t, host, "cmd-c", ackStatusAcked)

	// cmd-a is not re-executed on the second pass: its receipt is terminal.
	wantPaths := []string{"/api/patterns/delete", "/api/trusted-ips", "/api/trusted-ips", "/api/corrections"}
	if got := local.paths(); strings.Join(got, ",") != strings.Join(wantPaths, ",") {
		t.Errorf("local call order = %v; want %v", got, wantPaths)
	}
	if n := host.ackCount("cmd-a"); n != 2 {
		t.Errorf("cmd-a acks = %d; want 2 (a terminal receipt re-acks, it does not re-execute)", n)
	}
}

// An ack the hosted side rejects also stops the batch. The receipt is already
// terminal, so the retry re-acks instead of re-executing.
func TestLaneCAckFailureStopsBatchAndRetryDoesNotReexecute(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	host.serve(
		signer.command("cmd-1", "pattern_delete", patternDeletePayload),
		signer.command("cmd-2", "trusted_ip_add", trustedIPPayload),
	)
	host.failAcks(func(ack commandAck) int {
		if ack.ID == "cmd-1" {
			return http.StatusInternalServerError
		}
		return 0
	})

	e.pollCommands(context.Background())

	// cmd-1 executed and is terminal locally, but the hosted side never
	// recorded it; cmd-2 was not attempted at all.
	wantOutcome(t, st, "cmd-1", store.CommandOutcomeExecuted)
	if r := receipt(t, st, "cmd-2"); r != nil {
		t.Errorf("receipt cmd-2 = %+v; want none - the batch stopped on the failed ack", r)
	}
	if len(host.ackList()) != 0 {
		t.Errorf("acks = %+v; want none recorded", host.ackList())
	}
	if got := local.paths(); len(got) != 1 {
		t.Errorf("local calls = %v; want only cmd-1", got)
	}

	// Acks work again: cmd-1 is re-acked from its receipt, cmd-2 runs.
	host.failAcks(nil)
	e.pollCommands(context.Background())

	wantAck(t, host, "cmd-1", ackStatusAcked)
	wantAck(t, host, "cmd-2", ackStatusAcked)
	if got := local.paths(); strings.Join(got, ",") != "/api/patterns/delete,/api/trusted-ips" {
		t.Errorf("local calls = %v; want cmd-1 executed exactly once", got)
	}
}

// A poll response over the 1MB cap is refused BEFORE decoding, as a transient
// failure: nothing is executed, nothing is acked.
func TestLaneCOversizePollResponseIsTransient(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	// A syntactically valid batch, padded past the limit.
	cmd := signer.command("cmd-big", "pattern_delete", patternDeletePayload)
	host.serveRaw(`{"padding":"` + strings.Repeat("x", commandPollLimit) + `","commands":[{"id":"` + cmd.ID + `"}]}`)

	e.pollCommands(context.Background())

	if calls := local.callList(); len(calls) != 0 {
		t.Errorf("local calls = %d; want 0 - an oversize response is never decoded", len(calls))
	}
	if acks := host.ackList(); len(acks) != 0 {
		t.Errorf("acks = %d; want 0", len(acks))
	}
	if r := receipt(t, st, "cmd-big"); r != nil {
		t.Errorf("receipt = %+v; want none", r)
	}
	if !e.laneCDown {
		t.Error("lane C should have logged a down transition after an oversize response")
	}

	// A normal response recovers.
	host.serve(cmd)
	e.pollCommands(context.Background())
	if e.laneCDown {
		t.Error("lane C should have recovered after a good poll")
	}
	wantOutcome(t, st, "cmd-big", store.CommandOutcomeExecuted)
}

// An undecodable poll response, and a poll that errors, are both transient.
func TestLaneCBadPollResponsesAreTransient(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	e := newLaneCEngine(t, st, host, local, newCommandSigner(t))

	host.serveRaw(`{"commands": [ this is not json`)
	e.pollCommands(context.Background())
	if !e.laneCDown {
		t.Error("an undecodable poll response must be reported as a failure")
	}
	if calls := local.callList(); len(calls) != 0 {
		t.Errorf("local calls = %d; want 0", len(calls))
	}

	host.mu.Lock()
	host.pollStatus = http.StatusBadGateway
	host.rawBatch = `{"commands":[]}`
	host.mu.Unlock()
	e.pollCommands(context.Background())
	if !e.laneCDown {
		t.Error("a non-2xx poll must be reported as a failure")
	}
}

// =============================================================================
// Ordering
// =============================================================================

// The served order is the execution order, end to end.
func TestLaneCPreservesServedOrder(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	types := []string{"correction", "pattern_delete", "trusted_ip_add", "trusted_ip_delete", "decision_review"}
	var batch []hostedCommand
	var want []string
	for i, cmdType := range types {
		batch = append(batch, signer.command(fmt.Sprintf("cmd-%02d", i), cmdType,
			[]byte(fmt.Sprintf(`{"seq":%d}`, i))))
		want = append(want, commandRoutes[cmdType])
	}
	host.serve(batch...)

	e.pollCommands(context.Background())

	if got := local.paths(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("local call order = %v; want %v", got, want)
	}
	// The bodies must arrive in the same order, byte-for-byte.
	for i, call := range local.callList() {
		if want := fmt.Sprintf(`{"seq":%d}`, i); string(call.Body) != want {
			t.Errorf("call %d body = %q; want %q", i, call.Body, want)
		}
	}
	acks := host.ackList()
	if len(acks) != len(types) {
		t.Fatalf("acks = %d; want %d", len(acks), len(types))
	}
	for i, ack := range acks {
		if want := fmt.Sprintf("cmd-%02d", i); ack.ID != want {
			t.Errorf("ack %d = %q; want %q - acks follow the served order", i, ack.ID, want)
		}
	}
}

// =============================================================================
// Signature message
// =============================================================================

// The signed message is a protocol contract with the hosted side: pin it.
func TestCommandSigMessageShape(t *testing.T) {
	got := string(commandSigMessage("id-1", "inst-1", "epoch-1", "pattern_delete",
		"abc123", 1757440000000, 1757526400000))
	want := "VG-COMMAND/v1\nid-1\ninst-1\nepoch-1\npattern_delete\nabc123\n1757440000000\n1757526400000"
	if got != want {
		t.Errorf("signed message =\n%q\nwant\n%q", got, want)
	}
}

// The convergence matcher must track the strings the API actually emits.
func TestConvergedBodyMatchesPinnedStrings(t *testing.T) {
	for _, marker := range api.ConvergedResponses() {
		if !convergedBody([]byte(fmt.Sprintf(`{"error":"%s"}`, marker))) {
			t.Errorf("convergence marker %q is not recognized by lane C", marker)
		}
	}
	if convergedBody([]byte(`{"error":"Invalid verdict. Must be one of: allow, malicious, alert, suppress"}`)) {
		t.Error("a genuine validation error must not be treated as convergence")
	}
}

// A sustained outage must cost two log lines - one down, one up - not two per
// tick. Lane C reports health per tick, not per step, precisely so a failing
// poll followed by a failing batch cannot flap the state.
func TestLaneCLogsTransitionsNotEveryTick(t *testing.T) {
	st := newTestStore(t)
	host := newCommandHost(t)
	local := newLocalCommandAPI(t)
	signer := newCommandSigner(t)
	e := newLaneCEngine(t, st, host, local, signer)

	var logs strings.Builder
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// The local API is down for three ticks with a fresh command each time.
	local.setResponder(func(localCall, int) (int, string) {
		return http.StatusInternalServerError, `{"error":"database is locked"}`
	})
	for i := 0; i < 3; i++ {
		host.serve(signer.command(fmt.Sprintf("cmd-%d", i), "pattern_delete", patternDeletePayload))
		e.pollCommands(context.Background())
	}
	if n := strings.Count(logs.String(), "command channel failing"); n != 1 {
		t.Errorf("down transitions logged = %d; want exactly 1 across three failing ticks:\n%s",
			n, logs.String())
	}

	// Recovery, then two more healthy ticks.
	local.setResponder(nil)
	for i := 0; i < 2; i++ {
		host.serve(signer.command(fmt.Sprintf("cmd-ok-%d", i), "pattern_delete", patternDeletePayload))
		e.pollCommands(context.Background())
	}
	if n := strings.Count(logs.String(), "command channel recovered"); n != 1 {
		t.Errorf("recovery transitions logged = %d; want exactly 1:\n%s", n, logs.String())
	}
}
