package sync

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vaultguardian/observer/internal/api"
	"github.com/vaultguardian/observer/internal/store"
)

// =============================================================================
// LANE C - hosted command channel (inbound)
// =============================================================================
//
// Lane C polls signed commands DOWN from the hosted dashboard and executes
// each one against Observer's OWN local API: the same handlers, the same
// validation, the same store methods a dashboard click used to hit. Nothing
// about a command's content ever reaches this package's decision making -
// the type selects a hard-coded local path, and the payload is opaque bytes
// forwarded verbatim.
//
// THREAT MODEL
//
// The hosted control plane's DATABASE is treated as attacker-writable. That
// single assumption shapes everything here:
//
//   - SIGNATURES. Every command carries an Ed25519 signature over its own
//     identity, target, epoch, type, payload digest and validity window. The
//     private key lives in the hosted platform's environment, never in a
//     table, so an attacker with database write access cannot mint a command
//     and cannot alter one (any edit invalidates the signature).
//
//   - PAYLOAD IDENTITY. The signature covers sha256 of the EXACT payload
//     bytes, and those same bytes are what gets POSTed to the local API. No
//     JSON is re-marshaled anywhere in this path: bytes signed == bytes
//     executed. A re-encode would change field order or number formatting and
//     silently break that equality.
//
//   - EPOCH. The signed tuple names the pairing session. On re-pair the epoch
//     rotates, so commands minted for the previous session are rejected rather
//     than executed late. Encountering one is expected (a poll that crossed a
//     re-pair boundary), which is why it is a loud log and not a panic.
//
//   - RECEIPTS. A local ledger (store.CommandReceipt) records every command
//     this box has seen. It absorbs redelivery: a terminal receipt turns a
//     second delivery into a re-ack with no second execution. See
//     internal/store/command_receipts.go for what that does and does not
//     cover.
//
//   - NO AUTHORITY IS GRANTED BY BEING ASKED. Commands are still subject to
//     every local check: the API's bearer auth, its request-size limits, its
//     strict JSON decoding, and each handler's own validation. Lane C cannot
//     do anything an operator at the local dashboard could not do.
//
// ORDERING AND FAILURE
//
// Commands are executed in the order the server served them, and the batch
// STOPS at the first transient failure (local 5xx, local API down, ack
// rejected). Stopping preserves ordering: skipping ahead could apply a later
// correction before an earlier one it depends on. Terminal failures
// (bad signature, wrong epoch, expired, rejected by a handler) do NOT stop
// the batch - a forged or stale command must not be able to wedge the channel
// and block legitimate work queued behind it.

const (
	pathIngestCommands    = "/api/ingest/commands"
	pathIngestCommandsAck = "/api/ingest/commands/ack"

	// commandPollLimit bounds the poll response BEFORE it is decoded. The
	// contract caps a batch at 50 small commands; anything approaching a
	// megabyte is a misconfigured URL or a hostile response, and is treated
	// as a transient failure rather than parsed.
	commandPollLimit = 1 << 20

	// maxCommandPayload bounds one command's decoded payload. The local API
	// rejects bodies over 64KB anyway (api.maxRequestBody); refusing here
	// makes the outcome a clean "rejected" with a readable reason instead of
	// a 400 from a truncated body read.
	maxCommandPayload = 64 << 10

	// maxResultMessage bounds the ack's result_message, per the contract.
	maxResultMessage = 1024

	// commandSigContext is the domain-separation prefix of the signed
	// message. Version it, never reuse it: a signature minted for one context
	// must never verify in another.
	commandSigContext = "VG-COMMAND/v1"
)

// Ack statuses. The hosted side treats both as terminal; "failed" carries the
// reason in result_message.
const (
	ackStatusAcked  = "acked"
	ackStatusFailed = "failed"
)

// commandRoutes is the ALLOWLIST: the complete set of command types this
// Observer will execute, and the only local paths lane C can POST to.
//
// A hard-coded map, not a computed path, is the point. The payload cannot
// influence the URL, the method, or the headers, so no command - forged,
// stale, or merely buggy - can aim this at an arbitrary local endpoint. An
// unrecognized type is rejected without any local contact at all, which also
// makes a newer control plane safe to run against an older Observer.
var commandRoutes = map[string]string{
	"correction":        "/api/corrections",
	"decision_review":   "/api/decisions/review",
	"pattern_delete":    "/api/patterns/delete",
	"trusted_ip_add":    "/api/trusted-ips",
	"trusted_ip_delete": "/api/trusted-ips/delete",
}

// hostedCommand is one entry of the poll response.
//
// InstanceID is NOT part of the frozen response schema; it is accepted when
// present so a command that was minted for a different box can be reported as
// an instance mismatch instead of an indistinguishable signature failure.
// When absent, the signed tuple is built with this instance's own id, so a
// command aimed elsewhere simply fails to verify - which is the same refusal,
// less legibly.
type hostedCommand struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	PayloadB64   string `json:"payload_b64"`
	Epoch        string `json:"epoch"`
	IssuedAtMS   int64  `json:"issued_at_ms"`
	ExpiresAtMS  int64  `json:"expires_at_ms"`
	SignatureB64 string `json:"signature_b64"`
	InstanceID   string `json:"instance_id,omitempty"`
}

// commandBatch is the poll response envelope.
type commandBatch struct {
	Commands []hostedCommand `json:"commands"`
}

// commandAck is the ack request body.
type commandAck struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	ResultMessage string `json:"result_message"`
}

// transient builds the one error class lane C reports upward: a failure that
// decided nothing, so the batch stops here and the whole remainder - this
// command included - is retried in the same order next tick. Every terminal
// outcome is recorded in the receipt and acked instead of returned.
func transient(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// runLaneC is the lane C goroutine.
//
// It returns immediately when the command channel is not configured, so an
// unpaired (or partially paired) Observer pays nothing for this lane beyond
// one goroutine start. Shutdown is cancellation-only, like lanes A and B.
func (e *Engine) runLaneC(ctx context.Context) {
	if !e.commandsEnabled() {
		return
	}

	ticker := time.NewTicker(e.cfg.CommandInterval)
	defer ticker.Stop()

	// Poll immediately: a freshly paired instance should pick up whatever the
	// operator queued during pairing without waiting out an interval.
	e.pollCommands(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.pollCommands(ctx)
		}
	}
}

// pollCommands runs one lane C tick: fetch the batch, then execute it in the
// order served, stopping at the first transient failure.
//
// Health is reported per TICK, not per step: a tick counts as healthy only if
// the poll and every command in it got a decision. Reporting the fetch and the
// batch separately would log a recovery and a failure every tick for as long as
// the local API was down.
func (e *Engine) pollCommands(ctx context.Context) {
	batch, err := e.fetchCommands(ctx)
	if err == nil {
		var applied int
		applied, err = e.runBatch(ctx, batch)
		if applied > 0 {
			// At least one command changed (or confirmed) local state. Push it
			// outbound now rather than on the next scheduled pass.
			e.nudgeOutbound()
		}
	}

	switch {
	case ctx.Err() != nil:
		// Shutting down: not a channel failure, and not worth a log line.
	case err != nil:
		e.noteLaneC(false, err.Error())
	default:
		e.noteLaneC(true, "")
	}
}

// runBatch executes commands in the order served and stops at the first
// transient failure, so the remainder keeps its position for the next tick.
// Returns how many commands ended up executed or converged.
func (e *Engine) runBatch(ctx context.Context, batch []hostedCommand) (int, error) {
	applied := 0
	for _, cmd := range batch {
		if ctx.Err() != nil {
			return applied, ctx.Err()
		}
		outcome, err := e.executeCommand(ctx, cmd)
		if err != nil {
			// The receipt for this one is still non-terminal and its handler
			// is convergent, so retrying it next tick is safe.
			return applied, err
		}
		if outcome == store.CommandOutcomeExecuted || outcome == store.CommandOutcomeConverged {
			applied++
		}
	}
	return applied, nil
}

// nudgeOutbound pokes lanes A and B after commands actually changed local
// state. Non-blocking by construction: the channels are size-1 and a queued
// nudge already covers this pass.
func (e *Engine) nudgeOutbound() {
	select {
	case e.dirtyNudge <- struct{}{}:
	default:
	}
	select {
	case e.snapshotNudge <- struct{}{}:
	default:
	}
}

// noteLaneC logs command-channel health transitions once, not per tick.
func (e *Engine) noteLaneC(ok bool, detail string) {
	switch {
	case !ok && !e.laneCDown:
		log.Printf("[sync] command channel failing: %s (retrying next tick)", detail)
		e.laneCDown = true
	case ok && e.laneCDown:
		log.Printf("[sync] command channel recovered")
		e.laneCDown = false
	}
}

// -----------------------------------------------------------------------------
// Poll
// -----------------------------------------------------------------------------

// fetchCommands GETs the pending batch. Any failure - transport, status,
// oversize body, undecodable JSON - is transient: log the transition and try
// again next tick.
func (e *Engine) fetchCommands(ctx context.Context) ([]hostedCommand, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.BaseURL+pathIngestCommands, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.cfg.Token)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", pathIngestCommands, err)
	}
	defer resp.Body.Close()

	// Bounded read BEFORE decoding, and one byte past the limit so an
	// exactly-at-limit body is still distinguishable from an over-limit one.
	body, err := io.ReadAll(io.LimitReader(resp.Body, commandPollLimit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: reading response: %w", pathIngestCommands, err)
	}
	if len(body) > commandPollLimit {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes - refusing to decode",
			pathIngestCommands, commandPollLimit)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", pathIngestCommands, resp.StatusCode, snippet(body))
	}

	var batch commandBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		return nil, fmt.Errorf("GET %s: undecodable response: %w", pathIngestCommands, err)
	}
	return batch.Commands, nil
}

// -----------------------------------------------------------------------------
// Per-command pipeline
// -----------------------------------------------------------------------------

// executeCommand runs one command through verification, the receipt ledger,
// execution and acknowledgement.
//
// It returns the terminal outcome recorded for the command, or a transient
// error meaning "nothing was decided; stop the batch and retry next tick".
// Every non-transient path ends with both a finalized receipt and an ack.
func (e *Engine) executeCommand(ctx context.Context, cmd hostedCommand) (string, error) {
	if cmd.ID == "" {
		// Unaddressable: there is no id to ack and no receipt to write. Skip
		// it (loudly) rather than stopping the batch behind it.
		log.Printf("[sync:command] dropping a command with no id (type=%q)", cmd.Type)
		return "", nil
	}

	// --- (a) signature over the exact payload bytes -------------------------
	payload, err := base64.StdEncoding.DecodeString(cmd.PayloadB64)
	if err != nil {
		// Undecodable payload: the signed digest cannot even be computed, so
		// this is an integrity failure, not a bad request.
		return e.rejectCommand(ctx, cmd, "", store.CommandOutcomeIntegrityFailed,
			"payload is not valid base64")
	}
	payloadSHA := sha256Hex(payload)

	if !e.verifyCommand(cmd, payloadSHA) {
		return e.rejectCommand(ctx, cmd, payloadSHA, store.CommandOutcomeIntegrityFailed,
			"signature verification failed")
	}

	// --- (b) instance and epoch --------------------------------------------
	//
	// Both are inside the signed tuple, so a mismatch here is never an
	// attacker's doing - it is a legitimately signed command that belongs to
	// another box or another pairing session. Loud, terminal, and it must not
	// stop the batch.
	if cmd.InstanceID != "" && cmd.InstanceID != e.cfg.InstanceID {
		return e.rejectCommand(ctx, cmd, payloadSHA, store.CommandOutcomeIntegrityFailed,
			"instance mismatch")
	}
	if cmd.Epoch != e.cfg.Epoch {
		return e.rejectCommand(ctx, cmd, payloadSHA, store.CommandOutcomeIntegrityFailed,
			"epoch mismatch")
	}

	// --- (c) receipt lookup -------------------------------------------------
	existing, err := e.store.GetCommandReceipt(ctx, cmd.ID)
	if err != nil {
		// A local database failure decides nothing.
		return "", transient("command %s: receipt lookup: %v", cmd.ID, err)
	}
	if existing.Terminal() {
		switch {
		case existing.PayloadSHA != payloadSHA:
			// Same id, different bytes. Either the control plane reused an id
			// or somebody edited a row; either way this is not the command we
			// already answered, and it is not going to be executed.
			return e.rejectCommand(ctx, cmd, payloadSHA, store.CommandOutcomeIntegrityFailed,
				"payload changed for known command id")

		case existing.ExecutedAt <= cmd.ExpiresAtMS:
			// Already decided. Re-ack the stored outcome verbatim - this is
			// the whole point of the ledger, and it is what makes a lost ack
			// harmless. Expiry is deliberately NOT re-checked: a command
			// executed at 11:59:59 and redelivered at 12:00:01 was executed
			// in time, and must be reported as executed, not as expired.
			log.Printf("[sync:command] %s (%s) already %s - re-acking without re-executing",
				cmd.ID, cmd.Type, existing.Outcome)
			if err := e.ackCommand(ctx, cmd.ID, ackStatusFor(existing.Outcome), existing.Result); err != nil {
				return "", err
			}
			return existing.Outcome, nil
		}
		// Terminal, same payload, but finalized after the validity window
		// closed. Falls through to the expiry check below, which reports it
		// as expired without touching the recorded outcome.
	}

	// --- (d) expiry ---------------------------------------------------------
	now := time.Now().UnixMilli()
	if now > cmd.ExpiresAtMS {
		return e.rejectCommand(ctx, cmd, payloadSHA, store.CommandOutcomeExpired, "expired")
	}

	// --- (e) record, then execute ------------------------------------------
	if err := e.recordSeen(ctx, cmd, payloadSHA, now); err != nil {
		return "", err
	}

	path, known := commandRoutes[cmd.Type]
	if !known {
		// Rejected without any local contact: an unknown type has no safe
		// destination, and guessing one is how a control-plane version skew
		// turns into an arbitrary local POST.
		return e.finishCommand(ctx, cmd, 0, store.CommandOutcomeRejected,
			fmt.Sprintf("unknown command type %q", cmd.Type))
	}
	if len(payload) > maxCommandPayload {
		return e.finishCommand(ctx, cmd, 0, store.CommandOutcomeRejected,
			fmt.Sprintf("payload is %d bytes, limit is %d", len(payload), maxCommandPayload))
	}

	status, body, err := e.postLocal(ctx, path, payload)
	if err != nil {
		return "", transient("command %s: POST %s: %v", cmd.ID, path, err)
	}

	// --- (f) outcome mapping ------------------------------------------------
	outcome := ""
	switch {
	case status >= 200 && status <= 299:
		outcome = store.CommandOutcomeExecuted
	case status >= 400 && status <= 499:
		if convergedBody(body) {
			outcome = store.CommandOutcomeConverged
		} else {
			outcome = store.CommandOutcomeRejected
		}
	default:
		// 5xx (and anything else unexpected) is the local API saying the work
		// did not durably land. Nothing is finalized and nothing is acked, so
		// the next tick retries this exact command in this exact position.
		return "", transient("command %s: POST %s: HTTP %d: %s", cmd.ID, path, status, snippet(body))
	}

	// --- (g) finalize, then ack --------------------------------------------
	return e.finishCommand(ctx, cmd, status, outcome, snippet(body))
}

// verifyCommand checks the Ed25519 signature over the canonical tuple.
//
// The tuple is rebuilt locally from this instance's own configuration plus the
// command's transported fields, so every element a decision depends on is
// covered by the signature.
func (e *Engine) verifyCommand(cmd hostedCommand, payloadSHA string) bool {
	sig, err := base64.StdEncoding.DecodeString(cmd.SignatureB64)
	if err != nil {
		return false
	}
	// An absent instance_id means "minted for whoever holds this token", per
	// the frozen response schema; verify against our own id.
	instanceID := cmd.InstanceID
	if instanceID == "" {
		instanceID = e.cfg.InstanceID
	}
	msg := commandSigMessage(cmd.ID, instanceID, cmd.Epoch, cmd.Type,
		payloadSHA, cmd.IssuedAtMS, cmd.ExpiresAtMS)
	return ed25519.Verify(e.cfg.VerifyKey, msg, sig)
}

// commandSigMessage builds the signed message. Field order and separators are
// part of the protocol contract; numbers are base-10 ASCII with no padding.
//
// Both sides of the channel construct this string, so it is deliberately dumb:
// no JSON, no map iteration, nothing that could render differently in two
// languages.
func commandSigMessage(id, instanceID, epoch, cmdType, payloadSHA string, issuedAtMS, expiresAtMS int64) []byte {
	var b strings.Builder
	b.WriteString(commandSigContext)
	for _, field := range []string{
		id,
		instanceID,
		epoch,
		cmdType,
		payloadSHA,
		strconv.FormatInt(issuedAtMS, 10),
		strconv.FormatInt(expiresAtMS, 10),
	} {
		b.WriteByte('\n')
		b.WriteString(field)
	}
	return []byte(b.String())
}

// convergedBody reports whether a 4xx body says the requested state is
// already true. The strings are pinned in internal/api next to the handlers
// that emit them, so this match cannot drift out from under a copy edit.
func convergedBody(body []byte) bool {
	text := string(body)
	for _, marker := range api.ConvergedResponses() {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// ackStatusFor maps a recorded outcome to the ack status the hosted side
// expects. Only executed and converged are successes.
func ackStatusFor(outcome string) string {
	switch outcome {
	case store.CommandOutcomeExecuted, store.CommandOutcomeConverged:
		return ackStatusAcked
	default:
		return ackStatusFailed
	}
}

// -----------------------------------------------------------------------------
// Receipts and acknowledgement
// -----------------------------------------------------------------------------

// recordSeen writes the signed tuple to the ledger before anything is done
// with the command. Idempotent - a redelivery keeps the original first_seen.
func (e *Engine) recordSeen(ctx context.Context, cmd hostedCommand, payloadSHA string, nowMS int64) error {
	err := e.store.RecordCommandSeen(ctx, &store.CommandReceipt{
		CommandID:   cmd.ID,
		CommandType: cmd.Type,
		PayloadSHA:  payloadSHA,
		Epoch:       cmd.Epoch,
		Signature:   cmd.SignatureB64,
		ExpiresAt:   cmd.ExpiresAtMS,
		FirstSeenAt: nowMS,
	})
	if err != nil {
		return transient("command %s: recording receipt: %v", cmd.ID, err)
	}
	return nil
}

// rejectCommand handles a terminal refusal reached before execution: record
// the command was seen, finalize the receipt with the refusal, ack failed.
//
// It logs loudly. An integrity failure means either a control-plane bug or
// somebody writing to the hosted database, and neither should be discoverable
// only by reading a table.
func (e *Engine) rejectCommand(
	ctx context.Context,
	cmd hostedCommand,
	payloadSHA string,
	outcome string,
	message string,
) (string, error) {
	if outcome == store.CommandOutcomeIntegrityFailed {
		log.Printf("[sync:command] REFUSED %s (type=%s epoch=%s): %s - this command was NOT executed",
			cmd.ID, cmd.Type, cmd.Epoch, message)
	} else {
		log.Printf("[sync:command] %s (type=%s): %s - not executed", cmd.ID, cmd.Type, message)
	}

	if err := e.recordSeen(ctx, cmd, payloadSHA, time.Now().UnixMilli()); err != nil {
		return "", err
	}
	return e.finishCommand(ctx, cmd, 0, outcome, message)
}

// finishCommand finalizes the receipt and then acks.
//
// Receipt first, deliberately: if the ack fails, the stored terminal outcome
// makes the retry a re-ack instead of a second execution. The reverse order
// would leave the hosted side thinking a command was applied while this box
// has no record that it was.
func (e *Engine) finishCommand(
	ctx context.Context,
	cmd hostedCommand,
	httpStatus int,
	outcome string,
	result string,
) (string, error) {
	if len(result) > maxResultMessage {
		result = result[:maxResultMessage]
	}

	err := e.store.FinalizeCommandReceipt(ctx, cmd.ID, time.Now().UnixMilli(), httpStatus, result, outcome)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrCommandReceiptTerminal):
		// The receipt already holds a terminal outcome - the narrow case of a
		// command redelivered after its validity window closed (§(c) falls
		// through to the expiry check). The first outcome stays authoritative;
		// we still owe the hosted side an ack so it stops serving this.
		log.Printf("[sync:command] %s: keeping the recorded outcome, acking %s: %v",
			cmd.ID, outcome, err)
	default:
		return "", transient("command %s: finalizing receipt: %v", cmd.ID, err)
	}

	if err := e.ackCommand(ctx, cmd.ID, ackStatusFor(outcome), result); err != nil {
		return "", err
	}
	return outcome, nil
}

// ackCommand reports a terminal outcome to the hosted side.
//
// Anything other than a 2xx - including a network error - is transient: the
// caller stops the batch and retries next tick, where the receipt turns this
// command into a re-ack rather than a second execution.
func (e *Engine) ackCommand(ctx context.Context, id, status, message string) error {
	if len(message) > maxResultMessage {
		message = message[:maxResultMessage]
	}
	body, err := json.Marshal(commandAck{ID: id, Status: status, ResultMessage: message})
	if err != nil {
		return transient("command %s: encoding ack: %v", id, err)
	}

	code, respBody, err := e.postIngest(ctx, pathIngestCommandsAck, body)
	if err != nil {
		return transient("command %s: ack: %v", id, err)
	}
	if code < 200 || code > 299 {
		return transient("command %s: ack: HTTP %d: %s", id, code, snippet(respBody))
	}
	return nil
}

// -----------------------------------------------------------------------------
// Local execution
// -----------------------------------------------------------------------------

// postLocal POSTs the EXACT payload bytes to one allowlisted local API path.
//
// The bytes are forwarded untouched - the digest the hosted side signed is a
// digest of these bytes, so re-encoding them would break the one equality this
// design rests on. The path comes from commandRoutes, the method is always
// POST, and the only headers are a constant content type and the local bearer
// token: nothing in the payload can influence where or how this is sent.
func (e *Engine) postLocal(ctx context.Context, path string, payload []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.LocalBaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.localToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.localToken)
	}

	resp, err := e.localClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

// sha256Hex is the payload digest format the signed tuple uses: lowercase hex.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
