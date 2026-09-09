// internal/store/command_receipts.go
package store

// =============================================================================
// Command receipt ledger (Phase 4, lane C)
// =============================================================================
//
// The hosted control plane hands Observer signed commands; this table is
// Observer's own record of what it was asked to do and what happened. It is
// written by internal/sync lane C and by nothing else.
//
// WHAT IT PROTECTS AGAINST [A13]
//
// The hosted side marks a command terminal only when Observer acks it. If the
// ack is lost - network drop, hosted restart, Observer killed between
// executing and acking - the command is served again. Without a local record
// the second delivery would execute a second time. The ledger closes exactly
// that window: a terminal receipt turns a redelivery into a re-ack, with no
// second execution and no second local mutation. Ed25519 signatures stop a
// database-write attacker from minting commands; the epoch stops commands
// from an older pairing; this ledger stops honest redelivery from double
// applying.
//
// WHAT IT DOES NOT PROTECT AGAINST
//
// A residual crash window remains, and it is accepted rather than papered
// over. The local mutation and the receipt live in two different databases
// (the local API's SQLite write, then this row) and therefore in two
// transactions. A crash between them leaves a command executed with a
// non-terminal receipt, and the next delivery executes it again.
//
// That is survivable only because every command type is effect-convergent:
// re-running one lands the same end state (an already-deleted pattern reports
// "not found", an already-trusted IP reports "already trusted", a re-applied
// correction rewrites the same verdict and the same pattern). The observable
// consequence of a replay is limited to re-stamped audit metadata - a fresh
// reviewed_at, a fresh resolved_at, a second identical log line. No new
// verdict, no second email, no divergence from the operator's intent. Any
// future command type that is NOT effect-convergent (a counter increment, an
// append, anything order-dependent) breaks this reasoning and must not be
// added to lane C's allowlist without closing the window first.
//
// Receipts deliberately survive re-pairing. The epoch rotates, the hosted
// database may be rebuilt, but this box's record of what it was told to do is
// its own; that is the point of keeping it locally. Retention is 90 days,
// pruned alongside every other retention policy in Store.Prune - far longer
// than any redelivery window the hosted side can produce.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Terminal outcomes recorded in command_receipts.outcome. A receipt with an
// empty outcome is non-terminal: it was seen, and possibly executed, but the
// result was never committed.
const (
	// CommandOutcomeExecuted - the local API accepted the command (2xx).
	CommandOutcomeExecuted = "executed"

	// CommandOutcomeConverged - the local API reported the requested state was
	// already true. Success from the control plane's point of view.
	CommandOutcomeConverged = "converged"

	// CommandOutcomeRejected - the local API refused the command (4xx that is
	// not a convergence), or lane C refused it before dispatch (unknown type,
	// oversize payload).
	CommandOutcomeRejected = "rejected"

	// CommandOutcomeIntegrityFailed - the command failed signature, instance,
	// epoch, or payload-identity verification. It was never executed.
	CommandOutcomeIntegrityFailed = "integrity_failed"

	// CommandOutcomeExpired - the command's expiry had passed before it could
	// be executed. It was never executed.
	CommandOutcomeExpired = "expired"
)

// ErrCommandReceiptTerminal is returned by FinalizeCommandReceipt when the
// receipt already holds a terminal outcome. The first terminal outcome is the
// authoritative one: it is what was acked to the control plane, and what a
// redelivery re-acks.
var ErrCommandReceiptTerminal = errors.New("command receipt already terminal")

// maxCommandResult bounds the stored result snippet (and, with it, the
// result_message lane C acks back).
const maxCommandResult = 1024

// CommandReceipt is one row of the ledger.
//
// The first six fields come from the SIGNED command tuple, not from anywhere
// a hosted database write could reach on its own: storing them is what lets a
// redelivery be checked for payload identity (same id, different payload =
// tampering, not a retry).
type CommandReceipt struct {
	CommandID   string
	CommandType string
	PayloadSHA  string // lowercase hex sha256 of the exact payload bytes
	Epoch       string
	Signature   string // base64, exactly as received
	ExpiresAt   int64  // unix ms, from the signed tuple
	FirstSeenAt int64  // unix ms
	ExecutedAt  int64  // unix ms; 0 until finalized
	HTTPStatus  int    // local API status; 0 if never dispatched
	Result      string // snippet, <= maxCommandResult bytes
	Outcome     string // one of the CommandOutcome* constants; "" = non-terminal
}

// Terminal reports whether this receipt already holds a final outcome.
func (r *CommandReceipt) Terminal() bool {
	return r != nil && r.Outcome != ""
}

// GetCommandReceipt returns the receipt for a command id, or nil if this box
// has never seen that command.
func (s *Store) GetCommandReceipt(ctx context.Context, commandID string) (*CommandReceipt, error) {
	var (
		r          CommandReceipt
		executedAt sql.NullInt64
		httpStatus sql.NullInt64
		result     sql.NullString
		outcome    sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `SELECT
		command_id, command_type, payload_sha, epoch, signature,
		expires_at, first_seen_at, executed_at, http_status, result, outcome
		FROM command_receipts WHERE command_id = ?`, commandID,
	).Scan(
		&r.CommandID, &r.CommandType, &r.PayloadSHA, &r.Epoch, &r.Signature,
		&r.ExpiresAt, &r.FirstSeenAt, &executedAt, &httpStatus, &result, &outcome,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get command receipt %s: %w", commandID, err)
	}
	r.ExecutedAt = executedAt.Int64
	r.HTTPStatus = int(httpStatus.Int64)
	r.Result = result.String
	r.Outcome = outcome.String
	return &r, nil
}

// RecordCommandSeen writes the signed tuple of a command before anything is
// done with it. Idempotent: a redelivery leaves the original first_seen_at and
// any recorded outcome untouched, so the ledger keeps saying when this box
// FIRST heard about the command.
func (s *Store) RecordCommandSeen(ctx context.Context, r *CommandReceipt) error {
	if r == nil || r.CommandID == "" {
		return fmt.Errorf("record command seen: command id is required")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO command_receipts
		(command_id, command_type, payload_sha, epoch, signature, expires_at, first_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(command_id) DO NOTHING`,
		r.CommandID, r.CommandType, r.PayloadSHA, r.Epoch, r.Signature,
		r.ExpiresAt, r.FirstSeenAt,
	)
	if err != nil {
		return fmt.Errorf("record command seen %s: %w", r.CommandID, err)
	}
	return nil
}

// FinalizeCommandReceipt records what happened to a command.
//
// It refuses to overwrite a terminal outcome (ErrCommandReceiptTerminal): the
// first terminal outcome is the one that was acked, so overwriting it would
// make the ledger disagree with what the control plane was told. A caller that
// hits this has a redelivery it should be re-acking, not re-finalizing.
func (s *Store) FinalizeCommandReceipt(
	ctx context.Context,
	commandID string,
	executedAtMS int64,
	httpStatus int,
	result string,
	outcome string,
) error {
	if outcome == "" {
		return fmt.Errorf("finalize command receipt %s: outcome is required", commandID)
	}
	if len(result) > maxCommandResult {
		result = result[:maxCommandResult]
	}

	res, err := s.db.ExecContext(ctx, `UPDATE command_receipts SET
		executed_at = ?,
		http_status = ?,
		result = ?,
		outcome = ?
		WHERE command_id = ? AND (outcome IS NULL OR outcome = '')`,
		executedAtMS, httpStatus, result, outcome, commandID,
	)
	if err != nil {
		return fmt.Errorf("finalize command receipt %s: %w", commandID, err)
	}
	if rows, _ := res.RowsAffected(); rows > 0 {
		return nil
	}

	// Nothing updated: either the row is already terminal or it does not
	// exist. Both are caller bugs, but they are different bugs.
	existing, gerr := s.GetCommandReceipt(ctx, commandID)
	if gerr != nil {
		return gerr
	}
	if existing == nil {
		return fmt.Errorf("finalize command receipt %s: no receipt recorded", commandID)
	}
	return fmt.Errorf("finalize command receipt %s (outcome %s): %w",
		commandID, existing.Outcome, ErrCommandReceiptTerminal)
}
