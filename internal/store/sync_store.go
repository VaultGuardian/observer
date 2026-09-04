// internal/store/sync_store.go
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
)

// =============================================================================
// Phase 2: hosted sync state (cursors + dirty journal)
// =============================================================================
//
// Two tables back the sync engine (migration v15):
//
//   sync_state  - key/value scalars: the per-stream cursors and the pairing
//                 metadata (target fingerprint + journal continuity flag).
//   sync_dirty  - an append-only journal of rows MUTATED after insert. The
//                 cursor lane alone cannot see an in-place UPDATE (the rowid
//                 does not move), so every mutation records its key here.
//
// The journal is written only when EnableSyncJournal has been called - an
// unpaired Observer never touches these tables beyond migration.

// Sync stream names. Each has its own cursor row in sync_state.
const (
	SyncStreamFindings  = "findings"
	SyncStreamDecisions = "decisions"
)

// Sync dirty-journal kinds.
const (
	SyncKindFinding  = "finding"
	SyncKindDecision = "decision"
)

// Sync metadata keys in sync_state.
//
//	SyncMetaTarget     - sha256(SYNC_URL + "\n" + SYNC_TOKEN), hex. A change
//	                     means we are pointed at a different hosted mirror.
//	SyncMetaContinuous - "1" while the process that owns this DB has been
//	                     journaling mutations. Set to "0" on any boot that
//	                     finds the DB previously paired but sync now disabled:
//	                     mutations during that run went unjournaled, so the
//	                     next enable must full-resync.
const (
	SyncMetaTarget     = "meta:target"
	SyncMetaContinuous = "meta:continuous"
)

// SyncDirtyEntry is one row of the mutation journal.
type SyncDirtyEntry struct {
	ID  int64  // sync_dirty.id - the ordering/delete boundary key
	Ref string // event_id (findings) or decision id as text (decisions)
}

// EnableSyncJournal turns on dirty-journal writes inside the three mutation
// methods. Called from main.go only when sync is configured AND the rollback
// fail-closed check passed. While off, no journal row is ever written.
func (s *Store) EnableSyncJournal() {
	s.syncJournal.Store(true)
}

// SyncJournalEnabled reports whether mutation journaling is active.
func (s *Store) SyncJournalEnabled() bool {
	return s.syncJournal.Load()
}

// journalSyncDirtyTx appends one mutation journal row inside the caller's
// transaction. Callers must already have checked SyncJournalEnabled and must
// only call this when the UPDATE actually matched a row.
func journalSyncDirtyTx(ctx context.Context, tx *sql.Tx, kind, ref string) error {
	_, err := tx.ExecContext(ctx,
		"INSERT INTO sync_dirty (kind, ref) VALUES (?, ?)", kind, ref)
	if err != nil {
		return fmt.Errorf("journal sync dirty (%s/%s): %w", kind, ref, err)
	}
	return nil
}

// =============================================================================
// Cursors
// =============================================================================

func syncCursorKey(stream string) string { return "cursor:" + stream }

// GetSyncCursor returns the highest rowid already mirrored for a stream.
// A missing or unparseable row reads as 0 (nothing sent yet).
func (s *Store) GetSyncCursor(ctx context.Context, stream string) (int64, error) {
	raw, err := s.GetSyncMeta(ctx, syncCursorKey(stream))
	if err != nil {
		return 0, err
	}
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse sync cursor %s=%q: %w", stream, raw, err)
	}
	return n, nil
}

// SetSyncCursor records the highest rowid mirrored for a stream.
func (s *Store) SetSyncCursor(ctx context.Context, stream string, value int64) error {
	return s.SetSyncMeta(ctx, syncCursorKey(stream), strconv.FormatInt(value, 10))
}

// GetSyncMeta reads a sync_state scalar. Missing keys return "" with no error.
func (s *Store) GetSyncMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM sync_state WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read sync_state %s: %w", key, err)
	}
	return value, nil
}

// SetSyncMeta writes a sync_state scalar.
func (s *Store) SetSyncMeta(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO sync_state (key, value) VALUES (?, ?)", key, value)
	if err != nil {
		return fmt.Errorf("write sync_state %s: %w", key, err)
	}
	return nil
}

// =============================================================================
// Dirty journal
// =============================================================================

// TakeSyncDirty returns up to limit journal rows of one kind, oldest first.
// It does not remove them - deletion is DeleteSyncDirtyThrough, after the
// corresponding rows have been accepted by the hosted mirror.
func (s *Store) TakeSyncDirty(ctx context.Context, kind string, limit int) ([]SyncDirtyEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, ref FROM sync_dirty WHERE kind = ? ORDER BY id ASC LIMIT ?", kind, limit)
	if err != nil {
		return nil, fmt.Errorf("take sync_dirty %s: %w", kind, err)
	}
	defer rows.Close()

	var out []SyncDirtyEntry
	for rows.Next() {
		var e SyncDirtyEntry
		if err := rows.Scan(&e.ID, &e.Ref); err != nil {
			return nil, fmt.Errorf("scan sync_dirty %s: %w", kind, err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteSyncDirtyThrough removes journal rows of ONE kind up to and including
// maxJournalID.
//
// [A8] The kind scope is not optional: findings and decisions share one
// autoincrement id space, so an unscoped "id <= N" would silently discard
// decision journal rows that the findings pass never looked at. Callers may
// only pass a boundary for which every journal row of that kind at or below it
// was either sent-and-acked or satisfied-by-prune in the same cycle; any scan
// error must abort the cycle without deleting.
func (s *Store) DeleteSyncDirtyThrough(ctx context.Context, kind string, maxJournalID int64) error {
	if maxJournalID <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM sync_dirty WHERE kind = ? AND id <= ?", kind, maxJournalID)
	if err != nil {
		return fmt.Errorf("delete sync_dirty %s <= %d: %w", kind, maxJournalID, err)
	}
	return nil
}

// ClearSyncDirty drops the entire mutation journal. Used only by the full
// resync path, where every row is about to be re-sent from cursor 0 anyway.
func (s *Store) ClearSyncDirty(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sync_dirty"); err != nil {
		return fmt.Errorf("clear sync_dirty: %w", err)
	}
	return nil
}

// =============================================================================
// Rollback detection support
// =============================================================================

// MaxFindingRowID returns the highest findings rowid, or 0 for an empty table.
func (s *Store) MaxFindingRowID(ctx context.Context) (int64, error) {
	var max int64
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(id), 0) FROM findings").Scan(&max)
	if err != nil {
		return 0, fmt.Errorf("max findings rowid: %w", err)
	}
	return max, nil
}

// MaxLLMDecisionRowID returns the highest llm_decisions rowid, or 0 when empty.
func (s *Store) MaxLLMDecisionRowID(ctx context.Context) (int64, error) {
	var max int64
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(id), 0) FROM llm_decisions").Scan(&max)
	if err != nil {
		return 0, fmt.Errorf("max llm_decisions rowid: %w", err)
	}
	return max, nil
}
