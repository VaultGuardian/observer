package sync

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

// =============================================================================
// LANE A - findings and llm_decisions
// =============================================================================
//
// Ordering invariant [A2]. Why a partially-applied hosted batch cannot leave
// the mirror holding a stale version of an event:
//
//   - The cursor lane is the ONLY introducer of new row versions, and it walks
//     rowids strictly ascending.
//   - Within one scan window, rows sharing an event_id are collapsed to the
//     newest, so a single POST never contains two versions of the same event.
//   - The dirty lane only ever touches events whose newest row is already
//     at-or-behind the cursor, and only ever sends that newest row - never
//     history. Anything ahead of the cursor is deferred to the cursor lane.
//   - Nothing advances on an unvalidated ack, so a batch the hosted side only
//     half-applied is simply re-sent, ascending and collapsed, until a fully
//     validated success lands the newest version last.
//
// The four steps run strictly sequentially and abort on the first failure:
// running them concurrently, or continuing past an error, would break the
// "cursor is at-or-behind reality" premise the dirty lane's defer test relies
// on.

const (
	pathFindings  = "/api/ingest/findings"
	pathDecisions = "/api/ingest/decisions"

	keyFindings  = "findings"
	keyDecisions = "decisions"
)

// runLaneA is the lane A goroutine: tick, drain, back off on failure.
func (e *Engine) runLaneA(ctx context.Context) {
	backoff := e.cfg.Interval
	failing := false

	timer := time.NewTimer(e.cfg.Interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		for {
			more, progressed, err := e.laneACycle(ctx)

			if progressed {
				backoff = e.cfg.Interval
				if failing {
					log.Printf("[sync] lane A recovered")
					failing = false
				}
			}

			if err != nil {
				if ctx.Err() != nil {
					return
				}
				backoff = nextBackoff(backoff, e.cfg.Interval)
				// Log the state change, not every retry: a hosted outage
				// would otherwise write a line every few seconds forever.
				if !failing {
					log.Printf("[sync] lane A failing: %v (retrying with backoff, max %s)", err, maxBackoff)
					failing = true
				}
				break
			}

			if !more || ctx.Err() != nil {
				break
			}
			// Drain mode: a full scan window means there is more waiting.
			// Loop immediately instead of idling for a whole interval.
		}

		timer.Reset(backoff)
	}
}

// nextBackoff doubles the current delay, capped at maxBackoff and floored at
// the configured interval.
func nextBackoff(current, base time.Duration) time.Duration {
	if current < base {
		current = base
	}
	next := current * 2
	if next > maxBackoff {
		next = maxBackoff
	}
	return next
}

// laneACycle runs the four lane A steps in order.
//
// Returns more=true when any step filled its scan window (there is more work
// queued right now), progressed=true when at least one acknowledgement
// validated or journal rows were retired, and the first error encountered.
func (e *Engine) laneACycle(ctx context.Context) (more bool, progressed bool, err error) {
	steps := []func(context.Context) (bool, bool, error){
		e.syncFindingsCursor,
		e.syncDecisionsCursor,
		e.syncFindingsDirty,
		e.syncDecisionsDirty,
	}
	for _, step := range steps {
		stepMore, stepProgressed, stepErr := step(ctx)
		more = more || stepMore
		progressed = progressed || stepProgressed
		if stepErr != nil {
			// Abort the remaining steps: the later steps' defer tests assume
			// the cursors describe what the mirror actually holds.
			return more, progressed, stepErr
		}
	}
	return more, progressed, nil
}

// -----------------------------------------------------------------------------
// Step 1 - findings cursor batch
// -----------------------------------------------------------------------------

func (e *Engine) syncFindingsCursor(ctx context.Context) (bool, bool, error) {
	cursor, err := e.store.GetSyncCursor(ctx, store.SyncStreamFindings)
	if err != nil {
		return false, false, err
	}
	rows, err := e.store.ListFindingsAfterIDFull(ctx, cursor, scanWindow)
	if err != nil {
		return false, false, err
	}
	if len(rows) == 0 {
		return false, false, nil
	}

	// The scanned max, not the sent max: rows collapsed away or skipped by
	// pre-validation are covered by this window and must not be re-read
	// forever. Rows arrive ascending, so the last one is the highest.
	scannedMax := rows[len(rows)-1].Rowid
	full := len(rows) == scanWindow

	items := prepareFindings(collapseFindings(rows))
	batches := splitBatches(keyFindings, items)

	if len(batches) == 0 {
		// Every row in the window was unsendable. Advance anyway - they are
		// permanently unsendable by contract, and stalling here would wedge
		// the whole stream behind them.
		if err := e.store.SetSyncCursor(ctx, store.SyncStreamFindings, scannedMax); err != nil {
			return false, false, err
		}
		return full, true, nil
	}

	progressed := false
	for i, batch := range batches {
		if err := e.postBatch(ctx, pathFindings, keyFindings, batch); err != nil {
			return false, progressed, err
		}
		progressed = true

		// [A5] A budget-split batch advances only to what it actually sent;
		// only the final batch may claim the whole scanned window.
		advanceTo := maxRowid(batch)
		if i == len(batches)-1 {
			advanceTo = scannedMax
		}
		if err := e.store.SetSyncCursor(ctx, store.SyncStreamFindings, advanceTo); err != nil {
			return false, progressed, err
		}
	}
	return full, progressed, nil
}

// collapseFindings [A2] keeps only the highest-rowid row per event_id,
// preserving ascending rowid order.
//
// The hosted upsert keys on (instance, event_id) and overwrites, so sending
// the older versions would be pure waste - and worse, it would widen the
// window in which a partially-applied batch leaves the mirror on a stale
// version of the event.
func collapseFindings(rows []store.SyncFinding) []store.SyncFinding {
	newest := make(map[string]int64, len(rows))
	for _, r := range rows {
		if r.Rowid > newest[r.F.EventID] {
			newest[r.F.EventID] = r.Rowid
		}
	}
	out := make([]store.SyncFinding, 0, len(rows))
	for _, r := range rows {
		if newest[r.F.EventID] == r.Rowid {
			out = append(out, r)
		}
	}
	return out
}

// -----------------------------------------------------------------------------
// Step 2 - decisions cursor batch
// -----------------------------------------------------------------------------

func (e *Engine) syncDecisionsCursor(ctx context.Context) (bool, bool, error) {
	cursor, err := e.store.GetSyncCursor(ctx, store.SyncStreamDecisions)
	if err != nil {
		return false, false, err
	}
	rows, err := e.store.ListDecisionsAfterIDFull(ctx, cursor, scanWindow)
	if err != nil {
		return false, false, err
	}
	if len(rows) == 0 {
		return false, false, nil
	}

	// No collapsing: id IS the hosted key, so every row is a distinct entity.
	scannedMax := rows[len(rows)-1].ID
	full := len(rows) == scanWindow

	batches := splitBatches(keyDecisions, prepareDecisions(rows))
	if len(batches) == 0 {
		if err := e.store.SetSyncCursor(ctx, store.SyncStreamDecisions, scannedMax); err != nil {
			return false, false, err
		}
		return full, true, nil
	}

	progressed := false
	for i, batch := range batches {
		if err := e.postBatch(ctx, pathDecisions, keyDecisions, batch); err != nil {
			return false, progressed, err
		}
		progressed = true

		advanceTo := maxRowid(batch)
		if i == len(batches)-1 {
			advanceTo = scannedMax
		}
		if err := e.store.SetSyncCursor(ctx, store.SyncStreamDecisions, advanceTo); err != nil {
			return false, progressed, err
		}
	}
	return full, progressed, nil
}

// -----------------------------------------------------------------------------
// Steps 3 and 4 - dirty journal
// -----------------------------------------------------------------------------

// dirtyState is what one cycle decided about a journal ref.
type dirtyState int

const (
	// dirtySend: the newest local row is at-or-behind the cursor, so the
	// cursor lane will never deliver it - this lane must.
	dirtySend dirtyState = iota
	// dirtySatisfied: nothing left to send (row pruned, or the ref is
	// unusable). The journal rows can be retired.
	dirtySatisfied
	// dirtyDeferred: the newest row is AHEAD of the cursor, so the cursor
	// lane will deliver it. Leave the journal rows in place; retiring them
	// now would lose the mutation if the cursor pass later fails.
	dirtyDeferred
)

// syncFindingsDirty re-sends findings mutated in place after they were
// already mirrored.
func (e *Engine) syncFindingsDirty(ctx context.Context) (bool, bool, error) {
	entries, err := e.store.TakeSyncDirty(ctx, store.SyncKindFinding, scanWindow)
	if err != nil {
		return false, false, err
	}
	if len(entries) == 0 {
		return false, false, nil
	}
	cursor, err := e.store.GetSyncCursor(ctx, store.SyncStreamFindings)
	if err != nil {
		return false, false, err
	}

	seen := make(map[string]dirtyState, len(entries))
	var rows []store.SyncFinding
	var minDeferred int64

	for _, entry := range entries {
		state, known := seen[entry.Ref]
		if !known {
			// [A2/A9] Newest row only. Never replay an event's history.
			rowid, finding, lerr := e.store.LatestFindingForEventIDFull(ctx, entry.Ref)
			if lerr != nil {
				return false, false, lerr
			}
			switch {
			case finding == nil:
				state = dirtySatisfied
			case rowid > cursor:
				state = dirtyDeferred
			default:
				state = dirtySend
				rows = append(rows, store.SyncFinding{Rowid: rowid, F: *finding})
			}
			seen[entry.Ref] = state
		}
		if state == dirtyDeferred && (minDeferred == 0 || entry.ID < minDeferred) {
			minDeferred = entry.ID
		}
	}

	boundary := deleteBoundary(entries, minDeferred)
	return e.flushDirty(ctx, store.SyncKindFinding, pathFindings, keyFindings,
		prepareFindings(rows), boundary, len(entries) == scanWindow)
}

// syncDecisionsDirty re-sends decisions whose human-review columns changed.
func (e *Engine) syncDecisionsDirty(ctx context.Context) (bool, bool, error) {
	entries, err := e.store.TakeSyncDirty(ctx, store.SyncKindDecision, scanWindow)
	if err != nil {
		return false, false, err
	}
	if len(entries) == 0 {
		return false, false, nil
	}
	cursor, err := e.store.GetSyncCursor(ctx, store.SyncStreamDecisions)
	if err != nil {
		return false, false, err
	}

	seen := make(map[string]dirtyState, len(entries))
	var rows []store.LLMDecision
	var minDeferred int64

	for _, entry := range entries {
		state, known := seen[entry.Ref]
		if !known {
			id, perr := strconv.ParseInt(entry.Ref, 10, 64)
			if perr != nil {
				// A ref that is not a decision id can never be sent; letting
				// it sit would wedge the journal behind it forever.
				log.Printf("[sync] dropping unusable decision journal ref %q: %v", entry.Ref, perr)
				state = dirtySatisfied
			} else if decision, gerr := e.store.GetDecisionByIDFull(ctx, id); gerr != nil {
				return false, false, gerr
			} else {
				switch {
				case decision == nil:
					state = dirtySatisfied
				case decision.ID > cursor:
					// A decision's rowid IS its id, so the defer test is
					// exactly "is the cursor lane still going to send it".
					state = dirtyDeferred
				default:
					state = dirtySend
					rows = append(rows, *decision)
				}
			}
			seen[entry.Ref] = state
		}
		if state == dirtyDeferred && (minDeferred == 0 || entry.ID < minDeferred) {
			minDeferred = entry.ID
		}
	}

	boundary := deleteBoundary(entries, minDeferred)
	return e.flushDirty(ctx, store.SyncKindDecision, pathDecisions, keyDecisions,
		prepareDecisions(rows), boundary, len(entries) == scanWindow)
}

// deleteBoundary returns the highest journal id such that every row of this
// kind at or below it was either sent or satisfied this cycle. A deferred ref
// caps the boundary just below its earliest journal id - everything at or
// above that stays for a later cycle, even rows that were sent, because we
// cannot retire a deferred mutation we have not delivered.
func deleteBoundary(entries []store.SyncDirtyEntry, minDeferred int64) int64 {
	if minDeferred > 0 {
		return minDeferred - 1
	}
	return entries[len(entries)-1].ID
}

// flushDirty POSTs the collected rows and, only on full success, retires the
// journal rows up to the boundary.
func (e *Engine) flushDirty(
	ctx context.Context,
	kind, path, key string,
	items []preparedItem,
	boundary int64,
	fullWindow bool,
) (bool, bool, error) {
	progressed := false
	for _, batch := range splitBatches(key, items) {
		if err := e.postBatch(ctx, path, key, batch); err != nil {
			// [A8] Any failure aborts without deleting: the journal is the
			// only record that these rows still need mirroring.
			return false, progressed, err
		}
		progressed = true
	}

	if boundary <= 0 {
		// Everything in this window is deferred; the cursor lane will deliver
		// it. Do not report more work - re-reading the same deferred entries
		// immediately would spin.
		return false, progressed, nil
	}
	if err := e.store.DeleteSyncDirtyThrough(ctx, kind, boundary); err != nil {
		return false, progressed, err
	}
	return fullWindow, true, nil
}
