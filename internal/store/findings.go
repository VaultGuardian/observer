// internal/store/findings.go
package store

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// RecordFinding writes a classification outcome to the findings table.
// This is the synchronous write path — used for direct/critical writes
// (resolution updates, reconciler). For high-volume pipeline writes,
// use Store.SubmitFinding() which routes through the async writer.
func (s *Store) RecordFinding(ctx context.Context, f *Finding) error {
	resolvedAt := ""
	if f.ResolvedAt != nil {
		resolvedAt = f.ResolvedAt.Format(time.RFC3339)
	}

	_, err := s.db.ExecContext(ctx, `INSERT INTO findings (
		event_id, timestamp, source_type, source_name,
		source_ip, dest_host, http_method, http_path, http_status, response_bytes, user_agent,
		verdict, classification, confidence, reason, matched_via,
		matched_pattern_scope, matched_pattern_bucket, matched_pattern_value,
		origin_event_id,
		raw_line, normalized_line, normalized_hash,
		evidence_status, evidence_status_code, evidence_content_type,
		evidence_body_hash, evidence_capture_mode,
		coordinator_key, coordinator_events, downgraded, downgrade_reason,
		notified,
		resolution_status, resolved_at, resolution_method, previous_verdict
	) VALUES (
		?, ?, ?, ?,
		?, ?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?,
		?,
		?, ?, ?,
		?, ?, ?,
		?, ?,
		?, ?, ?, ?,
		?,
		?, ?, ?, ?
	)`,
		f.EventID, f.Timestamp.Format(time.RFC3339), f.SourceType, f.SourceName,
		f.SourceIP, f.DestHost, f.HTTPMethod, f.HTTPPath, f.HTTPStatus, f.ResponseBytes, f.UserAgent,
		f.Verdict, f.Classification, f.Confidence, f.Reason, f.MatchedVia,
		f.MatchedPatternScope, f.MatchedPatternBucket, f.MatchedPatternValue,
		f.OriginEventID,
		f.RawLine, f.NormalizedLine, f.NormalizedHash,
		f.EvidenceStatus, f.EvidenceStatusCode, f.EvidenceContentType,
		f.EvidenceBodyHash, f.EvidenceCaptureMode,
		f.CoordinatorKey, f.CoordinatorEvents, boolToInt(f.Downgraded), f.DowngradeReason,
		boolToInt(f.Notified),
		f.ResolutionStatus, resolvedAt, f.ResolutionMethod, f.PreviousVerdict,
	)
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return nil
}

// =============================================================================
// Fix 4: Resolution Lifecycle Methods
// =============================================================================

// UpdateFindingResolution sets the resolution status on an existing finding.
// Append-only: keeps original verdict, adds resolution metadata.
// Used by the reconciler goroutine for timeout finalization and by the
// VIP push callback for immediate resolution.
func (s *Store) UpdateFindingResolution(ctx context.Context, eventID string, status string, method string, newVerdict string) error {
	now := time.Now().Format(time.RFC3339)

	// Get the current verdict before updating (for audit trail)
	var currentVerdict string
	err := s.db.QueryRowContext(ctx,
		"SELECT verdict FROM findings WHERE event_id = ? ORDER BY id DESC LIMIT 1",
		eventID,
	).Scan(&currentVerdict)
	if err != nil {
		return fmt.Errorf("lookup current verdict for %s: %w", eventID, err)
	}

	result, err := s.db.ExecContext(ctx, `UPDATE findings SET
		resolution_status = ?,
		resolved_at = ?,
		resolution_method = ?,
		previous_verdict = ?,
		verdict = CASE WHEN ? != '' THEN ? ELSE verdict END,
		downgraded = CASE WHEN ? = 'resolved' AND ? IN ('downgraded', 'recon_failed') THEN 1 ELSE downgraded END,
		downgrade_reason = CASE WHEN ? = 'resolved' AND ? IN ('downgraded', 'recon_failed') THEN ? ELSE downgrade_reason END
	WHERE event_id = ? AND (resolution_status = '' OR resolution_status = 'pending' OR resolution_status IS NULL)`,
		status, now, method, currentVerdict,
		newVerdict, newVerdict,
		status, newVerdict,
		status, newVerdict, method+" resolution",
		eventID,
	)
	if err != nil {
		return fmt.Errorf("update resolution for %s: %w", eventID, err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("finding %s not found or already resolved", eventID)
	}
	return nil
}

// QueryUnresolvedMalicious returns malicious HTTP findings that have not
// been resolved within the given age window. Used by the reconciler
// goroutine to finalize stale findings as "evidence_unavailable".
func (s *Store) QueryUnresolvedMalicious(ctx context.Context, olderThan time.Duration, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	cutoff := time.Now().Add(-olderThan).Format(time.RFC3339)

	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, timestamp, source_type, source_name,
		       dest_host, http_method, http_path, http_status,
		       verdict, classification, reason, matched_via,
		       resolution_status
		FROM findings
		WHERE verdict IN ('malicious', 'alert')
		  AND http_method != ''
		  AND (resolution_status = 'pending' OR resolution_status = '' OR resolution_status IS NULL)
		  AND timestamp < ?
		  AND downgraded = 0
		ORDER BY timestamp ASC
		LIMIT ?`, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("query unresolved malicious: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		var ts string
		var resStatus *string
		if err := rows.Scan(
			&f.EventID, &ts, &f.SourceType, &f.SourceName,
			&f.DestHost, &f.HTTPMethod, &f.HTTPPath, &f.HTTPStatus,
			&f.Verdict, &f.Classification, &f.Reason, &f.MatchedVia,
			&resStatus,
		); err != nil {
			return nil, err
		}
		f.Timestamp, _ = time.Parse(time.RFC3339, ts)
		if resStatus != nil {
			f.ResolutionStatus = *resStatus
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// =============================================================================
// Existing Query Methods (unchanged)
// =============================================================================

// QueryByIP returns all findings from a specific source IP, most recent first.
func (s *Store) QueryByIP(ctx context.Context, ip string, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, timestamp, source_type, source_name,
		       source_ip, dest_host, http_method, http_path, http_status,
		       verdict, classification, confidence, reason, matched_via,
		       matched_pattern_scope, matched_pattern_bucket, matched_pattern_value,
		       COALESCE(origin_event_id,''),
		       normalized_line, normalized_hash, downgraded, downgrade_reason, notified,
		       COALESCE(evidence_body_hash,''), COALESCE(evidence_status_code,0),
		       COALESCE(evidence_content_type,''), COALESCE(resolution_status,'')
		FROM findings
		WHERE source_ip = ?
		ORDER BY timestamp DESC
		LIMIT ?`, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("query by ip: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// QueryByVerdict returns findings matching a specific verdict, most recent first.
func (s *Store) QueryByVerdict(ctx context.Context, verdict string, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, timestamp, source_type, source_name,
		       source_ip, dest_host, http_method, http_path, http_status,
		       verdict, classification, confidence, reason, matched_via,
		       matched_pattern_scope, matched_pattern_bucket, matched_pattern_value,
		       COALESCE(origin_event_id,''),
		       normalized_line, normalized_hash, downgraded, downgrade_reason, notified,
		       COALESCE(evidence_body_hash,''), COALESCE(evidence_status_code,0),
		       COALESCE(evidence_content_type,''), COALESCE(resolution_status,'')
		FROM findings
		WHERE verdict = ?
		ORDER BY timestamp DESC
		LIMIT ?`, verdict, limit)
	if err != nil {
		return nil, fmt.Errorf("query by verdict: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// QueryRecent returns the most recent findings across all verdicts.
func (s *Store) QueryRecent(ctx context.Context, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, timestamp, source_type, source_name,
		       source_ip, dest_host, http_method, http_path, http_status,
		       verdict, classification, confidence, reason, matched_via,
		       matched_pattern_scope, matched_pattern_bucket, matched_pattern_value,
		       COALESCE(origin_event_id,''),
		       normalized_line, normalized_hash, downgraded, downgrade_reason, notified,
		       COALESCE(evidence_body_hash,''), COALESCE(evidence_status_code,0),
		       COALESCE(evidence_content_type,''), COALESCE(resolution_status,'')
		FROM findings
		ORDER BY timestamp DESC
		LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query recent: %w", err)
	}
	defer rows.Close()
	return scanFindings(rows)
}

// CountByVerdict returns a map of verdict → count for a given time window.
func (s *Store) CountByVerdict(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT verdict, COUNT(*) as cnt
		FROM findings
		WHERE timestamp >= ?
		GROUP BY verdict`,
		since.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("count by verdict: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int64)
	for rows.Next() {
		var verdict string
		var count int64
		if err := rows.Scan(&verdict, &count); err != nil {
			return nil, err
		}
		counts[verdict] = count
	}
	return counts, rows.Err()
}

// RecordPipelineStats writes a periodic stats snapshot.
func (s *Store) RecordPipelineStats(ctx context.Context, stats *PipelineStats) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO pipeline_stats (
		timestamp, processed, pattern_hits, noise_suppressed,
		llm_calls, llm_errors, patterns_learned,
		malicious_count, alert_count, suppress_count
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stats.Timestamp.Format(time.RFC3339),
		stats.Processed, stats.PatternHits, stats.NoiseSuppressed,
		stats.LLMCalls, stats.LLMErrors, stats.PatternsLearned,
		stats.MaliciousCount, stats.AlertCount, stats.SuppressCount,
	)
	if err != nil {
		return fmt.Errorf("insert pipeline stats: %w", err)
	}
	return nil
}

// =============================================================================
// Fix 3: Async Findings Writer
// =============================================================================
//
// Under DDoS scanner flood (10K+ requests/sec), synchronous RecordFinding()
// INSERTs for recon_failed events lock SQLite. The retry queue fills up.
// The ingestion channel hits its 1000-buffer limit. Observer drops real
// security events while choking on noise logging.
//
// The FindingsWriter batches INSERTs in a background goroutine. If the
// channel is full under DDoS, only recon/noise logging is dropped — real
// threat findings block until space is available.
//
// Design rule: "Never let async writer dropping apply to anything
// except recon/noise logging."

// FindingsWriter batches finding INSERTs in a background goroutine.
//
// v0.52 P0 fix: prior to this fix, Stop() called
// close(w.ch) while producers could still be in Submit(). Any goroutine in the
// blocking send path (critical findings, channel full) would panic with
// "send on closed channel". Fixed by using a dedicated stopCh signal — the data
// channel is never closed, so sends never race against a close.
type FindingsWriter struct {
	store   *Store
	ch      chan *Finding
	dropped atomic.Int64
	done    chan struct{} // closed when Run() exits
	stopCh  chan struct{} // closed when Stop() is called

	stopOnce sync.Once
}

// NewFindingsWriter creates a writer with the given buffer size.
func NewFindingsWriter(s *Store, bufSize int) *FindingsWriter {
	return &FindingsWriter{
		store:  s,
		ch:     make(chan *Finding, bufSize),
		done:   make(chan struct{}),
		stopCh: make(chan struct{}),
	}
}

// Submit sends a finding to the async writer.
// Droppable findings (recon, allow, suppress) are silently dropped if
// the channel is full. Critical findings (malicious, alert, policy,
// escalated, downgraded) block until space is available or shutdown.
func (w *FindingsWriter) Submit(f *Finding) {
	// Fast path: non-blocking try + shutdown check.
	select {
	case w.ch <- f:
		return
	case <-w.stopCh:
		if !isDroppable(f) {
			log.Printf("[findings-writer] SHUTDOWN: critical finding %s dropped (verdict=%s)", f.EventID, f.Verdict)
		}
		return
	default:
	}

	// Channel full — only drop noise/recon
	if isDroppable(f) {
		w.dropped.Add(1)
		return
	}

	// Critical finding: block until space available OR shutdown.
	// Prior to v0.52 this was a bare `w.ch <- f` which panicked if
	// Stop() closed w.ch concurrently. The stopCh select arm prevents
	// both the panic and the infinite block.
	select {
	case w.ch <- f:
	case <-w.stopCh:
		log.Printf("[findings-writer] SHUTDOWN: critical finding %s dropped (verdict=%s)", f.EventID, f.Verdict)
	}
}

// Dropped returns the count of dropped findings (recon/noise only).
func (w *FindingsWriter) Dropped() int64 {
	return w.dropped.Load()
}

// Stop signals the writer to drain and stop. Blocks until complete.
// Safe to call multiple times (idempotent via sync.Once).
func (w *FindingsWriter) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopCh)
	})
	<-w.done
}

// Run is the background goroutine that batches and writes findings.
// Flushes every 200ms or when batch reaches 50 items, whichever is first.
func (w *FindingsWriter) Run(ctx context.Context) {
	defer close(w.done)

	batch := make([]*Finding, 0, 100)
	flushTimer := time.NewTicker(200 * time.Millisecond)
	defer flushTimer.Stop()

	flush := func() {
		if len(batch) > 0 {
			w.flushBatch(ctx, batch)
			batch = batch[:0]
		}
	}

	for {
		select {
		case f := <-w.ch:
			batch = append(batch, f)
			if len(batch) >= 50 {
				flush()
			}

		case <-flushTimer.C:
			flush()

		case <-w.stopCh:
			// Shutdown: drain remaining findings from channel, then exit.
			for {
				select {
				case f := <-w.ch:
					batch = append(batch, f)
				default:
					flush()
					return
				}
			}

		case <-ctx.Done():
			// Context cancelled: drain remaining findings from channel.
			for {
				select {
				case f := <-w.ch:
					batch = append(batch, f)
				default:
					flush()
					return
				}
			}
		}
	}
}

// flushBatch writes a batch of findings in a single transaction.
func (w *FindingsWriter) flushBatch(ctx context.Context, batch []*Finding) {
	if len(batch) == 0 {
		return
	}

	tx, err := w.store.db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[findings-writer] Failed to begin transaction: %v — writing %d findings individually", err, len(batch))
		// Fallback: try individual inserts
		for _, f := range batch {
			w.store.RecordFinding(ctx, f)
		}
		return
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO findings (
		event_id, timestamp, source_type, source_name,
		source_ip, dest_host, http_method, http_path, http_status, response_bytes, user_agent,
		verdict, classification, confidence, reason, matched_via,
		matched_pattern_scope, matched_pattern_bucket, matched_pattern_value,
		origin_event_id,
		raw_line, normalized_line, normalized_hash,
		evidence_status, evidence_status_code, evidence_content_type,
		evidence_body_hash, evidence_capture_mode,
		coordinator_key, coordinator_events, downgraded, downgrade_reason,
		notified,
		resolution_status, resolved_at, resolution_method, previous_verdict
	) VALUES (
		?, ?, ?, ?,
		?, ?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?,
		?,
		?, ?, ?,
		?, ?, ?,
		?, ?,
		?, ?, ?, ?,
		?,
		?, ?, ?, ?
	)`)
	if err != nil {
		tx.Rollback()
		log.Printf("[findings-writer] Failed to prepare statement: %v", err)
		return
	}
	defer stmt.Close()

	inserted := 0
	for _, f := range batch {
		resolvedAt := ""
		if f.ResolvedAt != nil {
			resolvedAt = f.ResolvedAt.Format(time.RFC3339)
		}
		_, err := stmt.ExecContext(ctx,
			f.EventID, f.Timestamp.Format(time.RFC3339), f.SourceType, f.SourceName,
			f.SourceIP, f.DestHost, f.HTTPMethod, f.HTTPPath, f.HTTPStatus, f.ResponseBytes, f.UserAgent,
			f.Verdict, f.Classification, f.Confidence, f.Reason, f.MatchedVia,
			f.MatchedPatternScope, f.MatchedPatternBucket, f.MatchedPatternValue,
			f.OriginEventID,
			f.RawLine, f.NormalizedLine, f.NormalizedHash,
			f.EvidenceStatus, f.EvidenceStatusCode, f.EvidenceContentType,
			f.EvidenceBodyHash, f.EvidenceCaptureMode,
			f.CoordinatorKey, f.CoordinatorEvents, boolToInt(f.Downgraded), f.DowngradeReason,
			boolToInt(f.Notified),
			f.ResolutionStatus, resolvedAt, f.ResolutionMethod, f.PreviousVerdict,
		)
		if err != nil {
			log.Printf("[findings-writer] INSERT error for %s: %v", f.EventID, err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[findings-writer] Commit error: %v", err)
		return
	}

	if inserted > 0 && inserted != len(batch) {
		log.Printf("[findings-writer] Batch: %d/%d inserted", inserted, len(batch))
	}
}

// isDroppable returns true for findings that can be safely dropped under
// pressure. Only recon/allow/suppress are droppable — NEVER malicious,
// alert, policy, or resolution findings.
func isDroppable(f *Finding) bool {
	switch f.Verdict {
	case "recon", "allow", "suppress":
		return true
	}
	return false
}

// --- helpers ---

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func scanFindings(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]Finding, error) {
	var findings []Finding
	for rows.Next() {
		var f Finding
		var ts string
		var downgraded int
		var notified int
		if err := rows.Scan(
			&f.EventID, &ts, &f.SourceType, &f.SourceName,
			&f.SourceIP, &f.DestHost, &f.HTTPMethod, &f.HTTPPath, &f.HTTPStatus,
			&f.Verdict, &f.Classification, &f.Confidence, &f.Reason, &f.MatchedVia,
			&f.MatchedPatternScope, &f.MatchedPatternBucket, &f.MatchedPatternValue,
			&f.OriginEventID,
			&f.NormalizedLine, &f.NormalizedHash, &downgraded, &f.DowngradeReason, &notified,
			&f.EvidenceBodyHash, &f.EvidenceStatusCode,
			&f.EvidenceContentType, &f.ResolutionStatus,
		); err != nil {
			return nil, err
		}
		f.Timestamp, _ = time.Parse(time.RFC3339, ts)
		f.Downgraded = downgraded == 1
		f.Notified = notified == 1
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// UpdateFindingVerdict changes the verdict on a finding as part of a human
// correction. Records the previous verdict for audit trail, sets resolution
// method to "human_override". Used when a human corrects a classification
// from the dashboard.
//
// When the new verdict is a downgrade ('suppress', 'allow', 'recon'), this
// also clears the notified flag. The dashboard's outcome classifier checks
// notified before downgraded; leaving notified=1 alongside downgraded=1
// produces a hybrid render where the badge stays red ("ESCALATED") while
// the "Why it was downgraded" panel renders green underneath, and the event
// remains in the Needs Attention list. Clearing notified makes the DB row
// match the operator's intent so subsequent fetches stay consistent with
// the dashboard's optimistic update.
func (s *Store) UpdateFindingVerdict(ctx context.Context, eventID string, newVerdict string, reason string) error {
	now := time.Now().Format(time.RFC3339)

	// Get the current verdict for audit trail
	var currentVerdict string
	err := s.db.QueryRowContext(ctx,
		"SELECT verdict FROM findings WHERE event_id = ? ORDER BY id DESC LIMIT 1",
		eventID,
	).Scan(&currentVerdict)
	if err != nil {
		return fmt.Errorf("lookup current verdict for %s: %w", eventID, err)
	}

	_, err = s.db.ExecContext(ctx, `UPDATE findings SET
		verdict = ?,
		resolution_status = 'resolved',
		resolved_at = ?,
		resolution_method = 'human_override',
		previous_verdict = ?,
		downgraded = CASE WHEN ? IN ('suppress', 'allow', 'recon') THEN 1 ELSE downgraded END,
		downgrade_reason = CASE WHEN ? IN ('suppress', 'allow', 'recon') THEN ? ELSE downgrade_reason END,
		notified = CASE WHEN ? IN ('suppress', 'allow', 'recon') THEN 0 ELSE notified END
	WHERE event_id = ?`,
		newVerdict, now, currentVerdict,
		newVerdict,
		newVerdict, reason,
		newVerdict,
		eventID,
	)
	if err != nil {
		return fmt.Errorf("update verdict for %s: %w", eventID, err)
	}
	return nil
}

// GetFindingByEventID returns the most recent finding for an event ID.
// Used by the correction API to look up finding data server-side.
func (s *Store) GetFindingByEventID(ctx context.Context, eventID string) (*Finding, error) {
	var f Finding
	var ts string
	var downgraded, notified int

	err := s.db.QueryRowContext(ctx, `SELECT
		event_id, timestamp, source_type, source_name,
		COALESCE(source_ip,''), COALESCE(dest_host,''),
		COALESCE(http_method,''), COALESCE(http_path,''),
		COALESCE(http_status,0), COALESCE(response_bytes,0),
		verdict, COALESCE(classification,''), COALESCE(confidence,0), COALESCE(reason,''),
		COALESCE(matched_via,''),
		COALESCE(matched_pattern_scope,''), COALESCE(matched_pattern_bucket,''), COALESCE(matched_pattern_value,''),
		COALESCE(origin_event_id,''),
		COALESCE(normalized_line,''), COALESCE(normalized_hash,''),
		COALESCE(downgraded,0), COALESCE(downgrade_reason,''), COALESCE(notified,0),
		COALESCE(evidence_body_hash,''), COALESCE(evidence_status_code,0),
		COALESCE(evidence_content_type,''), COALESCE(resolution_status,'')
	FROM findings WHERE event_id = ? ORDER BY id DESC LIMIT 1`, eventID).Scan(
		&f.EventID, &ts, &f.SourceType, &f.SourceName,
		&f.SourceIP, &f.DestHost,
		&f.HTTPMethod, &f.HTTPPath,
		&f.HTTPStatus, &f.ResponseBytes,
		&f.Verdict, &f.Classification, &f.Confidence, &f.Reason,
		&f.MatchedVia,
		&f.MatchedPatternScope, &f.MatchedPatternBucket, &f.MatchedPatternValue,
		&f.OriginEventID,
		&f.NormalizedLine, &f.NormalizedHash,
		&downgraded, &f.DowngradeReason, &notified,
		&f.EvidenceBodyHash, &f.EvidenceStatusCode,
		&f.EvidenceContentType, &f.ResolutionStatus,
	)
	if err != nil {
		return nil, fmt.Errorf("get finding %s: %w", eventID, err)
	}
	f.Timestamp, _ = time.Parse(time.RFC3339, ts)
	f.Downgraded = downgraded == 1
	f.Notified = notified == 1
	return &f, nil
}
