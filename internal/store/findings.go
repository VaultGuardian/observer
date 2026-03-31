package store

import (
	"context"
	"fmt"
	"time"
)

// RecordFinding writes a classification outcome to the findings table.
// This is the primary write path — called for every event that makes it
// past deterministic noise suppression.
//
// Writes are immediate for deny/alert findings. For allow/suppress (high
// volume), callers may choose to batch via a channel — but that's a future
// optimization. At current volume (~500 events/day), direct writes are fine.
func (s *Store) RecordFinding(ctx context.Context, f *Finding) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO findings (
		event_id, timestamp, source_type, source_name,
		source_ip, dest_host, http_method, http_path, http_status, response_bytes, user_agent,
		verdict, classification, confidence, reason, matched_via,
		raw_line, normalized_line, normalized_hash,
		evidence_status, evidence_status_code, evidence_content_type,
		evidence_body_hash, evidence_capture_mode,
		coordinator_key, coordinator_events, downgraded, downgrade_reason,
		notified
	) VALUES (
		?, ?, ?, ?,
		?, ?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?,
		?, ?,
		?, ?, ?, ?,
		?
	)`,
		f.EventID, f.Timestamp.Format(time.RFC3339), f.SourceType, f.SourceName,
		f.SourceIP, f.DestHost, f.HTTPMethod, f.HTTPPath, f.HTTPStatus, f.ResponseBytes, f.UserAgent,
		f.Verdict, f.Classification, f.Confidence, f.Reason, f.MatchedVia,
		f.RawLine, f.NormalizedLine, f.NormalizedHash,
		f.EvidenceStatus, f.EvidenceStatusCode, f.EvidenceContentType,
		f.EvidenceBodyHash, f.EvidenceCaptureMode,
		f.CoordinatorKey, f.CoordinatorEvents, boolToInt(f.Downgraded), f.DowngradeReason,
		boolToInt(f.Notified),
	)
	if err != nil {
		return fmt.Errorf("insert finding: %w", err)
	}
	return nil
}

// QueryByIP returns all findings from a specific source IP, most recent first.
func (s *Store) QueryByIP(ctx context.Context, ip string, limit int) ([]Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_id, timestamp, source_type, source_name,
		       source_ip, dest_host, http_method, http_path, http_status,
		       verdict, classification, confidence, reason, matched_via,
		       normalized_hash, downgraded, downgrade_reason, notified
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
		       normalized_hash, downgraded, downgrade_reason, notified
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
		       normalized_hash, downgraded, downgrade_reason, notified
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
		deny_count, alert_count, suppress_count
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stats.Timestamp.Format(time.RFC3339),
		stats.Processed, stats.PatternHits, stats.NoiseSuppressed,
		stats.LLMCalls, stats.LLMErrors, stats.PatternsLearned,
		stats.DenyCount, stats.AlertCount, stats.SuppressCount,
	)
	if err != nil {
		return fmt.Errorf("insert pipeline stats: %w", err)
	}
	return nil
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
			&f.NormalizedHash, &downgraded, &f.DowngradeReason, &notified,
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