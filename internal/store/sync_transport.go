// internal/store/sync_transport.go
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// =============================================================================
// [A4] Canonical full-row transport scanners
// =============================================================================
//
// The dashboard scanners (scanFindings, GetFindingByEventID, ListLLMDecisions)
// deliberately omit columns the UI does not render - response_bytes,
// user_agent, raw_line, evidence_status, evidence_capture_mode, the
// coordinator fields, the resolution audit fields. That is fine for a browser
// but FATAL for sync: the hosted ingest upsert OVERWRITES every mapped column,
// so a partially-populated struct would null out real data on the mirror.
//
// Reusing the dashboard scanners for sync is therefore FORBIDDEN. Everything
// on the wire is read through the two column lists below, each of which is
// defined exactly once and must list EVERY column its struct carries.
//
// TestSyncTransportRoundTrip is the drift tripwire: it populates every field,
// round-trips through these scanners, and compares the marshaled JSON. A new
// column added to Finding / LLMDecision without being added here fails it.

// findingTransportColumns lists every findings column that store.Finding
// carries, prefixed by the rowid. Order must match scanSyncFinding.
const findingTransportColumns = `id,
	event_id, timestamp, source_type, source_name,
	COALESCE(source_ip,''), COALESCE(dest_host,''),
	COALESCE(http_method,''), COALESCE(http_path,''),
	COALESCE(http_status,0), COALESCE(response_bytes,0), COALESCE(user_agent,''),
	verdict, COALESCE(classification,''), COALESCE(confidence,0),
	COALESCE(reason,''), COALESCE(matched_via,''),
	COALESCE(matched_pattern_scope,''), COALESCE(matched_pattern_bucket,''),
	COALESCE(matched_pattern_value,''),
	COALESCE(origin_event_id,''),
	COALESCE(raw_line,''), COALESCE(normalized_line,''), COALESCE(normalized_hash,''),
	COALESCE(evidence_status,''), COALESCE(evidence_status_code,0),
	COALESCE(evidence_content_type,''), COALESCE(evidence_body_hash,''),
	COALESCE(evidence_capture_mode,''),
	COALESCE(coordinator_key,''), COALESCE(coordinator_events,0),
	COALESCE(downgraded,0), COALESCE(downgrade_reason,''),
	COALESCE(notified,0),
	COALESCE(resolution_status,''), COALESCE(resolved_at,''),
	COALESCE(resolution_method,''), COALESCE(previous_verdict,'')`

// decisionTransportColumns lists every llm_decisions column that
// store.LLMDecision carries. id doubles as the rowid AND the hosted key.
// Order must match scanSyncDecision.
const decisionTransportColumns = `id,
	COALESCE(event_id,''), timestamp, tier, model, COALESCE(reasoning_effort,''),
	COALESCE(prompt_tokens,0), COALESCE(completion_tokens,0), COALESCE(latency_ms,0),
	COALESCE(source_scope,''), COALESCE(raw_line,''),
	COALESCE(normalized_line,''), COALESCE(normalized_hash,''),
	COALESCE(evidence_preview,''), COALESCE(evidence_status_code,0),
	COALESCE(evidence_content_type,''), COALESCE(evidence_body_hash,''),
	COALESCE(llm_response_raw,''), COALESCE(classification,''), COALESCE(action,''),
	COALESCE(confidence,0), COALESCE(reason,''),
	COALESCE(pattern_type,''), COALESCE(pattern_value,''), COALESCE(source_hint,''),
	COALESCE(pattern_learned,0), COALESCE(pattern_bucket,''), COALESCE(cache_key,''),
	COALESCE(final_verdict,''),
	COALESCE(escalated,0), COALESCE(downgraded,0), COALESCE(finding_id,''),
	COALESCE(notified,0),
	COALESCE(prompt_version,''), COALESCE(code_version,''),
	COALESCE(review_status,''), COALESCE(reviewed_by,''), COALESCE(reviewed_at,''),
	COALESCE(reviewer_verdict,''), COALESCE(reviewer_reason,''),
	COALESCE(pattern_deleted,0), COALESCE(replacement_pattern,'')`

// SyncFinding pairs a findings row with its rowid, which is the cursor key.
type SyncFinding struct {
	Rowid int64
	F     Finding
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanSyncFinding reads one full findings row. Column order must match
// findingTransportColumns exactly.
func scanSyncFinding(sc rowScanner) (SyncFinding, error) {
	var out SyncFinding
	var f Finding
	var ts, resolvedAt string
	var downgraded, notified int

	err := sc.Scan(
		&out.Rowid,
		&f.EventID, &ts, &f.SourceType, &f.SourceName,
		&f.SourceIP, &f.DestHost,
		&f.HTTPMethod, &f.HTTPPath,
		&f.HTTPStatus, &f.ResponseBytes, &f.UserAgent,
		&f.Verdict, &f.Classification, &f.Confidence,
		&f.Reason, &f.MatchedVia,
		&f.MatchedPatternScope, &f.MatchedPatternBucket,
		&f.MatchedPatternValue,
		&f.OriginEventID,
		&f.RawLine, &f.NormalizedLine, &f.NormalizedHash,
		&f.EvidenceStatus, &f.EvidenceStatusCode,
		&f.EvidenceContentType, &f.EvidenceBodyHash,
		&f.EvidenceCaptureMode,
		&f.CoordinatorKey, &f.CoordinatorEvents,
		&downgraded, &f.DowngradeReason,
		&notified,
		&f.ResolutionStatus, &resolvedAt,
		&f.ResolutionMethod, &f.PreviousVerdict,
	)
	if err != nil {
		return SyncFinding{}, err
	}

	f.Timestamp, _ = time.Parse(time.RFC3339, ts)
	f.Downgraded = downgraded == 1
	f.Notified = notified == 1
	if resolvedAt != "" {
		if t, perr := time.Parse(time.RFC3339, resolvedAt); perr == nil {
			f.ResolvedAt = &t
		}
	}
	out.F = f
	return out, nil
}

// scanSyncDecision reads one full llm_decisions row. Column order must match
// decisionTransportColumns exactly.
func scanSyncDecision(sc rowScanner) (LLMDecision, error) {
	var d LLMDecision
	var ts string
	var patternLearned, escalated, downgraded, notified, patternDeleted int

	err := sc.Scan(
		&d.ID,
		&d.EventID, &ts, &d.Tier, &d.Model, &d.ReasoningEffort,
		&d.PromptTokens, &d.CompletionTokens, &d.LatencyMs,
		&d.SourceScope, &d.RawLine,
		&d.NormalizedLine, &d.NormalizedHash,
		&d.EvidencePreview, &d.EvidenceStatus,
		&d.EvidenceType, &d.EvidenceHash,
		&d.LLMResponseRaw, &d.Classification, &d.Action,
		&d.Confidence, &d.Reason,
		&d.PatternType, &d.PatternValue, &d.SourceHint,
		&patternLearned, &d.PatternBucket, &d.CacheKey,
		&d.FinalVerdict,
		&escalated, &downgraded, &d.FindingID,
		&notified,
		&d.PromptVersion, &d.CodeVersion,
		&d.ReviewStatus, &d.ReviewedBy, &d.ReviewedAt,
		&d.ReviewerVerdict, &d.ReviewerReason,
		&patternDeleted, &d.ReplacementPattern,
	)
	if err != nil {
		return LLMDecision{}, err
	}

	d.Timestamp, _ = time.Parse(time.RFC3339, ts)
	d.PatternLearned = patternLearned == 1
	d.Escalated = escalated == 1
	d.Downgraded = downgraded == 1
	d.Notified = notified == 1
	d.PatternDeleted = patternDeleted == 1
	return d, nil
}

// ListFindingsAfterIDFull returns full findings rows with rowid > afterRowid,
// ascending. This is the cursor lane's only reader.
func (s *Store) ListFindingsAfterIDFull(ctx context.Context, afterRowid int64, limit int) ([]SyncFinding, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+findingTransportColumns+`
		FROM findings WHERE id > ? ORDER BY id ASC LIMIT ?`, afterRowid, limit)
	if err != nil {
		return nil, fmt.Errorf("list findings after %d: %w", afterRowid, err)
	}
	defer rows.Close()

	var out []SyncFinding
	for rows.Next() {
		sf, err := scanSyncFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding after %d: %w", afterRowid, err)
		}
		out = append(out, sf)
	}
	return out, rows.Err()
}

// LatestFindingForEventIDFull returns the NEWEST findings row for an event ID.
//
// [A2/A9] "Newest only" is load-bearing: an event can accumulate several rows
// (original classification, then a resolution write that inserts rather than
// updates). The hosted upsert keys on (instance, event_id), so replaying an
// older row would regress the mirror. The dirty lane must never send history.
//
// Returns (0, nil, nil) when the event has no rows left locally - a pruned
// event whose journal entry is satisfied by the prune.
func (s *Store) LatestFindingForEventIDFull(ctx context.Context, eventID string) (int64, *Finding, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+findingTransportColumns+`
		FROM findings WHERE event_id = ? ORDER BY id DESC LIMIT 1`, eventID)

	sf, err := scanSyncFinding(row)
	if err == sql.ErrNoRows {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, fmt.Errorf("latest finding for %s: %w", eventID, err)
	}
	f := sf.F
	return sf.Rowid, &f, nil
}

// ListDecisionsAfterIDFull returns full llm_decisions rows with id >
// afterRowid, ascending. For decisions the rowid IS the hosted key, so no
// separate cursor field is needed.
func (s *Store) ListDecisionsAfterIDFull(ctx context.Context, afterRowid int64, limit int) ([]LLMDecision, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+decisionTransportColumns+`
		FROM llm_decisions WHERE id > ? ORDER BY id ASC LIMIT ?`, afterRowid, limit)
	if err != nil {
		return nil, fmt.Errorf("list decisions after %d: %w", afterRowid, err)
	}
	defer rows.Close()

	var out []LLMDecision
	for rows.Next() {
		d, err := scanSyncDecision(rows)
		if err != nil {
			return nil, fmt.Errorf("scan decision after %d: %w", afterRowid, err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetDecisionByIDFull returns one full llm_decisions row, or (nil, nil) when
// the decision has been pruned locally.
func (s *Store) GetDecisionByIDFull(ctx context.Context, id int64) (*LLMDecision, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+decisionTransportColumns+`
		FROM llm_decisions WHERE id = ?`, id)

	d, err := scanSyncDecision(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get decision %d: %w", id, err)
	}
	return &d, nil
}
