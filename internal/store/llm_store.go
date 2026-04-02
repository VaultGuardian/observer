package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

// =============================================================================
// LLM Decision Audit Trail
// =============================================================================
//
// Every LLM call gets recorded here — the input, the output, and what Observer
// did because of it. This is the foundation for:
//
//   1. Surgical corrections — find the bad call, delete the pattern, done
//   2. Blast radius analysis — how many downstream matches did this cause?
//   3. Prompt/model debugging — was this the old nano or the new mini?
//   4. Future fine-tuning — human-corrected decisions become training data
//
// IMMUTABILITY RULE (design consensus):
//   The LLM's original response is NEVER modified. Human corrections are
//   stored as a separate review layer. This preserves the audit trail:
//   what the model said, what the system did, what the human decided.

// LLMDecision records a single LLM call and everything that happened because of it.
type LLMDecision struct {
	// Identity
	ID        int64     `json:"id"`
	EventID   string    `json:"event_id"`
	Timestamp time.Time `json:"timestamp"`

	// Call metadata
	Tier            string `json:"tier"` // "classify", "reclassify", "catchall_verify"
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
	PromptTokens    int    `json:"prompt_tokens"`
	CompletionTokens int   `json:"completion_tokens"`
	LatencyMs       int64  `json:"latency_ms"`

	// Input context
	SourceScope     string `json:"source_scope"`
	RawLine         string `json:"raw_line,omitempty"`
	NormalizedLine  string `json:"normalized_line,omitempty"`
	NormalizedHash  string `json:"normalized_hash,omitempty"`
	EvidencePreview string `json:"evidence_preview,omitempty"` // tier 2 only
	EvidenceStatus  int    `json:"evidence_status_code,omitempty"`
	EvidenceType    string `json:"evidence_content_type,omitempty"`
	EvidenceHash    string `json:"evidence_body_hash,omitempty"`

	// LLM output (immutable — never edit this)
	LLMResponseRaw string  `json:"llm_response_raw"` // full JSON string
	Classification string  `json:"classification"`
	Action         string  `json:"action"`
	Confidence     float64 `json:"confidence"`
	Reason         string  `json:"reason"`
	PatternType    string  `json:"pattern_type,omitempty"`
	PatternValue   string  `json:"pattern_value,omitempty"`
	SourceHint     string  `json:"source_hint,omitempty"`

	// What Observer did with it
	PatternLearned bool   `json:"pattern_learned"`
	PatternBucket  string `json:"pattern_bucket,omitempty"` // allow, deny, alert, suppress
	CacheKey       string `json:"cache_key,omitempty"`      // pattern value (tier1) or body hash (tier2)
	FinalVerdict   string `json:"final_verdict,omitempty"`
	Escalated      bool   `json:"escalated"`
	Downgraded     bool   `json:"downgraded"`
	FindingID      string `json:"finding_id,omitempty"`
	Notified       bool   `json:"notified"`

	// Prompt/model versioning
	PromptVersion string `json:"prompt_version,omitempty"` // hash or label
	CodeVersion   string `json:"code_version,omitempty"`   // Observer version

	// Human review (gold layer — populated later via API)
	ReviewStatus      string `json:"review_status"` // pending, confirmed, corrected, ignored
	ReviewedBy        string `json:"reviewed_by,omitempty"`
	ReviewedAt        string `json:"reviewed_at,omitempty"`
	ReviewerVerdict   string `json:"reviewer_verdict,omitempty"`
	ReviewerReason    string `json:"reviewer_reason,omitempty"`
	PatternDeleted    bool   `json:"pattern_deleted"`
	ReplacementPattern string `json:"replacement_pattern,omitempty"`

	// Derived (not stored, computed on query)
	MatchCount int64 `json:"match_count,omitempty"` // how many pattern hits since learned
}

// RecordLLMDecision inserts a new decision into the audit trail.
func (s *Store) RecordLLMDecision(ctx context.Context, d *LLMDecision) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO llm_decisions (
		event_id, timestamp, tier, model, reasoning_effort,
		prompt_tokens, completion_tokens, latency_ms,
		source_scope, raw_line, normalized_line, normalized_hash,
		evidence_preview, evidence_status_code, evidence_content_type, evidence_body_hash,
		llm_response_raw, classification, action, confidence, reason,
		pattern_type, pattern_value, source_hint,
		pattern_learned, pattern_bucket, cache_key, final_verdict,
		escalated, downgraded, finding_id, notified,
		prompt_version, code_version, review_status
	) VALUES (
		?, ?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?
	)`,
		d.EventID, d.Timestamp.Format(time.RFC3339), d.Tier, d.Model, d.ReasoningEffort,
		d.PromptTokens, d.CompletionTokens, d.LatencyMs,
		d.SourceScope, d.RawLine, d.NormalizedLine, d.NormalizedHash,
		d.EvidencePreview, d.EvidenceStatus, d.EvidenceType, d.EvidenceHash,
		d.LLMResponseRaw, d.Classification, d.Action, d.Confidence, d.Reason,
		d.PatternType, d.PatternValue, d.SourceHint,
		boolToInt(d.PatternLearned), d.PatternBucket, d.CacheKey, d.FinalVerdict,
		boolToInt(d.Escalated), boolToInt(d.Downgraded), d.FindingID, boolToInt(d.Notified),
		d.PromptVersion, d.CodeVersion, "pending",
	)
	if err != nil {
		log.Printf("[store] Failed to record LLM decision: %v", err)
	}
	return err
}

// LLMDecisionFilter holds query parameters for listing decisions.
type LLMDecisionFilter struct {
	Tier           string // "classify", "reclassify", "catchall_verify"
	Classification string
	ReviewStatus   string // "pending", "confirmed", "corrected", "ignored"
	MinConfidence  float64
	MaxConfidence  float64
	SourceScope    string
	Since          time.Time
	Limit          int
	Offset         int
}

// ListLLMDecisions queries decisions with optional filters.
func (s *Store) ListLLMDecisions(ctx context.Context, f LLMDecisionFilter) ([]LLMDecision, error) {
	query := `SELECT
		id, event_id, timestamp, tier, model, reasoning_effort,
		prompt_tokens, completion_tokens, latency_ms,
		source_scope, raw_line, normalized_line, normalized_hash,
		evidence_preview, evidence_status_code, evidence_content_type, evidence_body_hash,
		llm_response_raw, classification, action, confidence, reason,
		pattern_type, pattern_value, source_hint,
		pattern_learned, pattern_bucket, cache_key, final_verdict,
		escalated, downgraded, finding_id, notified,
		prompt_version, code_version,
		review_status, reviewed_by, reviewed_at, reviewer_verdict, reviewer_reason,
		pattern_deleted, replacement_pattern
	FROM llm_decisions WHERE 1=1`

	args := []interface{}{}

	if f.Tier != "" {
		query += " AND tier = ?"
		args = append(args, f.Tier)
	}
	if f.Classification != "" {
		query += " AND classification = ?"
		args = append(args, f.Classification)
	}
	if f.ReviewStatus != "" {
		query += " AND review_status = ?"
		args = append(args, f.ReviewStatus)
	}
	if f.MinConfidence > 0 {
		query += " AND confidence >= ?"
		args = append(args, f.MinConfidence)
	}
	if f.MaxConfidence > 0 {
		query += " AND confidence <= ?"
		args = append(args, f.MaxConfidence)
	}
	if f.SourceScope != "" {
		query += " AND source_scope LIKE ?"
		args = append(args, "%"+f.SourceScope+"%")
	}
	if !f.Since.IsZero() {
		query += " AND timestamp > ?"
		args = append(args, f.Since.Format(time.RFC3339))
	}

	query += " ORDER BY id DESC"

	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	query += " LIMIT ?"
	args = append(args, f.Limit)

	if f.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, f.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query llm_decisions: %w", err)
	}
	defer rows.Close()

	var results []LLMDecision
	for rows.Next() {
		var d LLMDecision
		var ts string
		var patternLearned, escalated, downgraded, notified, patternDeleted int
		var reviewedBy, reviewedAt, reviewerVerdict, reviewerReason, replacementPattern sql.NullString
		var evidencePreview, evidenceType, evidenceHash sql.NullString
		var patternType, patternValue, sourceHint sql.NullString
		var patternBucket, cacheKey, finalVerdict, findingID sql.NullString
		var promptVersion, codeVersion sql.NullString

		err := rows.Scan(
			&d.ID, &d.EventID, &ts, &d.Tier, &d.Model, &d.ReasoningEffort,
			&d.PromptTokens, &d.CompletionTokens, &d.LatencyMs,
			&d.SourceScope, &d.RawLine, &d.NormalizedLine, &d.NormalizedHash,
			&evidencePreview, &d.EvidenceStatus, &evidenceType, &evidenceHash,
			&d.LLMResponseRaw, &d.Classification, &d.Action, &d.Confidence, &d.Reason,
			&patternType, &patternValue, &sourceHint,
			&patternLearned, &patternBucket, &cacheKey, &finalVerdict,
			&escalated, &downgraded, &findingID, &notified,
			&promptVersion, &codeVersion,
			&d.ReviewStatus, &reviewedBy, &reviewedAt, &reviewerVerdict, &reviewerReason,
			&patternDeleted, &replacementPattern,
		)
		if err != nil {
			return nil, fmt.Errorf("scan llm_decision: %w", err)
		}

		d.Timestamp, _ = time.Parse(time.RFC3339, ts)
		d.PatternLearned = patternLearned == 1
		d.Escalated = escalated == 1
		d.Downgraded = downgraded == 1
		d.Notified = notified == 1
		d.PatternDeleted = patternDeleted == 1
		d.EvidencePreview = nullStr(evidencePreview)
		d.EvidenceType = nullStr(evidenceType)
		d.EvidenceHash = nullStr(evidenceHash)
		d.PatternType = nullStr(patternType)
		d.PatternValue = nullStr(patternValue)
		d.SourceHint = nullStr(sourceHint)
		d.PatternBucket = nullStr(patternBucket)
		d.CacheKey = nullStr(cacheKey)
		d.FinalVerdict = nullStr(finalVerdict)
		d.FindingID = nullStr(findingID)
		d.PromptVersion = nullStr(promptVersion)
		d.CodeVersion = nullStr(codeVersion)
		d.ReviewedBy = nullStr(reviewedBy)
		d.ReviewedAt = nullStr(reviewedAt)
		d.ReviewerVerdict = nullStr(reviewerVerdict)
		d.ReviewerReason = nullStr(reviewerReason)
		d.ReplacementPattern = nullStr(replacementPattern)

		results = append(results, d)
	}

	return results, rows.Err()
}

// GetLLMDecision returns a single decision by ID.
func (s *Store) GetLLMDecision(ctx context.Context, id int64) (*LLMDecision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT
		id, event_id, timestamp, tier, model, reasoning_effort,
		prompt_tokens, completion_tokens, latency_ms,
		source_scope, raw_line, normalized_line, normalized_hash,
		evidence_preview, evidence_status_code, evidence_content_type, evidence_body_hash,
		llm_response_raw, classification, action, confidence, reason,
		pattern_type, pattern_value, source_hint,
		pattern_learned, pattern_bucket, cache_key, final_verdict,
		escalated, downgraded, finding_id, notified,
		prompt_version, code_version,
		review_status, reviewed_by, reviewed_at, reviewer_verdict, reviewer_reason,
		pattern_deleted, replacement_pattern
	FROM llm_decisions WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, fmt.Errorf("llm_decision %d not found", id)
	}

	var d LLMDecision
	var ts string
	var patternLearned, escalated, downgraded, notified, patternDeleted int
	var reviewedBy, reviewedAt, reviewerVerdict, reviewerReason, replacementPattern sql.NullString
	var evidencePreview, evidenceType, evidenceHash sql.NullString
	var patternType, patternValue, sourceHint sql.NullString
	var patternBucket, cacheKey, finalVerdict, findingID sql.NullString
	var promptVersion, codeVersion sql.NullString

	err = rows.Scan(
		&d.ID, &d.EventID, &ts, &d.Tier, &d.Model, &d.ReasoningEffort,
		&d.PromptTokens, &d.CompletionTokens, &d.LatencyMs,
		&d.SourceScope, &d.RawLine, &d.NormalizedLine, &d.NormalizedHash,
		&evidencePreview, &d.EvidenceStatus, &evidenceType, &evidenceHash,
		&d.LLMResponseRaw, &d.Classification, &d.Action, &d.Confidence, &d.Reason,
		&patternType, &patternValue, &sourceHint,
		&patternLearned, &patternBucket, &cacheKey, &finalVerdict,
		&escalated, &downgraded, &findingID, &notified,
		&promptVersion, &codeVersion,
		&d.ReviewStatus, &reviewedBy, &reviewedAt, &reviewerVerdict, &reviewerReason,
		&patternDeleted, &replacementPattern,
	)
	if err != nil {
		return nil, err
	}

	d.Timestamp, _ = time.Parse(time.RFC3339, ts)
	d.PatternLearned = patternLearned == 1
	d.Escalated = escalated == 1
	d.Downgraded = downgraded == 1
	d.Notified = notified == 1
	d.PatternDeleted = patternDeleted == 1
	d.EvidencePreview = nullStr(evidencePreview)
	d.EvidenceType = nullStr(evidenceType)
	d.EvidenceHash = nullStr(evidenceHash)
	d.PatternType = nullStr(patternType)
	d.PatternValue = nullStr(patternValue)
	d.SourceHint = nullStr(sourceHint)
	d.PatternBucket = nullStr(patternBucket)
	d.CacheKey = nullStr(cacheKey)
	d.FinalVerdict = nullStr(finalVerdict)
	d.FindingID = nullStr(findingID)
	d.PromptVersion = nullStr(promptVersion)
	d.CodeVersion = nullStr(codeVersion)
	d.ReviewedBy = nullStr(reviewedBy)
	d.ReviewedAt = nullStr(reviewedAt)
	d.ReviewerVerdict = nullStr(reviewerVerdict)
	d.ReviewerReason = nullStr(reviewerReason)
	d.ReplacementPattern = nullStr(replacementPattern)

	return &d, nil
}

// UpdateLLMDecisionReview updates the human review fields on a decision.
// The LLM response fields remain immutable.
func (s *Store) UpdateLLMDecisionReview(ctx context.Context, id int64, review LLMReview) error {
	result, err := s.db.ExecContext(ctx, `UPDATE llm_decisions SET
		review_status = ?,
		reviewed_by = ?,
		reviewed_at = ?,
		reviewer_verdict = ?,
		reviewer_reason = ?,
		pattern_deleted = ?,
		replacement_pattern = ?
	WHERE id = ?`,
		review.Status,
		review.ReviewedBy,
		time.Now().Format(time.RFC3339),
		review.Verdict,
		review.Reason,
		boolToInt(review.PatternDeleted),
		review.ReplacementPattern,
		id,
	)
	if err != nil {
		return fmt.Errorf("update review: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("llm_decision %d not found", id)
	}
	return nil
}

// LLMReview is the human correction payload.
type LLMReview struct {
	Status             string `json:"status"`              // confirmed, corrected, ignored
	ReviewedBy         string `json:"reviewed_by"`
	Verdict            string `json:"verdict,omitempty"`    // new verdict if corrected
	Reason             string `json:"reason,omitempty"`     // why the correction was made
	PatternDeleted     bool   `json:"pattern_deleted"`
	ReplacementPattern string `json:"replacement_pattern,omitempty"`
}

// LLMDecisionCounts returns summary counts for the dashboard.
type LLMDecisionCounts struct {
	Total       int64 `json:"total"`
	Pending     int64 `json:"pending"`
	Confirmed   int64 `json:"confirmed"`
	Corrected   int64 `json:"corrected"`
	ByTier      map[string]int64 `json:"by_tier"`
	ByClassification map[string]int64 `json:"by_classification"`
}

// GetLLMDecisionCounts returns summary statistics.
func (s *Store) GetLLMDecisionCounts(ctx context.Context) (*LLMDecisionCounts, error) {
	counts := &LLMDecisionCounts{
		ByTier:           make(map[string]int64),
		ByClassification: make(map[string]int64),
	}

	// Total + review status counts
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_decisions").Scan(&counts.Total)
	if err != nil {
		return nil, err
	}
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_decisions WHERE review_status = 'pending'").Scan(&counts.Pending)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_decisions WHERE review_status = 'confirmed'").Scan(&counts.Confirmed)
	s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM llm_decisions WHERE review_status = 'corrected'").Scan(&counts.Corrected)

	// By tier
	rows, err := s.db.QueryContext(ctx, "SELECT tier, COUNT(*) FROM llm_decisions GROUP BY tier")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var tier string
			var count int64
			rows.Scan(&tier, &count)
			counts.ByTier[tier] = count
		}
	}

	// By classification
	rows2, err := s.db.QueryContext(ctx, "SELECT classification, COUNT(*) FROM llm_decisions GROUP BY classification")
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var cls string
			var count int64
			rows2.Scan(&cls, &count)
			counts.ByClassification[cls] = count
		}
	}

	return counts, nil
}

// PruneLLMDecisions removes old unreviewed decisions.
// Human-reviewed decisions are never auto-pruned — they're the gold dataset.
func (s *Store) PruneLLMDecisions(ctx context.Context, unreviwedTTL time.Duration) error {
	cutoff := time.Now().Add(-unreviwedTTL).Format(time.RFC3339)
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM llm_decisions WHERE review_status = 'pending' AND timestamp < ?",
		cutoff,
	)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("[store] Pruned %d unreviewed LLM decisions older than %s", rows, unreviwedTTL)
	}
	return nil
}

// SerializeLLMResponse converts the parsed verdict fields back to a JSON string
// for storage. Call this when you have the parsed struct but need the raw string.
func SerializeLLMResponse(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Helpers

func nullStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}