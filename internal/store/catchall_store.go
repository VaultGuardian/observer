package store

import (
	"context"
	"fmt"
	"log"
	"time"
)

// CatchAllRule represents a verified catch-all fingerprint persisted to SQLite.
// This is a DTO — the coordinator maps it to/from its internal types.
type CatchAllRule struct {
	Host                string
	HTTPMethod          string
	HTTPStatus          int
	ResponseBytes       int64
	VerifiedAt          time.Time
	SamplePath          string
	ContentType         string
	BodyHash            string
	VerificationVerdict string
	VerificationReason  string
}

// SaveVerifiedCatchAll persists a newly verified catch-all rule.
// Upserts on (host, http_method, http_status, response_bytes) to avoid duplicates.
func (s *Store) SaveVerifiedCatchAll(ctx context.Context, rule *CatchAllRule) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO catchall_verified (
			host, http_method, http_status, response_bytes,
			verified_at, sample_path, content_type, body_hash,
			verification_verdict, verification_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, http_method, http_status, response_bytes)
		DO UPDATE SET
			verified_at = excluded.verified_at,
			sample_path = excluded.sample_path,
			content_type = excluded.content_type,
			body_hash = excluded.body_hash,
			verification_verdict = excluded.verification_verdict,
			verification_reason = excluded.verification_reason`,
		rule.Host, rule.HTTPMethod, rule.HTTPStatus, rule.ResponseBytes,
		rule.VerifiedAt.Format(time.RFC3339), rule.SamplePath,
		rule.ContentType, rule.BodyHash,
		rule.VerificationVerdict, rule.VerificationReason,
	)
	if err != nil {
		return fmt.Errorf("save verified catch-all: %w", err)
	}
	return nil
}

// LoadVerifiedCatchAlls returns all verified catch-all rules for startup seeding.
func (s *Store) LoadVerifiedCatchAlls(ctx context.Context) ([]CatchAllRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, http_method, http_status, response_bytes,
		       verified_at, sample_path, content_type, body_hash,
		       verification_verdict, verification_reason
		FROM catchall_verified
		WHERE verification_verdict = 'benign'
		ORDER BY verified_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("load catch-all rules: %w", err)
	}
	defer rows.Close()

	var rules []CatchAllRule
	for rows.Next() {
		var r CatchAllRule
		var verifiedAt string
		if err := rows.Scan(
			&r.Host, &r.HTTPMethod, &r.HTTPStatus, &r.ResponseBytes,
			&verifiedAt, &r.SamplePath, &r.ContentType, &r.BodyHash,
			&r.VerificationVerdict, &r.VerificationReason,
		); err != nil {
			return nil, fmt.Errorf("scan catch-all rule: %w", err)
		}
		r.VerifiedAt, _ = time.Parse(time.RFC3339, verifiedAt)
		rules = append(rules, r)
	}

	if len(rules) > 0 {
		log.Printf("[store] Loaded %d verified catch-all rules", len(rules))
	}
	return rules, rows.Err()
}

// DeleteVerifiedCatchAll removes a verified rule (e.g. if admin wants to re-verify).
func (s *Store) DeleteVerifiedCatchAll(ctx context.Context, host, method string, status int, bytes int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM catchall_verified WHERE host = ? AND http_method = ? AND http_status = ? AND response_bytes = ?`,
		host, method, status, bytes)
	if err != nil {
		return fmt.Errorf("delete catch-all rule: %w", err)
	}
	return nil
}