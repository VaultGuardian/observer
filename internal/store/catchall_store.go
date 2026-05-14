// internal/store/catchall_store.go
package store

import (
	"context"
	"fmt"
	"log"
	"time"
)

// CatchAllRule represents a verified catch-all fingerprint persisted to SQLite.
// This is a DTO — the coordinator maps it to/from its internal types.
//
// Fix 2 (v1.0 hardening): Fingerprint key changed from ResponseBytes to
// BodyPreviewHash (SHA-256). Prevents "accordion padding" attack where
// attacker varies query params to change response size and trick the
// catch-all into auto-downgrading real data exfiltration.
//
// Section 3 / Landmine A (v1.0 hardening, the design review catch): ResponseBytes added
// back as a non-key descriptive field so the Phase 3 fallback can compare
// access-log byte counts against the actual verified body size. The
// fingerprint is still keyed on body_preview_hash; response_bytes is purely
// for byte-similarity gating in the fallback path.
type CatchAllRule struct {
	Host                string
	HTTPMethod          string
	HTTPStatus          int
	BodyPreviewHash     string // SHA-256 of redacted response body — fingerprint key
	VerifiedAt          time.Time
	SamplePath          string
	ContentType         string
	BodyHash            string // verification body hash (may differ from fingerprint hash)
	VerificationVerdict string
	VerificationReason  string
	ResponseBytes       int64 // total response size at verification (Section 3 / Landmine A)
}

// SaveVerifiedCatchAll persists a newly verified catch-all rule.
// Upserts on (host, http_method, http_status, body_preview_hash) to avoid duplicates.
func (s *Store) SaveVerifiedCatchAll(ctx context.Context, rule *CatchAllRule) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO catchall_verified_v2 (
			host, http_method, http_status, body_preview_hash,
			verified_at, sample_path, content_type, body_hash,
			verification_verdict, verification_reason, response_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, http_method, http_status, body_preview_hash)
		DO UPDATE SET
			verified_at = excluded.verified_at,
			sample_path = excluded.sample_path,
			content_type = excluded.content_type,
			body_hash = excluded.body_hash,
			verification_verdict = excluded.verification_verdict,
			verification_reason = excluded.verification_reason,
			response_bytes = excluded.response_bytes`,
		rule.Host, rule.HTTPMethod, rule.HTTPStatus, rule.BodyPreviewHash,
		rule.VerifiedAt.Format(time.RFC3339), rule.SamplePath,
		rule.ContentType, rule.BodyHash,
		rule.VerificationVerdict, rule.VerificationReason, rule.ResponseBytes,
	)
	if err != nil {
		return fmt.Errorf("save verified catch-all: %w", err)
	}
	return nil
}

// LoadVerifiedCatchAlls returns all verified catch-all rules for startup seeding.
func (s *Store) LoadVerifiedCatchAlls(ctx context.Context) ([]CatchAllRule, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, http_method, http_status, body_preview_hash,
		       verified_at, sample_path, content_type, body_hash,
		       verification_verdict, verification_reason,
		       COALESCE(response_bytes, 0)
		FROM catchall_verified_v2
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
			&r.Host, &r.HTTPMethod, &r.HTTPStatus, &r.BodyPreviewHash,
			&verifiedAt, &r.SamplePath, &r.ContentType, &r.BodyHash,
			&r.VerificationVerdict, &r.VerificationReason, &r.ResponseBytes,
		); err != nil {
			return nil, fmt.Errorf("scan catch-all rule: %w", err)
		}
		r.VerifiedAt, _ = time.Parse(time.RFC3339, verifiedAt)
		rules = append(rules, r)
	}

	if len(rules) > 0 {
		log.Printf("[store] Loaded %d verified catch-all rules (v2, body hash keyed, byte-aware)", len(rules))
	}
	return rules, rows.Err()
}

// DeleteVerifiedCatchAll removes a verified rule (e.g. if admin wants to re-verify).
func (s *Store) DeleteVerifiedCatchAll(ctx context.Context, host, method string, status int, bodyPreviewHash string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM catchall_verified_v2 WHERE host = ? AND http_method = ? AND http_status = ? AND body_preview_hash = ?`,
		host, method, status, bodyPreviewHash)
	if err != nil {
		return fmt.Errorf("delete catch-all rule: %w", err)
	}
	return nil
}
