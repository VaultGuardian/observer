// internal/store/expected_endpoint_store.go
package store

import (
	"context"
	"fmt"
	"log"
	"time"
)

// =============================================================================
// Expected Endpoint Store — Persistent storage for Option 4 corrections
// =============================================================================
//
// Operator-confirmed "this endpoint is supposed to return sensitive-looking
// data" rules. Path-scoped so operators teach Observer the truth about
// specific auth/token/reset endpoints without globally whitelisting every
// token-shaped response on the host.
//
// =============================================================================
// Key semantics
// =============================================================================
//
// PRIMARY KEY: (host, http_method, http_path, http_status, body_preview_hash)
//
// IMPORTANT: body_preview_hash here is the REDACTED response-shape hash
// (rec.HashBody(SafeBodyPreview), surfaced as decision.CacheKey), NOT the
// raw transport body hash. Storing the raw hash here would break the entire
// feature for auth/token endpoints — every login produces a new token, so
// every login produces a new raw hash, so the rule would only match the one
// specific token string the operator clicked on. The redacted shape hash is
// stable across rotations because the redactor replaces secret values with
// markers like [REDACTED:token] before hashing.
//
// http_status is part of the key: cheap
// guard against e.g. a 200 expected-token response and a 401 error with
// similar body shape collapsing into the same row.
//
// Multiple body hashes per (host, method, path, status): each operator click
// broadens the legitimate-response surface for that endpoint. Admin vs user,
// paginated, role-flagged responses each get their own row.
//
// Architectural distinction:
//
//   catchall_verified_v2  — emergent, statistical, path-agnostic
//                           Threshold of 5+ distinct paths sharing the same
//                           body hash before verification runs.
//
//   expected_endpoints    — explicit, deterministic, path-scoped
//                           Single operator click = single rule. The human
//                           IS the verification.

// ExpectedEndpoint represents one operator-confirmed "this endpoint's response
// is expected to look sensitive" rule. DTO — the coordinator's in-memory
// tracker maps to/from this for hot-path lookups.
type ExpectedEndpoint struct {
	Host             string
	HTTPMethod       string
	HTTPPath         string
	HTTPStatus       int
	BodyPreviewHash  string // REDACTED response-shape hash; NEVER raw transport hash
	CreatedAt        time.Time
	CreatedByEventID string // finding event_id that triggered the click — audit trail
	Description      string // human-supplied reason ("captain login returns auth token by design")
}

// SaveExpectedEndpoint persists a new operator-confirmed expected endpoint.
// UPSERT on the full key tuple so repeated clicks on the same response are
// idempotent — no row duplication, but description/created_at refresh.
func (s *Store) SaveExpectedEndpoint(ctx context.Context, ee *ExpectedEndpoint) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO expected_endpoints (
			host, http_method, http_path, http_status, body_preview_hash,
			created_at, created_by_event_id, description
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host, http_method, http_path, http_status, body_preview_hash)
		DO UPDATE SET
			created_at = excluded.created_at,
			created_by_event_id = excluded.created_by_event_id,
			description = excluded.description`,
		ee.Host, ee.HTTPMethod, ee.HTTPPath, ee.HTTPStatus, ee.BodyPreviewHash,
		ee.CreatedAt.Format(time.RFC3339), ee.CreatedByEventID, ee.Description,
	)
	if err != nil {
		return fmt.Errorf("save expected endpoint: %w", err)
	}
	return nil
}

// LoadExpectedEndpoints returns all expected endpoint rules for startup
// seeding into the in-memory tracker.
func (s *Store) LoadExpectedEndpoints(ctx context.Context) ([]ExpectedEndpoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT host, http_method, http_path, http_status, body_preview_hash,
		       created_at, created_by_event_id, description
		FROM expected_endpoints
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("load expected endpoints: %w", err)
	}
	defer rows.Close()

	var rules []ExpectedEndpoint
	for rows.Next() {
		var ee ExpectedEndpoint
		var createdAt string
		if err := rows.Scan(
			&ee.Host, &ee.HTTPMethod, &ee.HTTPPath, &ee.HTTPStatus, &ee.BodyPreviewHash,
			&createdAt, &ee.CreatedByEventID, &ee.Description,
		); err != nil {
			return nil, fmt.Errorf("scan expected endpoint: %w", err)
		}
		ee.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		rules = append(rules, ee)
	}

	if len(rules) > 0 {
		log.Printf("[store] Loaded %d expected endpoint rules", len(rules))
	}
	return rules, rows.Err()
}

// DeleteExpectedEndpoint removes a specific rule by full key tuple. Not yet
// exposed via /api/* in v1.0 — present for future pattern-review UI work
// (Drew's note: "a year from now an endpoint might accumulate dozens of stale
// shapes from app versions that no longer exist; pattern-review UI can let
// operators prune them. v1.x problem.").
func (s *Store) DeleteExpectedEndpoint(ctx context.Context, host, method string, status int, path, bodyPreviewHash string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM expected_endpoints
		 WHERE host = ? AND http_method = ? AND http_path = ?
		   AND http_status = ? AND body_preview_hash = ?`,
		host, method, path, status, bodyPreviewHash)
	if err != nil {
		return fmt.Errorf("delete expected endpoint: %w", err)
	}
	return nil
}
