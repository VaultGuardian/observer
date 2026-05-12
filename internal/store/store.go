// internal/store/store.go
package store

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps a SQLite database for security findings, scanner sessions,
// and pipeline telemetry. Journald stays for operational logs (startup,
// debug, sniffer traces). SQLite is for structured security data.
//
// Architecture decision (2026-03-24 design team):
//   - Journald for ops, SQLite for findings
//   - WAL mode for concurrent reads + single writer
//   - Pure Go driver (modernc.org/sqlite) — no CGO, single binary preserved
//   - Package-level convenience via global, struct-backed internally
type Store struct {
	db          *sql.DB
	path        string
	asyncWriter *FindingsWriter // Fix 3: async writer for high-volume findings
}

// Init opens (or creates) the SQLite database at dataDir/observer.db,
// applies pragmas, runs migrations, and returns a ready Store.
func Init(dataDir string) (*Store, error) {
	dbPath := filepath.Join(dataDir, "observer.db")

	// Ensure data directory exists. 0700 (owner-only) — Observer's data
	// includes raw logs, evidence body previews, LLM decisions, and learned
	// patterns. Treat as sensitive security telemetry, not world-readable.
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Open with pragmas in DSN (modernc.org/sqlite supports _pragma=)
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate",
		dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Conservative pool: SQLite is single-writer, so keep it tight.
	// Multiple readers are fine in WAL mode.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)

	// Verify connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	s := &Store{db: db, path: dbPath}

	// Run migrations
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	log.Printf("[store] SQLite initialized: %s", dbPath)
	return s, nil
}

// Close closes the database connection and stops the async writer.
func (s *Store) Close() error {
	if s.asyncWriter != nil {
		s.asyncWriter.Stop()
	}
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// DB returns the underlying *sql.DB for advanced queries.
// Use sparingly — prefer the typed methods.
func (s *Store) DB() *sql.DB {
	return s.db
}

// StartAsyncWriter creates and starts the background findings writer.
// Fix 3: under DDoS scanner flood, synchronous INSERTs for recon_failed
// events choke the pipeline. The async writer batches INSERTs and drops
// only recon/noise if the channel is full.
func (s *Store) StartAsyncWriter(ctx context.Context, bufSize int) {
	if bufSize <= 0 {
		bufSize = 5000
	}
	s.asyncWriter = NewFindingsWriter(s, bufSize)
	go s.asyncWriter.Run(ctx)
	log.Printf("[store] Async findings writer started (buffer=%d)", bufSize)
}

// SubmitFinding sends a finding to the async writer for batched INSERT.
// If the async writer isn't running, falls back to synchronous INSERT.
//
// Priority rules (Fix 3, the team mandate):
//   - Recon/allow/suppress findings: dropped if channel full (DDoS safety valve)
//   - Malicious/alert/policy/escalated/downgraded: NEVER dropped, blocks if needed
func (s *Store) SubmitFinding(f *Finding) {
	if s.asyncWriter == nil {
		// Fallback to sync
		s.RecordFinding(context.Background(), f)
		return
	}
	s.asyncWriter.Submit(f)
}

// AsyncWriterStats returns the async writer's drop count for telemetry.
func (s *Store) AsyncWriterStats() int64 {
	if s.asyncWriter == nil {
		return 0
	}
	return s.asyncWriter.Dropped()
}

// migrate runs all schema migrations. Uses a simple version table
// to track which migrations have been applied.
func (s *Store) migrate() error {
	// Create migration tracking table
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL DEFAULT (datetime('now'))
	)`)
	if err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}

	// Check current version
	var current int
	err = s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current)
	if err != nil {
		return fmt.Errorf("check schema version: %w", err)
	}

	migrations := []struct {
		version int
		sql     string
		desc    string
	}{
		{
			version: 1,
			desc:    "findings table",
			sql: `CREATE TABLE IF NOT EXISTS findings (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				event_id TEXT NOT NULL,
				timestamp TEXT NOT NULL,
				source_type TEXT NOT NULL,
				source_name TEXT NOT NULL,

				source_ip TEXT,
				dest_host TEXT,
				http_method TEXT,
				http_path TEXT,
				http_status INTEGER,
				user_agent TEXT,

				verdict TEXT NOT NULL,
				classification TEXT,
				confidence REAL,
				reason TEXT,
				matched_via TEXT,

				raw_line TEXT,
				normalized_line TEXT,
				normalized_hash TEXT,

				evidence_status TEXT,
				evidence_status_code INTEGER,
				evidence_content_type TEXT,
				evidence_body_hash TEXT,
				evidence_capture_mode TEXT,

				coordinator_key TEXT,
				coordinator_events INTEGER,
				downgraded INTEGER DEFAULT 0,
				downgrade_reason TEXT,

				notified INTEGER DEFAULT 0,

				created_at TEXT NOT NULL DEFAULT (datetime('now'))
			);

			CREATE INDEX IF NOT EXISTS idx_findings_source_ip ON findings(source_ip);
			CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp);
			CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
			CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(normalized_hash);
			CREATE INDEX IF NOT EXISTS idx_findings_event_id ON findings(event_id);`,
		},
		{
			version: 2,
			desc:    "scanner_sessions table",
			sql: `CREATE TABLE IF NOT EXISTS scanner_sessions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				source_ip TEXT NOT NULL,
				target_app TEXT NOT NULL,
				body_hash TEXT,
				first_seen TEXT NOT NULL,
				last_seen TEXT NOT NULL,
				probe_count INTEGER DEFAULT 1,
				sample_paths TEXT,
				verdict TEXT,
				notified INTEGER DEFAULT 0,

				created_at TEXT NOT NULL DEFAULT (datetime('now'))
			);

			CREATE INDEX IF NOT EXISTS idx_scanner_source_ip ON scanner_sessions(source_ip);
			CREATE INDEX IF NOT EXISTS idx_scanner_last_seen ON scanner_sessions(last_seen);`,
		},
		{
			version: 3,
			desc:    "pipeline_stats table",
			sql: `CREATE TABLE IF NOT EXISTS pipeline_stats (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TEXT NOT NULL,
				processed INTEGER,
				pattern_hits INTEGER,
				noise_suppressed INTEGER,
				llm_calls INTEGER,
				llm_errors INTEGER,
				patterns_learned INTEGER,
				malicious_count INTEGER,
				alert_count INTEGER,
				suppress_count INTEGER
			);

			CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON pipeline_stats(timestamp);`,
		},
		{
			version: 4,
			desc:    "add response_bytes to findings",
			sql:     `ALTER TABLE findings ADD COLUMN response_bytes INTEGER DEFAULT 0;`,
		},
		{
			version: 5,
			desc:    "catchall_verified table",
			sql: `CREATE TABLE IF NOT EXISTS catchall_verified (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				host TEXT NOT NULL,
				http_method TEXT NOT NULL,
				http_status INTEGER NOT NULL,
				response_bytes INTEGER NOT NULL,
				verified_at TEXT NOT NULL,
				sample_path TEXT,
				content_type TEXT,
				body_hash TEXT,
				verification_verdict TEXT NOT NULL,
				verification_reason TEXT,
				created_at TEXT NOT NULL DEFAULT (datetime('now')),

				UNIQUE(host, http_method, http_status, response_bytes)
			);`,
		},
		{
			version: 6,
			desc:    "llm_decisions audit trail",
			sql: `CREATE TABLE IF NOT EXISTS llm_decisions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,

				-- Call metadata
				event_id TEXT,
				timestamp TEXT NOT NULL,
				tier TEXT NOT NULL,
				model TEXT NOT NULL,
				reasoning_effort TEXT,
				prompt_tokens INTEGER,
				completion_tokens INTEGER,
				latency_ms INTEGER,

				-- Input context
				source_scope TEXT,
				raw_line TEXT,
				normalized_line TEXT,
				normalized_hash TEXT,
				evidence_preview TEXT,
				evidence_status_code INTEGER,
				evidence_content_type TEXT,
				evidence_body_hash TEXT,

				-- LLM output (immutable)
				llm_response_raw TEXT,
				classification TEXT,
				action TEXT,
				confidence REAL,
				reason TEXT,
				pattern_type TEXT,
				pattern_value TEXT,
				source_hint TEXT,

				-- What Observer did with it
				pattern_learned INTEGER DEFAULT 0,
				pattern_bucket TEXT,
				cache_key TEXT,
				final_verdict TEXT,
				escalated INTEGER DEFAULT 0,
				downgraded INTEGER DEFAULT 0,
				finding_id TEXT,
				notified INTEGER DEFAULT 0,

				-- Prompt/model versioning
				prompt_version TEXT,
				code_version TEXT,

				-- Human review (gold layer)
				review_status TEXT DEFAULT 'pending',
				reviewed_by TEXT,
				reviewed_at TEXT,
				reviewer_verdict TEXT,
				reviewer_reason TEXT,
				pattern_deleted INTEGER DEFAULT 0,
				replacement_pattern TEXT,

				created_at TEXT NOT NULL DEFAULT (datetime('now'))
			);

			CREATE INDEX IF NOT EXISTS idx_llm_decisions_timestamp ON llm_decisions(timestamp);
			CREATE INDEX IF NOT EXISTS idx_llm_decisions_tier ON llm_decisions(tier);
			CREATE INDEX IF NOT EXISTS idx_llm_decisions_classification ON llm_decisions(classification);
			CREATE INDEX IF NOT EXISTS idx_llm_decisions_review_status ON llm_decisions(review_status);
			CREATE INDEX IF NOT EXISTS idx_llm_decisions_event_id ON llm_decisions(event_id);
			CREATE INDEX IF NOT EXISTS idx_llm_decisions_source_scope ON llm_decisions(source_scope);
			CREATE INDEX IF NOT EXISTS idx_llm_decisions_cache_key ON llm_decisions(cache_key);`,
		},
		{
			version: 7,
			desc:    "trusted_ips table for policy engine allowlist",
			sql: `CREATE TABLE IF NOT EXISTS trusted_ips (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip_address TEXT,
				cidr TEXT,
				description TEXT NOT NULL DEFAULT '',
				added_by TEXT NOT NULL DEFAULT 'api',
				created_at TEXT NOT NULL DEFAULT (datetime('now'))
			);

			CREATE INDEX IF NOT EXISTS idx_trusted_ips_address ON trusted_ips(ip_address);
			CREATE INDEX IF NOT EXISTS idx_trusted_ips_cidr ON trusted_ips(cidr);`,
		},
		// =====================================================================
		// v1.0 HARDENING MIGRATIONS
		// =====================================================================
		{
			version: 8,
			desc:    "Fix 4: resolution lifecycle columns on findings",
			sql: `ALTER TABLE findings ADD COLUMN resolution_status TEXT DEFAULT '';
			ALTER TABLE findings ADD COLUMN resolved_at TEXT DEFAULT '';
			ALTER TABLE findings ADD COLUMN resolution_method TEXT DEFAULT '';
			ALTER TABLE findings ADD COLUMN previous_verdict TEXT DEFAULT '';

			CREATE INDEX IF NOT EXISTS idx_findings_resolution ON findings(resolution_status);`,
		},
		{
			version: 9,
			desc:    "Fix 2: catchall_verified_v2 with body_preview_hash instead of response_bytes",
			sql: `CREATE TABLE IF NOT EXISTS catchall_verified_v2 (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				host TEXT NOT NULL,
				http_method TEXT NOT NULL,
				http_status INTEGER NOT NULL,
				body_preview_hash TEXT NOT NULL,
				verified_at TEXT NOT NULL,
				sample_path TEXT,
				content_type TEXT,
				body_hash TEXT,
				verification_verdict TEXT NOT NULL,
				verification_reason TEXT,
				created_at TEXT NOT NULL DEFAULT (datetime('now')),

				UNIQUE(host, http_method, http_status, body_preview_hash)
			);`,
		},
		{
			version: 10,
			desc:    "pattern match fields on findings for dashboard delete support",
			sql: `ALTER TABLE findings ADD COLUMN matched_pattern_scope TEXT DEFAULT '';
				  ALTER TABLE findings ADD COLUMN matched_pattern_bucket TEXT DEFAULT '';
				  ALTER TABLE findings ADD COLUMN matched_pattern_value TEXT DEFAULT '';`,
		},
		{
			// Section 3 / Landmine A (v1.0 hardening): the design review catch.
			// CheckFallbackByBytes was suppressing ANY response under 10KB on
			// a (host, method, status) tuple if any verified entry existed,
			// regardless of the verified entry's actual response size. We now
			// store response_bytes at verification time and require log
			// responseBytes to be byte-similar to it before suppressing.
			//
			// Existing rows get response_bytes=0 by default. The runtime
			// fallback skips byte-compatible matching when the stored value
			// is <=0 (conservative — re-verifies before suppressing).
			version: 11,
			desc:    "Section 3 / Landmine A: response_bytes on catchall_verified_v2 for byte-similarity check",
			sql:     `ALTER TABLE catchall_verified_v2 ADD COLUMN response_bytes INTEGER DEFAULT 0;`,
		},
		{
			// v1.0 pre-launch — Correction Dialog Redesign, Card 4
			// ("Expected sensitive response"). Path-scoped operator
			// confirmations that an endpoint's response is supposed to look
			// sensitive (login/token/reset/OAuth). Cannot reuse the CatchAll
			// subsystem because CatchAll requires multiple paths sharing the
			// same body hash before verification fires — a single login
			// endpoint would never reach the threshold.
			//
			// Architectural distinction (the design review mandate, May 11 2026):
			//   catchall_verified_v2  — emergent, statistical, path-agnostic
			//   expected_endpoints    — explicit, deterministic, path-scoped
			//
			// Key: (host, http_method, http_path, http_status, body_preview_hash)
			//
			// body_preview_hash is the REDACTED response-shape hash
			// (rec.HashBody(SafeBodyPreview), surfaced as decision.CacheKey).
			// NEVER the raw transport hash — that would break the feature for
			// auth/token endpoints with rotating values. (code review P0 catch +
			// design lock-in, May 11 2026.)
			//
			// http_status is part of the key (code review P1, locked May 11 2026):
			// cheap guard against 200/401/500 responses with similar body
			// shapes collapsing into the same row.
			version: 12,
			desc:    "v1.0 Card 4: expected_endpoints for path-scoped operator confirmations",
			sql: `CREATE TABLE IF NOT EXISTS expected_endpoints (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				host TEXT NOT NULL,
				http_method TEXT NOT NULL,
				http_path TEXT NOT NULL,
				http_status INTEGER NOT NULL,
				body_preview_hash TEXT NOT NULL,
				created_at TEXT NOT NULL,
				created_by_event_id TEXT NOT NULL DEFAULT '',
				description TEXT NOT NULL DEFAULT '',

				UNIQUE(host, http_method, http_path, http_status, body_preview_hash)
			);

			CREATE INDEX IF NOT EXISTS idx_expected_endpoints_lookup
				ON expected_endpoints(host, http_method, http_path, http_status);`,
		},
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if _, err := s.db.Exec(m.sql); err != nil {
			return fmt.Errorf("migration v%d (%s): %w", m.version, m.desc, err)
		}
		if _, err := s.db.Exec("INSERT INTO schema_version (version) VALUES (?)", m.version); err != nil {
			return fmt.Errorf("record migration v%d: %w", m.version, err)
		}
		log.Printf("[store] Applied migration v%d: %s", m.version, m.desc)
	}

	return nil
}

// Prune removes old findings based on verdict-specific retention policies.
// Call periodically from a background goroutine.
//
// Retention (design team agreed, 2026-03-24):
//   - allow/suppress: 7 days (high volume, low value)
//   - recon/downgrade: 90 days (useful for trend analysis)
//   - malicious/alert/malicious: never auto-pruned (security record)
//   - pipeline_stats: 90 days
func (s *Store) Prune(ctx context.Context) error {
	cutoff7d := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	cutoff90d := time.Now().AddDate(0, 0, -90).Format(time.RFC3339)

	queries := []struct {
		desc string
		sql  string
		arg  string
	}{
		{"allow/suppress findings >7d", "DELETE FROM findings WHERE verdict IN ('allow', 'suppress') AND timestamp < ?", cutoff7d},
		{"recon/downgraded findings >90d", "DELETE FROM findings WHERE (verdict = 'recon' OR downgraded = 1) AND timestamp < ?", cutoff90d},
		{"scanner sessions >90d", "DELETE FROM scanner_sessions WHERE last_seen < ?", cutoff90d},
		{"pipeline stats >90d", "DELETE FROM pipeline_stats WHERE timestamp < ?", cutoff90d},
		{"unreviewed LLM decisions >7d", "DELETE FROM llm_decisions WHERE review_status = 'pending' AND timestamp < ?", cutoff7d},
	}

	for _, q := range queries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		result, err := s.db.ExecContext(ctx, q.sql, q.arg)
		if err != nil {
			log.Printf("[store] Prune %s error: %v", q.desc, err)
			continue
		}
		if rows, _ := result.RowsAffected(); rows > 0 {
			log.Printf("[store] Pruned %d rows: %s", rows, q.desc)
		}
	}
	return nil
}