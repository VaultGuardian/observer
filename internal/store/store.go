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
	db   *sql.DB
	path string
}

// Init opens (or creates) the SQLite database at dataDir/observer.db,
// applies pragmas, runs migrations, and returns a ready Store.
func Init(dataDir string) (*Store, error) {
	dbPath := filepath.Join(dataDir, "observer.db")

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
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

// Close closes the database connection.
func (s *Store) Close() error {
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
				deny_count INTEGER,
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
//   - deny/alert/malicious: never auto-pruned (security record)
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