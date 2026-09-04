// Package sync mirrors Observer's local SQLite state to a hosted dashboard.
//
// It is strictly additive and ships dark: with SYNC_URL / SYNC_TOKEN unset,
// nothing in this package ever runs. It never participates in classification -
// no verdict, REC, normalizer, or coordinator behavior depends on it, and a
// hosted outage degrades to "the mirror is stale", never to lost local data.
//
// Two lanes, deliberately independent:
//
//	LANE A  cursor + dirty journal → /api/ingest/findings, /api/ingest/decisions
//	        Reads SQLite directly through the canonical full-row transport
//	        scanners. The cursor lane introduces new row versions in ascending
//	        rowid order; the dirty lane re-sends rows mutated in place after
//	        they were already mirrored.
//
//	LANE B  heartbeat + snapshot → /api/ingest/heartbeat, /stats, /snapshot
//	        Reads the LOCAL dashboard API over in-process HTTP so the hosted
//	        mirror sees byte-identical payloads to what the local dashboard
//	        consumed. Handler assembly logic is never reimplemented here.
//
// Progress is only ever recorded against a fully validated acknowledgement:
// cursors advance and journal rows are deleted after the hosted mirror has
// confirmed it accepted exactly what was sent. Anything else is a failure that
// backs off and retries, so the worst case is duplicate sends into an
// idempotent upsert - never a silent gap.
package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	stdsync "sync"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

// ErrRolledBack is returned by New when the local database appears to have
// regressed relative to the recorded sync state. The engine refuses to start.
var ErrRolledBack = errors.New("sync: local database rolled back relative to sync state")

// Config carries everything the engine needs. Built by main.go from the
// process Config; no environment reads happen in this package.
type Config struct {
	// Hosted ingest. BaseURL has no trailing slash; the engine appends
	// /api/ingest/*. Token is the bearer credential and is NEVER logged.
	BaseURL string
	Token   string

	// Cadences.
	Interval          time.Duration // lane A
	SnapshotInterval  time.Duration // lane B snapshot
	HeartbeatInterval time.Duration // lane B heartbeat

	// Local dashboard API, read by lane B.
	//
	// [A10] LocalBaseURL is derived from DASHBOARD_BIND_ADDR: a specific
	// non-loopback bind address is used verbatim, anything else falls back to
	// 127.0.0.1 (0.0.0.0 and :: are wildcards, not reachable addresses).
	// LocalKeyFile is read ONCE at construction - the API server also loads
	// its token once, so re-reading per cycle would desync on file rotation.
	LocalBaseURL string
	LocalKeyFile string
}

// Engine owns the three sync goroutines and their shared HTTP clients.
type Engine struct {
	store *store.Store
	cfg   Config

	client      *http.Client // hosted ingest
	localClient *http.Client // local dashboard API
	localToken  string

	cancel   context.CancelFunc
	wg       stdsync.WaitGroup
	stopOnce stdsync.Once

	// laneBDown / heartbeatDown track lane B health so each goroutine logs
	// state transitions once instead of a line per cycle forever. Each field
	// is touched only by its own goroutine.
	laneBDown     bool
	heartbeatDown bool
}

const (
	defaultInterval          = 15 * time.Second
	defaultSnapshotInterval  = 5 * time.Minute
	defaultHeartbeatInterval = 60 * time.Second

	// maxBackoff caps lane A's exponential retry delay.
	maxBackoff = 5 * time.Minute
)

// LocalBaseURL builds the lane B base URL from the dashboard bind address and
// port. [A10] A wildcard or empty bind address means "listening everywhere",
// which is not itself a dialable address - use loopback.
func LocalBaseURL(bindAddr string, port int) string {
	host := strings.TrimSpace(bindAddr)
	switch host {
	case "", "0.0.0.0", "::", "[::]", "*":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// New validates sync state and returns a ready (but not yet running) engine.
//
// It performs the two startup gates in order:
//
//	[A1] continuity + target metadata - decides resume vs. full resync
//	[A6] rollback fail-closed         - refuses to run against a regressed DB
//
// A returned error means sync must stay off for this process lifetime; the
// caller must NOT enable the store's dirty journal in that case.
func New(ctx context.Context, st *store.Store, cfg Config) (*Engine, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.SnapshotInterval <= 0 {
		cfg.SnapshotInterval = defaultSnapshotInterval
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = defaultHeartbeatInterval
	}

	e := &Engine{
		store:       st,
		cfg:         cfg,
		client:      &http.Client{Timeout: 10 * time.Second},
		localClient: &http.Client{Timeout: 5 * time.Second},
	}

	// [A10] Read the dashboard token exactly once.
	if cfg.LocalKeyFile != "" {
		data, err := os.ReadFile(cfg.LocalKeyFile)
		if err != nil {
			log.Printf("[sync] could not read dashboard key file %s: %v - snapshot lane will be unauthorized until restart",
				cfg.LocalKeyFile, err)
		} else {
			e.localToken = strings.TrimSpace(string(data))
		}
	}

	if err := e.prepare(ctx); err != nil {
		return nil, err
	}

	fc, _ := st.GetSyncCursor(ctx, store.SyncStreamFindings)
	dc, _ := st.GetSyncCursor(ctx, store.SyncStreamDecisions)
	log.Printf("[sync] enabled target=%s findings_cursor=%d decisions_cursor=%d interval=%s snapshot=%s heartbeat=%s",
		targetHost(cfg.BaseURL), fc, dc, cfg.Interval, cfg.SnapshotInterval, cfg.HeartbeatInterval)

	return e, nil
}

// prepare runs the [A1] continuity check then the [A6] rollback check.
func (e *Engine) prepare(ctx context.Context) error {
	st := e.store
	fingerprint := targetFingerprint(e.cfg.BaseURL, e.cfg.Token)

	target, err := st.GetSyncMeta(ctx, store.SyncMetaTarget)
	if err != nil {
		return fmt.Errorf("sync: read target metadata: %w", err)
	}
	continuous, err := st.GetSyncMeta(ctx, store.SyncMetaContinuous)
	if err != nil {
		return fmt.Errorf("sync: read continuity metadata: %w", err)
	}

	// [A1] Any of these three means we cannot trust the stored cursors to
	// describe what the hosted mirror actually holds. A full resync is safe
	// because hosted ingest upserts converge, and it is bounded by local
	// retention (7d allow/suppress, 90d recon, malicious kept).
	reason := ""
	switch {
	case target == "":
		reason = "first pairing"
	case target != fingerprint:
		reason = "target changed"
	case continuous != "1":
		reason = "journal continuity broken"
	}
	if reason != "" {
		if err := st.SetSyncCursor(ctx, store.SyncStreamFindings, 0); err != nil {
			return fmt.Errorf("sync: reset findings cursor: %w", err)
		}
		if err := st.SetSyncCursor(ctx, store.SyncStreamDecisions, 0); err != nil {
			return fmt.Errorf("sync: reset decisions cursor: %w", err)
		}
		if err := st.ClearSyncDirty(ctx); err != nil {
			return fmt.Errorf("sync: clear dirty journal: %w", err)
		}
		if err := st.SetSyncMeta(ctx, store.SyncMetaTarget, fingerprint); err != nil {
			return fmt.Errorf("sync: write target metadata: %w", err)
		}
		if err := st.SetSyncMeta(ctx, store.SyncMetaContinuous, "1"); err != nil {
			return fmt.Errorf("sync: write continuity metadata: %w", err)
		}
		log.Printf("[sync] full resync triggered (reason: %s)", reason)
	}

	// [A6] Rollback fail-closed. A cursor beyond the local table's high-water
	// mark means the database was restored from an older backup (or otherwise
	// regressed) while sync_state survived. Resetting the cursors here would
	// be actively destructive: new local rows reuse autoincrement ids from the
	// abandoned timeline, so they would OVERWRITE unrelated hosted decisions.
	// Refuse, loudly, every startup, until the operator re-pairs.
	findingsCursor, err := st.GetSyncCursor(ctx, store.SyncStreamFindings)
	if err != nil {
		return fmt.Errorf("sync: read findings cursor: %w", err)
	}
	decisionsCursor, err := st.GetSyncCursor(ctx, store.SyncStreamDecisions)
	if err != nil {
		return fmt.Errorf("sync: read decisions cursor: %w", err)
	}
	maxFinding, err := st.MaxFindingRowID(ctx)
	if err != nil {
		return fmt.Errorf("sync: read findings high-water mark: %w", err)
	}
	maxDecision, err := st.MaxLLMDecisionRowID(ctx)
	if err != nil {
		return fmt.Errorf("sync: read decisions high-water mark: %w", err)
	}
	if findingsCursor > maxFinding || decisionsCursor > maxDecision {
		log.Printf("[sync] local database appears rolled back relative to sync state; "+
			"hosted mirror cannot be safely updated. Re-pair this instance (new token) to resume syncing. "+
			"(findings cursor=%d max_rowid=%d, decisions cursor=%d max_rowid=%d)",
			findingsCursor, maxFinding, decisionsCursor, maxDecision)
		return ErrRolledBack
	}

	return nil
}

// NoteDisabled records that this boot is running unpaired.
//
// [A1] A database that was previously paired but is now running without
// SYNC_URL/SYNC_TOKEN is mutating findings and decisions with nobody writing
// the dirty journal. Those mutations are invisible to any future cursor pass,
// so the next enable must full-resync. Never-paired databases have no target
// row and are left completely untouched.
func NoteDisabled(ctx context.Context, st *store.Store) error {
	target, err := st.GetSyncMeta(ctx, store.SyncMetaTarget)
	if err != nil {
		return err
	}
	if target == "" {
		return nil // never paired - nothing to invalidate
	}
	continuous, err := st.GetSyncMeta(ctx, store.SyncMetaContinuous)
	if err != nil {
		return err
	}
	if continuous == "0" {
		return nil // already marked by an earlier unpaired boot
	}
	log.Printf("[sync] disabled but this database was previously paired - " +
		"marking journal continuity broken (the next enable will full-resync)")
	return st.SetSyncMeta(ctx, store.SyncMetaContinuous, "0")
}

// Start launches the three sync goroutines. Safe to call once.
func (e *Engine) Start(ctx context.Context) {
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	e.wg.Add(3)
	go func() {
		defer e.wg.Done()
		e.runLaneA(runCtx)
	}()
	go func() {
		defer e.wg.Done()
		e.runHeartbeat(runCtx)
	}()
	go func() {
		defer e.wg.Done()
		e.runSnapshot(runCtx)
	}()
}

// Stop cancels the sync goroutines and waits for them to exit.
//
// Nothing needs flushing: cursors and journal rows move only on a validated
// acknowledgement, so an interrupted cycle simply replays next boot. In-flight
// POSTs are bounded by the HTTP client timeout. Idempotent.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}
	})
	e.wg.Wait()
}

// targetFingerprint identifies the hosted mirror this DB is paired with.
// Hashed so the token never reaches disk in recoverable form.
func targetFingerprint(baseURL, token string) string {
	sum := sha256.Sum256([]byte(baseURL + "\n" + token))
	return hex.EncodeToString(sum[:])
}

// targetHost renders the sync target for logs. Host only - never the token,
// and never a URL that might carry credentials in userinfo.
func targetHost(baseURL string) string {
	trimmed := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	if i := strings.IndexAny(trimmed, "/?#"); i >= 0 {
		trimmed = trimmed[:i]
	}
	if at := strings.LastIndex(trimmed, "@"); at >= 0 {
		trimmed = trimmed[at+1:]
	}
	return trimmed
}
