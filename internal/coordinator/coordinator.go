package coordinator

import (
	"context"
	"log"
	"sync"
	"time"
)

// =============================================================================
// Alert Coordinator — "Forensic Huddle" + "Graveyard"
// =============================================================================
//
// WHY THIS EXISTS:
//   On Docker Swarm, a single HTTP request produces log lines from both
//   nginx and the backend container. Two problems:
//
//   1. Nginx fires instantly (cached hash hit, nanoseconds). The backend
//      arrives 10-120 seconds later (queued behind LLM semaphore). By then
//      the investigation is dispatched and deleted → duplicate email.
//
//   2. REC captures evidence (status code, body) but the evidence check
//      throws it away if the body preview is empty → missed downgrade.
//
// HOW IT WORKS:
//   Two data structures:
//
//   PENDING — active investigations with evidence timers.
//     - Sibling logs join the same huddle (nginx + backend = one finding)
//     - REC evidence can downgrade the alert during the window
//     - Two-phase timer: evidence sprint (2s) → finalize (5s)
//
//   GRAVEYARD — recently finalized outcomes (TTL 300s).
//     - Every investigation writes its outcome here on completion
//     - Late-arriving siblings check the graveyard before creating new investigations
//     - If a sibling finds a graveyard entry, it dies silently
//     - Stores ALL outcomes: alerted, downgraded, suppressed
//
//   AI DESIGN DECISION (2026-03-25):
//     the team, code review, and / independently agreed on this
//     architecture. The graveyard must store all finalized states, not just
//     "emails sent" — otherwise a downgraded nginx finding gets forgotten
//     and the late backend sibling reopens the case.

const (
	DefaultEvidenceWindow  = 2 * time.Second
	DefaultFinalizeWindow  = 5 * time.Second
	DefaultGraveyardTTL    = 300 * time.Second // 5 minutes — covers worst-case LLM queue delays
	maxPendingInvestigations = 100
)

// DispatchFunc is called when a pending alert is finalized.
// The coordinator calls this with the final alert decision.
type DispatchFunc func(alert FinalAlert)

// EvidenceCheckFunc is called by the coordinator to look up and
// re-classify evidence for a pending alert. Returns true + reason
// if the alert should be downgraded (suppressed).
type EvidenceCheckFunc func(pending *PendingAlert) (downgraded bool, reason string)

// FinalAlert is what the coordinator emits when an investigation concludes.
type FinalAlert struct {
	// The primary event that triggered the investigation
	EventID       string
	ScopeKey      string
	Reason        string
	MatchedVia    string
	Hash          string
	Line          string
	Verdict       string // "deny", "alert"
	Severity      string // "malicious", "suspicious"

	// HTTP metadata (from normalized + raw line parsing)
	Host          string
	StatusCode    int
	ResponseBytes int64
	HTTPMethod    string
	HTTPPath      string

	// Evidence fields (may be empty if no evidence arrived)
	EvidenceJournal string // ForJournal() output
	Evidence        interface{} // *rec.Evidence — kept as interface to avoid import cycle

	// Outcome
	Downgraded     bool
	DowngradeReason string

	// All events that joined this investigation
	EventCount     int

	// For the dispatch function to use
	BuildAlert     func() interface{} // returns notifier.Alert — kept as interface to avoid import cycle
}

// PendingAlert represents an ongoing investigation.
type PendingAlert struct {
	Key            string
	CreatedAt      time.Time

	// Primary event info (from the first log that triggered)
	EventID        string
	ScopeKey       string
	Reason         string
	MatchedVia     string
	Hash           string
	Line           string
	Verdict        string
	Severity       string
	Classification string

	// HTTP metadata (parsed from normalized line + raw line)
	Host           string
	StatusCode     int
	ResponseBytes  int64
	HTTPMethod     string
	HTTPPath       string

	// Evidence lookup context
	NormalizedLine string
	SourceName     string
	Timestamp      time.Time

	// Builder function — creates the notifier.Alert when we're ready to dispatch
	BuildAlert     func() interface{}

	// Evidence result (populated when evidence check succeeds)
	EvidenceResult  interface{} // *rec.Evidence
	EvidenceJournal string

	// State
	EventCount     int
	Downgraded     bool
	DowngradeReason string
	Resolved       bool
	Dispatched     bool
}

// FinalizedOutcome is a tombstone left in the graveyard after an investigation
// completes. Late-arriving siblings check this before creating new investigations.
type FinalizedOutcome struct {
	Outcome    string    // "alerted", "downgraded", "suppressed", "evicted"
	Reason     string    // downgrade reason or alert reason
	FinalizedAt time.Time
	EventCount int       // how many events were in the original investigation
}

// Coordinator manages pending alert investigations and the graveyard.
type Coordinator struct {
	mu              sync.Mutex
	pending         map[string]*PendingAlert      // correlationKey → active investigation
	graveyard       map[string]*FinalizedOutcome   // correlationKey → recently finalized outcome
	catchAll        *CatchAllTracker               // structural inference for catch-all responses
	evidenceWindow  time.Duration
	finalizeWindow  time.Duration
	graveyardTTL    time.Duration
	dispatch        DispatchFunc
	evidenceCheck   EvidenceCheckFunc
	ctx             context.Context
}

// Config holds coordinator settings.
type Config struct {
	EvidenceWindow    time.Duration
	FinalizeWindow    time.Duration
	GraveyardTTL      time.Duration
	CatchAllThreshold int // distinct paths before marking as catch-all (default 5)
}

// DefaultConfig returns sensible defaults agreed by the AI design team.
func DefaultConfig() Config {
	return Config{
		EvidenceWindow:    DefaultEvidenceWindow,
		FinalizeWindow:    DefaultFinalizeWindow,
		GraveyardTTL:      DefaultGraveyardTTL,
		CatchAllThreshold: DefaultCatchAllThreshold,
	}
}

// New creates a Coordinator.
//   - dispatch is called when an alert is finalized (send email, log, etc.)
//   - evidenceCheck is called to attempt REC lookup + re-classification
func New(ctx context.Context, cfg Config, dispatch DispatchFunc, evidenceCheck EvidenceCheckFunc) *Coordinator {
	if cfg.EvidenceWindow == 0 {
		cfg.EvidenceWindow = DefaultEvidenceWindow
	}
	if cfg.FinalizeWindow == 0 {
		cfg.FinalizeWindow = DefaultFinalizeWindow
	}
	if cfg.GraveyardTTL == 0 {
		cfg.GraveyardTTL = DefaultGraveyardTTL
	}
	c := &Coordinator{
		pending:        make(map[string]*PendingAlert),
		graveyard:      make(map[string]*FinalizedOutcome),
		catchAll:       NewCatchAllTracker(cfg.CatchAllThreshold),
		evidenceWindow: cfg.EvidenceWindow,
		finalizeWindow: cfg.FinalizeWindow,
		graveyardTTL:   cfg.GraveyardTTL,
		dispatch:       dispatch,
		evidenceCheck:  evidenceCheck,
		ctx:            ctx,
	}

	// Background goroutine to clean expired graveyard entries
	go c.graveyardCleanup()

	return c
}

// Process submits an event to the coordinator.
// Check order: active investigation → graveyard → create new.
func (c *Coordinator) Process(key string, alert *PendingAlert) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// --- Check 1: Join active investigation ---
	if existing, ok := c.pending[key]; ok {
		existing.EventCount++

		if alert.BuildAlert != nil {
			existing.BuildAlert = alert.BuildAlert
		}
		if alert.NormalizedLine != "" {
			existing.NormalizedLine = alert.NormalizedLine
		}
		if alert.SourceName != "" {
			existing.SourceName = alert.SourceName
		}
		if alert.Classification != "" {
			existing.Classification = alert.Classification
		}

		log.Printf("[coordinator] Event joined huddle: key=%s events=%d source=%s",
			key, existing.EventCount, alert.ScopeKey)
		return
	}

	// --- Check 2: Graveyard — was this recently finalized? ---
	if tomb, ok := c.graveyard[key]; ok {
		log.Printf("[coordinator] Late sibling suppressed via graveyard: key=%s source=%s outcome=%s original_events=%d age=%s",
			key, alert.ScopeKey, tomb.Outcome, tomb.EventCount,
			time.Since(tomb.FinalizedAt).Round(time.Millisecond))
		return
	}

	// --- Check 3: Catch-all structural inference ---
	// If we've seen enough distinct paths return the same (host, status, bytes),
	// this is a catch-all page. Auto-downgrade without evidence or LLM.
	if isCatchAll, reason := c.catchAll.Check(alert.Host, alert.StatusCode, alert.ResponseBytes, extractPath(key)); isCatchAll {
		log.Printf("[coordinator] Catch-all suppressed: key=%s host=%s status=%d bytes=%d source=%s",
			key, alert.Host, alert.StatusCode, alert.ResponseBytes, alert.ScopeKey)

		c.recordFinalized(key, "downgraded", reason, 1)
		// Dispatch as downgraded — goes to SQLite, no email
		go c.dispatch(FinalAlert{
			EventID:         alert.EventID,
			ScopeKey:        alert.ScopeKey,
			Reason:          alert.Reason,
			MatchedVia:      alert.MatchedVia,
			Hash:            alert.Hash,
			Line:            alert.Line,
			Verdict:         alert.Verdict,
			Severity:        alert.Severity,
			Host:            alert.Host,
			StatusCode:      alert.StatusCode,
			ResponseBytes:   alert.ResponseBytes,
			HTTPMethod:      alert.HTTPMethod,
			HTTPPath:        alert.HTTPPath,
			Downgraded:      true,
			DowngradeReason: reason,
			EventCount:      1,
			BuildAlert:      alert.BuildAlert,
		})
		return
	}

	// --- Check 4: Create new investigation ---
	if len(c.pending) >= maxPendingInvestigations {
		var oldestKey string
		var oldestTime time.Time
		for k, p := range c.pending {
			if oldestKey == "" || p.CreatedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = p.CreatedAt
			}
		}
		if oldestKey != "" {
			old := c.pending[oldestKey]
			delete(c.pending, oldestKey)
			c.recordFinalized(oldestKey, "evicted", "too many pending", old.EventCount)
			go c.forceDispatch(old, "evicted from coordinator (too many pending)")
		}
	}

	alert.Key = key
	alert.CreatedAt = time.Now()
	alert.EventCount = 1
	c.pending[key] = alert

	log.Printf("[coordinator] New investigation: key=%s source=%s reason=%s",
		key, alert.ScopeKey, truncateStr(alert.Reason, 80))

	go c.investigationLoop(key)
}

// investigationLoop runs the two-phase timer for a pending alert.
func (c *Coordinator) investigationLoop(key string) {
	// --- Phase 1: Evidence Sprint (2 seconds) ---
	checkInterval := 500 * time.Millisecond
	evidenceDeadline := time.After(c.evidenceWindow)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-evidenceDeadline:
			goto finalize
		case <-time.After(checkInterval):
			if c.tryEvidenceCheck(key) {
				return
			}
		}
	}

finalize:
	// --- Phase 2: Finalize (up to 5 seconds total) ---
	if c.tryEvidenceCheck(key) {
		return
	}

	remainingTime := c.finalizeWindow - c.evidenceWindow
	if remainingTime > 0 {
		finalDeadline := time.After(remainingTime)
		checkInterval := time.Second
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-finalDeadline:
				goto dispatch
			case <-time.After(checkInterval):
				if c.tryEvidenceCheck(key) {
					return
				}
			}
		}
	}

dispatch:
	// Timer expired — dispatch with whatever we have
	c.mu.Lock()
	pending, ok := c.pending[key]
	if !ok || pending.Dispatched {
		c.mu.Unlock()
		return
	}
	pending.Dispatched = true
	delete(c.pending, key)
	c.recordFinalized(key, "alerted", pending.Reason, pending.EventCount)
	c.mu.Unlock()

	c.dispatch(FinalAlert{
		EventID:         pending.EventID,
		ScopeKey:        pending.ScopeKey,
		Reason:          pending.Reason,
		MatchedVia:      pending.MatchedVia,
		Hash:            pending.Hash,
		Line:            pending.Line,
		Verdict:         pending.Verdict,
		Severity:        pending.Severity,
		Host:            pending.Host,
		StatusCode:      pending.StatusCode,
		ResponseBytes:   pending.ResponseBytes,
		HTTPMethod:      pending.HTTPMethod,
		HTTPPath:        pending.HTTPPath,
		EvidenceJournal: pending.EvidenceJournal,
		Evidence:        pending.EvidenceResult,
		Downgraded:      false,
		EventCount:      pending.EventCount,
		BuildAlert:      pending.BuildAlert,
	})
}

// tryEvidenceCheck calls the evidence check function and resolves the
// investigation if evidence downgrades the alert. Returns true if resolved.
func (c *Coordinator) tryEvidenceCheck(key string) bool {
	c.mu.Lock()
	pending, ok := c.pending[key]
	if !ok || pending.Resolved || pending.Dispatched {
		c.mu.Unlock()
		return true
	}
	c.mu.Unlock()

	downgraded, reason := c.evidenceCheck(pending)

	c.mu.Lock()
	defer c.mu.Unlock()

	pending, ok = c.pending[key]
	if !ok || pending.Resolved || pending.Dispatched {
		return true
	}

	if downgraded {
		pending.Resolved = true
		pending.Downgraded = true
		pending.DowngradeReason = reason
		pending.Dispatched = true
		delete(c.pending, key)
		c.recordFinalized(key, "downgraded", reason, pending.EventCount)

		log.Printf("[coordinator] Investigation resolved: DOWNGRADED key=%s events=%d reason=%s",
			key, pending.EventCount, truncateStr(reason, 100))

		c.dispatch(FinalAlert{
			EventID:         pending.EventID,
			ScopeKey:        pending.ScopeKey,
			Reason:          pending.Reason,
			MatchedVia:      pending.MatchedVia,
			Hash:            pending.Hash,
			Line:            pending.Line,
			Verdict:         pending.Verdict,
			Severity:        pending.Severity,
			Host:            pending.Host,
			StatusCode:      pending.StatusCode,
			ResponseBytes:   pending.ResponseBytes,
			HTTPMethod:      pending.HTTPMethod,
			HTTPPath:        pending.HTTPPath,
			EvidenceJournal: pending.EvidenceJournal,
			Evidence:        pending.EvidenceResult,
			Downgraded:      true,
			DowngradeReason: reason,
			EventCount:      pending.EventCount,
			BuildAlert:      pending.BuildAlert,
		})

		return true
	}

	return false
}

// forceDispatch sends an alert that was evicted from the coordinator.
func (c *Coordinator) forceDispatch(pending *PendingAlert, reason string) {
	log.Printf("[coordinator] Force dispatch (%s): key=%s", reason, pending.Key)
	c.dispatch(FinalAlert{
		EventID:         pending.EventID,
		ScopeKey:        pending.ScopeKey,
		Reason:          pending.Reason,
		MatchedVia:      pending.MatchedVia,
		Hash:            pending.Hash,
		Line:            pending.Line,
		Verdict:         pending.Verdict,
		Severity:        pending.Severity,
		Host:            pending.Host,
		StatusCode:      pending.StatusCode,
		ResponseBytes:   pending.ResponseBytes,
		HTTPMethod:      pending.HTTPMethod,
		HTTPPath:        pending.HTTPPath,
		EvidenceJournal: pending.EvidenceJournal,
		Evidence:        pending.EvidenceResult,
		EventCount:      pending.EventCount,
		BuildAlert:      pending.BuildAlert,
	})
}

// =============================================================================
// Graveyard — Recently Finalized Outcomes
// =============================================================================

// recordFinalized writes a tombstone to the graveyard. Must be called with mu held.
func (c *Coordinator) recordFinalized(key, outcome, reason string, eventCount int) {
	c.graveyard[key] = &FinalizedOutcome{
		Outcome:     outcome,
		Reason:      reason,
		FinalizedAt: time.Now(),
		EventCount:  eventCount,
	}
}

// graveyardCleanup periodically removes expired tombstones.
func (c *Coordinator) graveyardCleanup() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for key, tomb := range c.graveyard {
				if now.Sub(tomb.FinalizedAt) > c.graveyardTTL {
					delete(c.graveyard, key)
				}
			}
			c.mu.Unlock()
		}
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// extractPath pulls the path component from a coordinator correlation key.
// Key format: "METHOD|/path?query|STATUS"
func extractPath(key string) string {
	// Find first and last pipe
	first := -1
	last := -1
	for i, c := range key {
		if c == '|' {
			if first == -1 {
				first = i
			}
			last = i
		}
	}
	if first >= 0 && last > first {
		return key[first+1 : last]
	}
	return key
}

// Stats returns current coordinator state for monitoring.
func (c *Coordinator) Stats() (pending int, graveyard int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending), len(c.graveyard)
}

// CatchAllStats returns catch-all tracker state for telemetry.
func (c *Coordinator) CatchAllStats() (total int, catchAlls int, suppressed int64) {
	return c.catchAll.Stats()
}