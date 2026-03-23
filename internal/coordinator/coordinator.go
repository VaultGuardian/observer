package coordinator

import (
	"context"
	"log"
	"sync"
	"time"
)

// =============================================================================
// Alert Coordinator — "Forensic Huddle"
// =============================================================================
//
// WHY THIS EXISTS:
//   On Docker Swarm, a single HTTP request produces log lines from both
//   nginx and the backend container. Nginx fires instantly on a seeded
//   pattern ("SQL injection detected!") before REC can capture the response.
//   Seconds later, the backend pipeline captures evidence and correctly
//   determines "the server returned a welcome page, attack was ignored."
//   But the email already went out.
//
// HOW IT WORKS:
//   Instead of dispatching alerts immediately, evidence-eligible HTTP alerts
//   go into a "huddle" — a short holding period where:
//     1. Sibling logs from other containers can join (nginx + backend = one finding)
//     2. REC can capture the response
//     3. The re-classification cache can check if the body is known-safe
//     4. A fresh LLM re-classification can run if needed
//
//   Two timers:
//     - Evidence window (2s): time for REC capture + cache check
//     - Finalize window (5s): time for LLM re-classification if cache misses
//
//   If evidence downgrades the alert → suppress (no email)
//   If timer expires with no evidence → dispatch with honest language
//   Non-HTTP alerts (SSH, sudo, kernel) bypass the huddle entirely.
//
// DESIGN:
//   Three states: pending → resolved (suppressed or confirmed) → dispatched
//   Key: method|path|statusCode (same request from any container)
//   Bounded: max 100 pending investigations, oldest evicted if full

const (
	DefaultEvidenceWindow  = 2 * time.Second
	DefaultFinalizeWindow  = 5 * time.Second
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

// Coordinator manages pending alert investigations.
type Coordinator struct {
	mu              sync.Mutex
	pending         map[string]*PendingAlert // correlationKey → investigation
	evidenceWindow  time.Duration
	finalizeWindow  time.Duration
	dispatch        DispatchFunc
	evidenceCheck   EvidenceCheckFunc
	ctx             context.Context
}

// Config holds coordinator settings.
type Config struct {
	EvidenceWindow  time.Duration
	FinalizeWindow  time.Duration
}

// DefaultConfig returns sensible defaults agreed by the AI design team.
func DefaultConfig() Config {
	return Config{
		EvidenceWindow:  DefaultEvidenceWindow,
		FinalizeWindow:  DefaultFinalizeWindow,
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
	return &Coordinator{
		pending:        make(map[string]*PendingAlert),
		evidenceWindow: cfg.EvidenceWindow,
		finalizeWindow: cfg.FinalizeWindow,
		dispatch:       dispatch,
		evidenceCheck:  evidenceCheck,
		ctx:            ctx,
	}
}

// Process submits an event to the coordinator.
// If a pending investigation exists for this correlation key, the event joins it.
// If not, a new investigation is created with timers.
func (c *Coordinator) Process(key string, alert *PendingAlert) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.pending[key]; ok {
		// Join existing investigation — this is the sibling log from another container
		existing.EventCount++

		// If the new event has a better builder (e.g., backend has more context), update
		if alert.BuildAlert != nil {
			existing.BuildAlert = alert.BuildAlert
		}

		// Inherit evidence-related fields if the newcomer has them
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

	// New investigation — bounded map
	if len(c.pending) >= maxPendingInvestigations {
		// Evict oldest
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
			// Force-dispatch the evicted alert
			go c.forceDispatch(old, "evicted from coordinator (too many pending)")
		}
	}

	alert.Key = key
	alert.CreatedAt = time.Now()
	alert.EventCount = 1
	c.pending[key] = alert

	log.Printf("[coordinator] New investigation: key=%s source=%s reason=%s",
		key, alert.ScopeKey, truncateStr(alert.Reason, 80))

	// Start evidence window timer
	go c.investigationLoop(key)
}

// investigationLoop runs the two-phase timer for a pending alert.
func (c *Coordinator) investigationLoop(key string) {
	// --- Phase 1: Evidence Sprint (2 seconds) ---
	// Try evidence check immediately, then again at intervals
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
				return // resolved — either dispatched or suppressed
			}
		}
	}

finalize:
	// --- Phase 2: Finalize (up to 5 seconds total) ---
	// One more evidence check, then dispatch whatever we have
	if c.tryEvidenceCheck(key) {
		return
	}

	// If we still don't have evidence, wait a bit more for LLM
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
		return true // already handled
	}
	c.mu.Unlock()

	// Call evidence check (may involve REC lookup + cache/LLM)
	// This runs outside the lock — it may take time
	downgraded, reason := c.evidenceCheck(pending)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check state (might have been resolved by another goroutine)
	pending, ok = c.pending[key]
	if !ok || pending.Resolved || pending.Dispatched {
		return true
	}

	if downgraded {
		// Evidence says this is harmless — suppress
		pending.Resolved = true
		pending.Downgraded = true
		pending.DowngradeReason = reason
		pending.Dispatched = true
		delete(c.pending, key)

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
			EvidenceJournal: pending.EvidenceJournal,
			Evidence:        pending.EvidenceResult,
			Downgraded:      true,
			DowngradeReason: reason,
			EventCount:      pending.EventCount,
			BuildAlert:      pending.BuildAlert,
		})

		return true
	}

	return false // not resolved yet, keep waiting
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
		EvidenceJournal: pending.EvidenceJournal,
		Evidence:        pending.EvidenceResult,
		EventCount:      pending.EventCount,
		BuildAlert:      pending.BuildAlert,
	})
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// Stats returns current coordinator state for monitoring.
func (c *Coordinator) Stats() (pending int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}
