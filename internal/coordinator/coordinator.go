// internal/coordinator/coordinator.go
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
//   nginx and the backend container. The coordinator deduplicates and
//   holds alerts for evidence collection.
//
// HOW IT WORKS:
//   PENDING — active investigations with evidence timers.
//   GRAVEYARD — recently finalized outcomes (TTL 300s).

const (
	DefaultEvidenceWindow    = 2 * time.Second
	DefaultFinalizeWindow    = 5 * time.Second
	DefaultGraveyardTTL      = 300 * time.Second
	maxPendingInvestigations = 100
)

// DispatchFunc is called when a pending alert is finalized.
type DispatchFunc func(alert FinalAlert)

// EvidenceCheckFunc is called by the coordinator to look up and
// re-classify evidence for a pending alert.
type EvidenceCheckFunc func(pending *PendingAlert) (downgraded bool, escalated bool, reason string, newSeverity string)

// FinalAlert is what the coordinator emits when an investigation concludes.
type FinalAlert struct {
	EventID       string
	ScopeKey      string
	SourceType    string
	Reason        string
	MatchedVia    string
	Hash          string
	Line          string
	Verdict       string
	Severity      string

	Host          string
	StatusCode    int
	ResponseBytes int64
	HTTPMethod    string
	HTTPPath      string

	EvidenceJournal string
	Evidence        interface{}

	Downgraded      bool
	DowngradeReason string
	Escalated       bool
	EscalateReason  string

	EventCount     int
	Timestamp      time.Time
	BuildAlert     func() interface{}
}

// PendingAlert represents an ongoing investigation.
type PendingAlert struct {
	Key            string
	CreatedAt      time.Time

	EventID        string
	ScopeKey       string
	SourceType     string
	Reason         string
	MatchedVia     string
	Hash           string
	Line           string
	Verdict        string
	Severity       string
	Classification string

	Host           string
	StatusCode     int
	ResponseBytes  int64
	HTTPMethod     string
	HTTPPath       string

	// Fix 2: Body preview hash for catch-all matching.
	// Populated when REC has evidence at routing time.
	BodyPreviewHash string

	NormalizedLine string
	SourceName     string
	Timestamp      time.Time

	BuildAlert     func() interface{}

	EvidenceResult  interface{}
	EvidenceJournal string

	EventCount      int
	Downgraded      bool
	DowngradeReason string
	Escalated       bool
	EscalateReason  string
	Resolved        bool
	Dispatched      bool
}

// FinalizedOutcome is a tombstone left in the graveyard.
type FinalizedOutcome struct {
	Outcome       string
	Reason        string
	FinalizedAt   time.Time
	EventCount    int
	EvidenceBased bool
}

// Coordinator manages pending alert investigations and the graveyard.
type Coordinator struct {
	mu              sync.Mutex
	pending         map[string]*PendingAlert
	graveyard       map[string]*FinalizedOutcome
	catchAll        *CatchAllTracker
	selfSuppress    *SelfSuppressor
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
	CatchAllThreshold int
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		EvidenceWindow:    DefaultEvidenceWindow,
		FinalizeWindow:    DefaultFinalizeWindow,
		GraveyardTTL:      DefaultGraveyardTTL,
		CatchAllThreshold: DefaultCatchAllThreshold,
	}
}

// New creates a Coordinator.
func New(ctx context.Context, cfg Config, dispatch DispatchFunc, evidenceCheck EvidenceCheckFunc, verifyFunc VerifyFunc, selfSuppress *SelfSuppressor) *Coordinator {
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
		catchAll:       NewCatchAllTracker(cfg.CatchAllThreshold, verifyFunc),
		selfSuppress:   selfSuppress,
		evidenceWindow: cfg.EvidenceWindow,
		finalizeWindow: cfg.FinalizeWindow,
		graveyardTTL:   cfg.GraveyardTTL,
		dispatch:       dispatch,
		evidenceCheck:  evidenceCheck,
		ctx:            ctx,
	}

	go c.graveyardCleanup()

	return c
}

// Process submits an event to the coordinator.
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

	// --- Check 2: Graveyard ---
	if tomb, ok := c.graveyard[key]; ok {
		if tomb.EvidenceBased && time.Since(tomb.FinalizedAt) > 30*time.Second {
			delete(c.graveyard, key)
		} else {
			log.Printf("[coordinator] Late sibling suppressed via graveyard: key=%s source=%s outcome=%s original_events=%d age=%s",
				key, alert.ScopeKey, tomb.Outcome, tomb.EventCount,
				time.Since(tomb.FinalizedAt).Round(time.Millisecond))
			return
		}
	}

	// --- Check 3: Catch-all structural inference ---
	// Fix 2: Uses BodyPreviewHash instead of ResponseBytes.
	// If BodyPreviewHash is empty (evidence not yet captured), skip catch-all check —
	// the coordinator will re-evaluate when evidence arrives.
	if alert.BodyPreviewHash != "" {
		if isCatchAll, reason := c.catchAll.Check(alert.Host, alert.HTTPMethod, alert.StatusCode, alert.BodyPreviewHash, extractPath(key)); isCatchAll {
			log.Printf("[coordinator] Catch-all suppressed: key=%s host=%s status=%d hash=%.16s source=%s",
				key, alert.Host, alert.StatusCode, alert.BodyPreviewHash, alert.ScopeKey)

			c.recordFinalized(key, "downgraded", reason, 1, false)
			go c.dispatch(FinalAlert{
				EventID:         alert.EventID,
				ScopeKey:        alert.ScopeKey,
				SourceType:      alert.SourceType,
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
				Timestamp:       alert.Timestamp,
				BuildAlert:      alert.BuildAlert,
			})
			return
		}
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
			c.recordFinalized(oldestKey, "evicted", "too many pending", old.EventCount, false)
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
	// --- Phase 2: Finalize ---
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
	c.mu.Lock()
	pending, ok := c.pending[key]
	if !ok || pending.Dispatched {
		c.mu.Unlock()
		return
	}
	pending.Dispatched = true
	delete(c.pending, key)
	c.recordFinalized(key, "alerted", pending.Reason, pending.EventCount, false)
	c.mu.Unlock()

	c.dispatch(FinalAlert{
		EventID:         pending.EventID,
		ScopeKey:        pending.ScopeKey,
		SourceType:      pending.SourceType,
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
		Timestamp:       pending.Timestamp,
		BuildAlert:      pending.BuildAlert,
	})
}

// tryEvidenceCheck calls the evidence check function and resolves the
// investigation if evidence downgrades or escalates the alert.
func (c *Coordinator) tryEvidenceCheck(key string) bool {
	c.mu.Lock()
	pending, ok := c.pending[key]
	if !ok || pending.Resolved || pending.Dispatched {
		c.mu.Unlock()
		return true
	}
	c.mu.Unlock()

	downgraded, escalated, reason, newSeverity := c.evidenceCheck(pending)

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
		c.recordFinalized(key, "downgraded", reason, pending.EventCount, true)

		log.Printf("[coordinator] Investigation resolved: DOWNGRADED key=%s events=%d reason=%s",
			key, pending.EventCount, truncateStr(reason, 100))

		c.dispatch(FinalAlert{
			EventID:         pending.EventID,
			ScopeKey:        pending.ScopeKey,
			SourceType:      pending.SourceType,
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
			Timestamp:       pending.Timestamp,
			BuildAlert:      pending.BuildAlert,
		})

		return true
	}

	if escalated {
		pending.Resolved = true
		pending.Escalated = true
		pending.EscalateReason = reason
		pending.Dispatched = true
		originalSeverity := pending.Severity
		if newSeverity != "" {
			pending.Severity = newSeverity
		}
		if pending.Severity == "malicious" {
			pending.Verdict = "malicious"
		}
		pending.Reason = reason
		delete(c.pending, key)
		c.recordFinalized(key, "escalated", reason, pending.EventCount, false)

		log.Printf("[coordinator] Investigation resolved: ESCALATED key=%s events=%d %s→%s reason=%s",
			key, pending.EventCount, originalSeverity, pending.Severity, truncateStr(reason, 100))

		c.dispatch(FinalAlert{
			EventID:         pending.EventID,
			ScopeKey:        pending.ScopeKey,
			SourceType:      pending.SourceType,
			Reason:          reason,
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
			Escalated:       true,
			EscalateReason:  reason,
			EventCount:      pending.EventCount,
			Timestamp:       pending.Timestamp,
			BuildAlert:      pending.BuildAlert,
		})

		return true
	}

	return false
}

// =============================================================================
// Fix 1: VIP Push Resolution
// =============================================================================

// TryResolveVIP is called by the VIP push callback when evidence for a
// malicious event arrives. It triggers an immediate evidence check for the
// given correlation key, bypassing the polling cycle.
//
// Safe to call even if the investigation doesn't exist or is already resolved.
func (c *Coordinator) TryResolveVIP(correlationKey string) {
	log.Printf("[coordinator:vip] Push notification for key=%s — attempting immediate evidence check", correlationKey)
	c.tryEvidenceCheck(correlationKey)
}

// forceDispatch sends an alert that was evicted from the coordinator.
func (c *Coordinator) forceDispatch(pending *PendingAlert, reason string) {
	log.Printf("[coordinator] Force dispatch (%s): key=%s", reason, pending.Key)
	c.dispatch(FinalAlert{
		EventID:         pending.EventID,
		ScopeKey:        pending.ScopeKey,
		SourceType:      pending.SourceType,
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
		Timestamp:       pending.Timestamp,
		BuildAlert:      pending.BuildAlert,
	})
}

// =============================================================================
// Graveyard
// =============================================================================

func (c *Coordinator) recordFinalized(key, outcome, reason string, eventCount int, evidenceBased bool) {
	c.graveyard[key] = &FinalizedOutcome{
		Outcome:       outcome,
		Reason:        reason,
		FinalizedAt:   time.Now(),
		EventCount:    eventCount,
		EvidenceBased: evidenceBased,
	}
}

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
				if now.Sub(tomb.FinalizedAt) > c.graveyardTTL || (tomb.EvidenceBased && now.Sub(tomb.FinalizedAt) > 30*time.Second) {
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

func extractPath(key string) string {
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
func (c *Coordinator) CatchAllStats() (total, candidates, pending, verified, rejected int, suppressed int64) {
	return c.catchAll.Stats()
}

// SelfSuppressor returns the self-suppression token registry.
func (c *Coordinator) SelfSuppressor() *SelfSuppressor {
	return c.selfSuppress
}

// CatchAllTracker returns the tracker for startup seeding.
func (c *Coordinator) CatchAllTracker() *CatchAllTracker {
	return c.catchAll
}
