// internal/coordinator/coordinator.go
package coordinator

import (
	"context"
	"log"
	"strings"
	"sync"
	"sync/atomic"
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
//
// =============================================================================
// Section 3 fixes (v1.0 hardening):
// =============================================================================
//
//   Finding 2 — host in correlation key:
//     resultrouter now builds keys as "host|method|path|status" so two vhosts
//     hitting the same path/status don't false-join the same investigation.
//     `extractPath()` is gone — the coordinator reads pending.HTTPPath /
//     alert.HTTPPath directly instead of parsing the key. Key is opaque.
//
//   Finding 3 — better merge on join:
//     Process() now upgrades Host, ResponseBytes, weak StatusCode, and other
//     metadata when a sibling event has stronger data than the existing
//     pending alert. Previously only HTTPPath was upgraded.
//
//   Findings 4+5 — concurrency refactor:
//     EvidenceCheckFunc now returns an EvidenceDecision struct. The callback
//     no longer mutates pending state; the coordinator applies the decision
//     under lock. Dispatch happens outside the mutex.
//     New shape:
//       lock → snapshot pending → unlock → evidenceCheck(snapshot) →
//       lock → apply decision to live pending → build FinalAlert →
//       delete from pending → record finalized → unlock → dispatch
// =============================================================================

const (
	// v0.43.2+: Bumped from 2s/5s to 5s/10s to account for the full REC pipeline
	// delay: assembler flush (~2s) + orphan response expiry queue (~2-3s) + cleanup
	// loop interval (1s).
	DefaultEvidenceWindow    = 5 * time.Second
	DefaultFinalizeWindow    = 10 * time.Second
	DefaultGraveyardTTL      = 300 * time.Second
	maxPendingInvestigations = 100
)

// DispatchFunc is called when a pending alert is finalized.
type DispatchFunc func(alert FinalAlert)

// EvidenceDecision carries the evidenceCheck callback's verdict back to the
// coordinator. The callback no longer mutates pending state directly — it
// returns this struct and the coordinator applies it under its own lock.
//
// Section 3 / Findings 4+5 — purity discipline:
//
//	Pre-fix the callback signature was
//	  func(*PendingAlert) (downgraded, escalated bool, reason, newSeverity string)
//	and the implementation in main.go silently mutated pending.BodyPreviewHash,
//	pending.EvidenceResult, and pending.EvidenceJournal. Two paths
//	(investigationLoop polling + TryResolveVIP push) could call the callback
//	concurrently, racing on those writes. Returning a value-typed decision
//	eliminates the race; the coordinator owns coordinator state.
type EvidenceDecision struct {
	Downgraded      bool
	Escalated       bool
	Reason          string
	NewSeverity     string
	Evidence        interface{} // applied to pending.EvidenceResult
	EvidenceJournal string      // applied to pending.EvidenceJournal
	BodyPreviewHash string      // applied to pending.BodyPreviewHash (Phase 2 catch-all re-arm)
}

// EvidenceCheckFunc is called by the coordinator to look up and re-classify
// evidence for a pending alert. The callback receives a snapshot of pending —
// reads only, no mutation. All decisions and any state to apply come back via
// the returned EvidenceDecision.
type EvidenceCheckFunc func(snapshot *PendingAlert) EvidenceDecision

// FinalAlert is what the coordinator emits when an investigation concludes.
type FinalAlert struct {
	EventID    string
	ScopeKey   string
	SourceType string
	Reason     string
	MatchedVia string
	Hash       string
	Line       string
	Verdict    string
	Severity   string

	// Key is the coordinator correlation key (host|method|path|status).
	// Distinct from ScopeKey, which is source identity (e.g. "docker:captain-nginx").
	// Section 3 follow-up (code review review): logs and DB writes used to put
	// ScopeKey in the coordinator_key column, which lied about what the
	// coordinator actually correlated on. This field carries the real key.
	Key string

	Host          string
	StatusCode    int
	ResponseBytes int64
	HTTPMethod    string
	HTTPPath      string

	PatternScope  string
	PatternBucket string
	PatternValue  string

	EvidenceJournal string
	Evidence        interface{}

	Downgraded      bool
	DowngradeReason string
	Escalated       bool
	EscalateReason  string

	EventCount int
	Timestamp  time.Time
	// BuildAlert is invoked with the final evidence so the dispatch callback
	// can build a notifier.Alert without doing a redundant REC lookup.
	// Section 3 / Finding 7: previously took no args and did a fresh
	// host-less Lookup at dispatch time, racing with the coordinator's own
	// host-aware lookup. Now it just adapts the already-attached evidence.
	BuildAlert func(evidence interface{}) interface{}
}

// PendingAlert represents an ongoing investigation.
type PendingAlert struct {
	Key       string
	CreatedAt time.Time

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

	Host          string
	StatusCode    int
	ResponseBytes int64
	HTTPMethod    string
	HTTPPath      string

	PatternScope  string
	PatternBucket string
	PatternValue  string

	BodyPreviewHash string

	NormalizedLine string
	SourceName     string
	Timestamp      time.Time

	BuildAlert func(evidence interface{}) interface{}

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
	mu             sync.Mutex
	pending        map[string]*PendingAlert
	graveyard      map[string]*FinalizedOutcome
	catchAll       *CatchAllTracker
	selfSuppress   *SelfSuppressor
	evidenceWindow time.Duration
	finalizeWindow time.Duration
	graveyardTTL   time.Duration
	dispatch       DispatchFunc
	evidenceCheck  EvidenceCheckFunc
	ctx            context.Context

	// Section 3 follow-up (code review review item #6): telemetry for the
	// host-aware coordinator key. Counts new investigations created with
	// the "<unknown-host>" placeholder, indicating events that came in
	// without parseable Host metadata. Low number = healthy. High number
	// = backend logs are losing host attribution and we should look at
	// the parser/normalizer pipeline.
	hostlessKeys atomic.Int64
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
//
// Section 3 / Finding 3: on join, merge stronger metadata from the incoming
// alert. Previously only HTTPPath was upgraded (raw-over-<NUM>). Now Host,
// ResponseBytes, weak StatusCode, Reason, Line, SourceType, Timestamp are
// all considered for upgrade when the existing pending has weaker data.
//
// Section 3 / Finding 2: the catch-all check now takes alert.HTTPPath
// directly. Previously it called extractPath(key) which depended on the
// key format.
//
// Section 3 / Finding 5: dispatch happens outside the lock. The function
// uses explicit unlock + dispatch (no defer) so the catch-all match path
// can dispatch cleanly without a re-lock dance.
func (c *Coordinator) Process(key string, alert *PendingAlert) {
	c.mu.Lock()

	// --- Check 1: Join active investigation ---
	if existing, ok := c.pending[key]; ok {
		existing.EventCount++
		mergePendingMetadata(existing, alert)
		log.Printf("[coordinator] Event joined huddle: key=%s events=%d source=%s",
			key, existing.EventCount, alert.ScopeKey)
		c.mu.Unlock()
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
			c.mu.Unlock()
			return
		}
	}

	// --- Check 3: Catch-all structural inference ---
	// Section 3 / Finding 2: read alert.HTTPPath directly instead of
	// parsing the coordinator key.
	if alert.BodyPreviewHash != "" {
		if isCatchAll, reason := c.catchAll.Check(alert.Host, alert.HTTPMethod, alert.StatusCode, alert.BodyPreviewHash, alert.HTTPPath); isCatchAll {
			c.recordFinalized(key, "downgraded", reason, 1, true)
			finalAlert := FinalAlert{
				EventID:         alert.EventID,
				ScopeKey:        alert.ScopeKey,
				Key:             key, // Section 3 follow-up: real coordinator key
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
				PatternScope:    alert.PatternScope,
				PatternBucket:   alert.PatternBucket,
				PatternValue:    alert.PatternValue,
				Downgraded:      true,
				DowngradeReason: reason,
				EventCount:      1,
				Timestamp:       alert.Timestamp,
				BuildAlert:      alert.BuildAlert,
			}
			c.mu.Unlock()

			log.Printf("[coordinator] CATCH-ALL match (Process): key=%s host=%s status=%d hash=%.16s — auto-downgrade source=%s",
				key, alert.Host, alert.StatusCode, alert.BodyPreviewHash, alert.ScopeKey)
			c.dispatch(finalAlert)
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

	// Section 3 follow-up: telemetry for hostless keys. Increment under the
	// lock isn't necessary (atomic), but the read is right here anyway.
	if strings.HasPrefix(key, "<unknown-host>|") {
		c.hostlessKeys.Add(1)
	}

	c.mu.Unlock()

	log.Printf("[coordinator] New investigation: key=%s source=%s reason=%s",
		key, alert.ScopeKey, truncateStr(alert.Reason, 80))

	go c.investigationLoop(key)
}

// mergePendingMetadata upgrades fields on `existing` whenever `incoming` has
// stronger or fresher data. Section 3 / Finding 3.
//
// Rules:
//   - never overwrite non-empty with empty
//   - prefer raw HTTPPath over <NUM>-substituted (preserves the v0.44 fix)
//   - prefer non-zero StatusCode / ResponseBytes / non-empty Host
//   - keep first-arrival Timestamp (don't churn) but update LastSeen via
//     EventCount increment which the caller already did
//   - update BuildAlert/NormalizedLine/SourceName/Classification/Pattern* if
//     incoming has them — they're correctness-preserving overrides
func mergePendingMetadata(existing, incoming *PendingAlert) {
	if incoming.BuildAlert != nil {
		existing.BuildAlert = incoming.BuildAlert
	}
	if incoming.NormalizedLine != "" {
		existing.NormalizedLine = incoming.NormalizedLine
	}
	if incoming.SourceName != "" {
		existing.SourceName = incoming.SourceName
	}
	if incoming.Classification != "" {
		existing.Classification = incoming.Classification
	}
	if incoming.PatternValue != "" {
		existing.PatternScope = incoming.PatternScope
		existing.PatternBucket = incoming.PatternBucket
		existing.PatternValue = incoming.PatternValue
	}

	// HTTPPath: prefer raw over <NUM> (design consensus P0 fix, 2026-05).
	if existing.HTTPPath == "" && incoming.HTTPPath != "" {
		existing.HTTPPath = incoming.HTTPPath
	} else if incoming.HTTPPath != "" &&
		strings.Contains(existing.HTTPPath, "<NUM>") &&
		!strings.Contains(incoming.HTTPPath, "<NUM>") {
		existing.HTTPPath = incoming.HTTPPath
	}

	// HTTPMethod: nginx and backend should agree, but if existing is empty,
	// take whatever the sibling has.
	if existing.HTTPMethod == "" && incoming.HTTPMethod != "" {
		existing.HTTPMethod = incoming.HTTPMethod
	}

	// StatusCode: 0 means unset. Upgrade.
	if existing.StatusCode == 0 && incoming.StatusCode != 0 {
		existing.StatusCode = incoming.StatusCode
	}

	// Host: nginx exposes vhost, backend usually doesn't. Take the first
	// non-empty host we see and keep it.
	if existing.Host == "" && incoming.Host != "" {
		existing.Host = incoming.Host
	}

	// ResponseBytes: nginx access log carries this, backend usually doesn't.
	// Upgrade if existing is missing it.
	if existing.ResponseBytes == 0 && incoming.ResponseBytes > 0 {
		existing.ResponseBytes = incoming.ResponseBytes
	}

	// Reason / Line / SourceType: upgrade if incoming is non-empty and
	// existing is empty. Don't churn — first-arrival wins when both populated.
	if existing.Reason == "" && incoming.Reason != "" {
		existing.Reason = incoming.Reason
	}
	if existing.Line == "" && incoming.Line != "" {
		existing.Line = incoming.Line
	}
	if existing.SourceType == "" && incoming.SourceType != "" {
		existing.SourceType = incoming.SourceType
	}
	if existing.Hash == "" && incoming.Hash != "" {
		existing.Hash = incoming.Hash
	}
	if existing.MatchedVia == "" && incoming.MatchedVia != "" {
		existing.MatchedVia = incoming.MatchedVia
	}

	// Timestamp: keep first-arrival timestamp. EventCount tracks recurrence.
}

// investigationLoop runs the two-phase timer for a pending alert.
func (c *Coordinator) investigationLoop(key string) {
	// --- Phase 1: Evidence Sprint ---
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
	// --- Phase 2: Finalize sprint ---
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
	c.dispatchTimedOut(key)
}

// dispatchTimedOut handles the timeout dispatch at the end of investigationLoop.
//
// Section 3 / Findings 4+5: builds the FinalAlert under the lock, then
// dispatches outside the lock. Phase 3 fallback (catch-all by bytes) is
// also evaluated under the lock with the same discipline.
func (c *Coordinator) dispatchTimedOut(key string) {
	var finalAlert *FinalAlert

	c.mu.Lock()
	pending, ok := c.pending[key]
	if !ok || pending.Dispatched {
		c.mu.Unlock()
		return
	}

	// --- Phase 3: ResponseBytes fallback for REC-miss events ---
	// Section 3 / Finding 2: read pending.HTTPPath directly, not extractPath(key).
	// Section 3 / Landmine A: CheckFallbackByBytes now requires byte-similarity
	// to the verified entry's recorded ResponseBytes.
	if pending.BodyPreviewHash == "" && pending.ResponseBytes > 0 {
		if isCatchAll, fallbackReason := c.catchAll.CheckFallbackByBytes(
			pending.Host, pending.HTTPMethod, pending.StatusCode,
			pending.ResponseBytes, pending.HTTPPath,
		); isCatchAll {
			pending.Dispatched = true
			delete(c.pending, key)
			c.recordFinalized(key, "downgraded", fallbackReason, pending.EventCount, false)

			finalAlert = buildFinalAlert(pending, finalShape{
				downgraded:      true,
				downgradeReason: fallbackReason,
			})
			c.mu.Unlock()

			log.Printf("[coordinator] Investigation resolved: CATCH-ALL FALLBACK (REC-miss) key=%s events=%d reason=%s",
				key, pending.EventCount, truncateStr(fallbackReason, 100))
			c.dispatch(*finalAlert)
			return
		}
	}

	pending.Dispatched = true
	delete(c.pending, key)
	c.recordFinalized(key, "alerted", pending.Reason, pending.EventCount, false)

	finalAlert = buildFinalAlert(pending, finalShape{})
	c.mu.Unlock()

	c.dispatch(*finalAlert)
}

// tryEvidenceCheck snapshots the pending alert, runs the (pure) evidence
// check on the snapshot, and applies the resulting decision under lock.
//
// Section 3 / Findings 4+5: this replaces the previous shape where the
// callback received the live pending pointer and mutated EvidenceResult /
// EvidenceJournal / BodyPreviewHash directly. With two callers
// (investigationLoop polling and TryResolveVIP push) racing, those mutations
// were a real data race. The fix is purity: callback returns a value-typed
// EvidenceDecision, coordinator owns the apply step. Dispatch happens
// outside the lock.
//
// Returns true if the investigation was resolved (no further polling needed).
func (c *Coordinator) tryEvidenceCheck(key string) bool {
	// --- Step 1: Snapshot under lock ---
	c.mu.Lock()
	pending, ok := c.pending[key]
	if !ok || pending.Resolved || pending.Dispatched {
		c.mu.Unlock()
		return true
	}
	snapshot := *pending
	c.mu.Unlock()

	// --- Step 2: Evidence check on the snapshot, no shared-state mutation ---
	decision := c.evidenceCheck(&snapshot)

	// --- Step 3: Apply under lock + build FinalAlert ---
	var finalAlert *FinalAlert

	c.mu.Lock()
	pending, ok = c.pending[key]
	if !ok || pending.Resolved || pending.Dispatched {
		c.mu.Unlock()
		return true
	}

	// Apply attached evidence first — this lets Phase 2 catch-all re-arm
	// see the populated BodyPreviewHash even when no downgrade/escalation
	// fired this iteration.
	if decision.BodyPreviewHash != "" {
		pending.BodyPreviewHash = decision.BodyPreviewHash
	}
	if decision.Evidence != nil {
		pending.EvidenceResult = decision.Evidence
	}
	if decision.EvidenceJournal != "" {
		pending.EvidenceJournal = decision.EvidenceJournal
	}

	switch {
	case decision.Downgraded:
		pending.Resolved = true
		pending.Downgraded = true
		pending.DowngradeReason = decision.Reason
		pending.Dispatched = true
		delete(c.pending, key)
		c.recordFinalized(key, "downgraded", decision.Reason, pending.EventCount, true)

		log.Printf("[coordinator] Investigation resolved: DOWNGRADED key=%s events=%d reason=%s",
			key, pending.EventCount, truncateStr(decision.Reason, 100))

		finalAlert = buildFinalAlert(pending, finalShape{
			downgraded:      true,
			downgradeReason: decision.Reason,
		})

	case decision.Escalated:
		pending.Resolved = true
		pending.Escalated = true
		pending.EscalateReason = decision.Reason
		pending.Dispatched = true
		originalSeverity := pending.Severity
		if decision.NewSeverity != "" {
			pending.Severity = decision.NewSeverity
		}
		if pending.Severity == "malicious" {
			pending.Verdict = "malicious"
		}
		pending.Reason = decision.Reason
		delete(c.pending, key)
		c.recordFinalized(key, "escalated", decision.Reason, pending.EventCount, false)

		log.Printf("[coordinator] Investigation resolved: ESCALATED key=%s events=%d %s→%s reason=%s",
			key, pending.EventCount, originalSeverity, pending.Severity, truncateStr(decision.Reason, 100))

		finalAlert = buildFinalAlert(pending, finalShape{
			escalated:      true,
			escalateReason: decision.Reason,
		})

	default:
		// No verdict change. Try Phase 2 catch-all re-arm if BodyPreviewHash
		// was populated by the evidence step. Section 3 / Finding 2: read
		// pending.HTTPPath directly instead of parsing the key.
		if pending.BodyPreviewHash != "" {
			if isCatchAll, catchReason := c.catchAll.Check(
				pending.Host, pending.HTTPMethod, pending.StatusCode,
				pending.BodyPreviewHash, pending.HTTPPath,
			); isCatchAll {
				pending.Resolved = true
				pending.Downgraded = true
				pending.DowngradeReason = catchReason
				pending.Dispatched = true
				delete(c.pending, key)
				c.recordFinalized(key, "downgraded", catchReason, pending.EventCount, true)

				log.Printf("[coordinator] Investigation resolved: CATCH-ALL (re-armed) key=%s events=%d hash=%.16s reason=%s",
					key, pending.EventCount, pending.BodyPreviewHash, truncateStr(catchReason, 100))

				finalAlert = buildFinalAlert(pending, finalShape{
					downgraded:      true,
					downgradeReason: catchReason,
				})
			}
		}
	}

	c.mu.Unlock()

	// --- Step 4: Dispatch outside the lock ---
	if finalAlert != nil {
		c.dispatch(*finalAlert)
		return true
	}
	return false
}

// finalShape captures the verdict-specific fields needed to assemble a
// FinalAlert without repeating the boilerplate at every call site.
type finalShape struct {
	downgraded      bool
	downgradeReason string
	escalated       bool
	escalateReason  string
}

// buildFinalAlert constructs a FinalAlert from a pending alert plus
// verdict-specific shape. Caller is responsible for holding the lock or
// using a snapshot — buildFinalAlert just reads.
func buildFinalAlert(pending *PendingAlert, shape finalShape) *FinalAlert {
	reason := pending.Reason
	if shape.escalated && shape.escalateReason != "" {
		reason = shape.escalateReason
	}
	return &FinalAlert{
		EventID:         pending.EventID,
		ScopeKey:        pending.ScopeKey,
		Key:             pending.Key, // Section 3 follow-up: real coordinator key for logs/DB
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
		PatternScope:    pending.PatternScope,
		PatternBucket:   pending.PatternBucket,
		PatternValue:    pending.PatternValue,
		EvidenceJournal: pending.EvidenceJournal,
		Evidence:        pending.EvidenceResult,
		Downgraded:      shape.downgraded,
		DowngradeReason: shape.downgradeReason,
		Escalated:       shape.escalated,
		EscalateReason:  shape.escalateReason,
		EventCount:      pending.EventCount,
		Timestamp:       pending.Timestamp,
		BuildAlert:      pending.BuildAlert,
	}
}

// =============================================================================
// VIP Push Resolution
// =============================================================================

// TryResolveVIP is called by the VIP push callback when evidence for a
// malicious event arrives. Triggers an immediate evidence check, bypassing
// the polling cycle. Safe to call even if the investigation doesn't exist
// or is already resolved.
func (c *Coordinator) TryResolveVIP(correlationKey string) {
	log.Printf("[coordinator:vip] Push notification for key=%s — attempting immediate evidence check", correlationKey)
	c.tryEvidenceCheck(correlationKey)
}

// forceDispatch sends an alert that was evicted from the coordinator.
// Already runs outside any held lock (caller does `go c.forceDispatch(...)`).
func (c *Coordinator) forceDispatch(pending *PendingAlert, reason string) {
	log.Printf("[coordinator] Force dispatch (%s): key=%s", reason, pending.Key)
	c.dispatch(*buildFinalAlert(pending, finalShape{}))
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

// HostlessKeys returns the lifetime count of new investigations created with
// the "<unknown-host>" placeholder. Section 3 follow-up telemetry — see
// Coordinator struct comment.
func (c *Coordinator) HostlessKeys() int64 {
	return c.hostlessKeys.Load()
}

// SelfSuppressor returns the self-suppression token registry.
func (c *Coordinator) SelfSuppressor() *SelfSuppressor {
	return c.selfSuppress
}

// CatchAllTracker returns the tracker for startup seeding.
func (c *Coordinator) CatchAllTracker() *CatchAllTracker {
	return c.catchAll
}