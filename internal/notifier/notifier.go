package notifier

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vaultguardian/observer/internal/rec"
)

// Severity levels for alert routing.
type Severity string

const (
	SeverityMalicious  Severity = "malicious"
	SeveritySuspicious Severity = "suspicious"
	SeverityAlert      Severity = "alert"
)

// Tunables for the worker pool and limiter sweeper. Conservative defaults —
// a 32-deep queue per channel is enough to absorb burst alert storms without
// unbounded goroutine spawn. Past that, we drop and log: the operator gets
// a visible counter on stats rather than silent memory growth.
const (
	defaultQueueSize    = 32
	defaultSendTimeout  = 10 * time.Second
	limiterSweepEvery   = 5 * time.Minute
	limiterIdleEviction = 1 * time.Hour
)

// Alert is the unified payload sent to all notification channels.
// Built as an immutable snapshot from a single event — all fields must come
// from the same event/result pair to prevent cross-event contamination.
type Alert struct {
	EventID        string        `json:"event_id" yaml:"event_id"`
	Severity       Severity      `json:"severity" yaml:"severity"`
	ContainerID    string        `json:"container_id" yaml:"container_id"`
	ContainerName  string        `json:"container_name" yaml:"container_name"`
	LogLine        string        `json:"log_line" yaml:"log_line"`
	NormalizedHash string        `json:"normalized_hash,omitempty" yaml:"normalized_hash,omitempty"`
	Reason         string        `json:"reason" yaml:"reason"`
	MatchedVia     string        `json:"matched_via,omitempty" yaml:"matched_via,omitempty"` // "pattern", "llm", "seeded"
	Classification string        `json:"classification,omitempty" yaml:"classification,omitempty"`
	Confidence     float64       `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Timestamp      time.Time     `json:"timestamp" yaml:"timestamp"`
	Evidence       *rec.Evidence `json:"evidence,omitempty" yaml:"evidence,omitempty"` // REC response evidence (Phase 1: enrichment-only)
}

// Notifier is the interface every notification channel implements.
type Notifier interface {
	// Send delivers an alert through this channel. Implementations should
	// be safe for concurrent use and handle their own retries if needed.
	Send(ctx context.Context, alert Alert) error

	// Name returns a short identifier for logging (e.g. "webhook", "email", "sms").
	Name() string
}

// Dispatcher fans out alerts to all enabled channels, applying severity
// routing and per-channel rate limiting.
//
// Send is bounded: each channel has its own buffered queue and a single
// worker goroutine. Dispatch never spawns a goroutine per alert. When a
// queue is full (sustained overload), the alert is dropped and the
// dropped-counter incremented so operators can see shedding.
type Dispatcher struct {
	channels []Notifier
	config   *Config

	// Rate-limiter state. Keyed "channelName:containerName" — high
	// cardinality, so a sweeper goroutine evicts idle entries.
	limiters map[string]*rateLimiter
	mu       sync.Mutex

	// Per-channel work queues. One worker per queue. Started in
	// NewDispatcher, drained and stopped in Stop().
	queues map[string]chan Alert

	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	dropped atomic.Int64
}

// NewDispatcher creates a dispatcher from the given config. It auto-detects
// which channels to enable based on environment variables: if the required
// secret for a channel is set, the channel is registered.
func NewDispatcher(cfg *Config) (*Dispatcher, error) {
	d := &Dispatcher{
		config:   cfg,
		limiters: make(map[string]*rateLimiter),
		queues:   make(map[string]chan Alert),
		stopCh:   make(chan struct{}),
	}

	// --- Auto-detect channels from env config ---

	if cfg.Webhook.URL != "" {
		d.channels = append(d.channels, NewWebhookNotifier(cfg.Webhook))
	}

	if cfg.Email.APIKey != "" && cfg.Email.To != "" {
		d.channels = append(d.channels, NewEmailNotifier(cfg.Email))
	}

	if cfg.SMS.AccountSID != "" && cfg.SMS.AuthToken != "" && cfg.SMS.To != "" {
		d.channels = append(d.channels, NewSMSNotifier(cfg.SMS))
	}

	if cfg.APNs.KeyPath != "" && cfg.APNs.DeviceToken != "" {
		n, err := NewAPNsNotifier(cfg.APNs)
		if err != nil {
			log.Printf("[notifier] Failed to init APNs: %v (skipping)", err)
		} else {
			d.channels = append(d.channels, n)
		}
	}

	if cfg.FCM.CredentialsPath != "" && cfg.FCM.DeviceToken != "" {
		n, err := NewFCMNotifier(cfg.FCM)
		if err != nil {
			log.Printf("[notifier] Failed to init FCM: %v (skipping)", err)
		} else {
			d.channels = append(d.channels, n)
		}
	}

	// --- Start one worker per channel ---
	for _, ch := range d.channels {
		q := make(chan Alert, defaultQueueSize)
		d.queues[ch.Name()] = q
		d.wg.Add(1)
		go d.runWorker(ch, q)
	}

	// --- Start limiter sweeper ---
	d.wg.Add(1)
	go d.runLimiterSweeper()

	return d, nil
}

// Dispatch enqueues an alert for delivery on every channel configured to
// receive the given severity. Returns the number of channels that actually
// accepted the alert into their queue (after rate-limit and queue-full
// checks). Callers that record a "notified" flag should gate it on a
// non-zero return so dropped alerts don't get marked delivered.
//
// Drops are logged and increment the dropped counter (see DroppedCount).
// After Stop() has been called, all dispatches return 0 immediately.
func (d *Dispatcher) Dispatch(ctx context.Context, alert Alert) int {
	// Fast path: already stopped → drop without lock.
	select {
	case <-d.stopCh:
		return 0
	default:
	}

	allowedChannels := d.config.Routing.ChannelsFor(alert.Severity)
	enqueued := 0

	for _, ch := range d.channels {
		if !contains(allowedChannels, ch.Name()) {
			continue
		}

		// Phase 1: pure check. Doesn't mutate the limiter — that happens
		// only if the enqueue below succeeds.
		limited, rlKey := d.rateLimitCheck(ch.Name(), alert.ContainerName)
		if limited {
			continue
		}

		q := d.queues[ch.Name()]
		select {
		case q <- alert:
			// Phase 2: enqueue succeeded → commit rate-limit timestamp.
			d.commitRateLimit(rlKey)
			enqueued++
		case <-d.stopCh:
			return enqueued
		default:
			// Queue full — drop and log. Limiter NOT committed: a real
			// alert in the next interval gets its slot, not a dropped one.
			d.dropped.Add(1)
			log.Printf("[notifier] %s queue full (depth=%d) — dropped event=%s severity=%s",
				ch.Name(), len(q), alert.EventID, alert.Severity)
		}
	}

	return enqueued
}

// runWorker drains one channel's queue. Send errors are logged, not retried —
// individual notifier implementations own their retry policy.
func (d *Dispatcher) runWorker(n Notifier, q chan Alert) {
	defer d.wg.Done()
	for {
		select {
		case <-d.stopCh:
			// Best-effort drain of anything already enqueued.
			for {
				select {
				case alert := <-q:
					d.send(n, alert)
				default:
					return
				}
			}
		case alert := <-q:
			d.send(n, alert)
		}
	}
}

func (d *Dispatcher) send(n Notifier, alert Alert) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSendTimeout)
	defer cancel()
	if err := n.Send(ctx, alert); err != nil {
		log.Printf("[notifier] %s send failed: %v", n.Name(), err)
	}
}

// runLimiterSweeper evicts rate-limiter entries that haven't been touched
// in `limiterIdleEviction`. Without this, the limiter map grows forever
// since keys include container name (high cardinality across container
// restarts).
func (d *Dispatcher) runLimiterSweeper() {
	defer d.wg.Done()
	ticker := time.NewTicker(limiterSweepEvery)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.sweepLimiters()
		}
	}
}

func (d *Dispatcher) sweepLimiters() {
	cutoff := time.Now().Add(-limiterIdleEviction)
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, rl := range d.limiters {
		if rl.lastSent.Before(cutoff) {
			delete(d.limiters, k)
		}
	}
}

// Stop signals workers to drain and exit, then waits up to the context
// deadline for in-flight sends to complete. Alerts still queued past the
// deadline are dropped. Safe to call multiple times. Subsequent Dispatch
// calls drop silently.
func (d *Dispatcher) Stop(ctx context.Context) {
	d.stopOnce.Do(func() {
		close(d.stopCh)
	})
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// Drain deadline exceeded — accept the loss.
	}
}

// DroppedCount returns the cumulative number of alerts dropped due to
// full queues since startup.
func (d *Dispatcher) DroppedCount() int64 {
	return d.dropped.Load()
}

// PrintStatus logs which channels are active on startup.
func (d *Dispatcher) PrintStatus() {
	type channelInfo struct {
		name    string
		enabled bool
		hint    string
		detail  string
	}

	all := []channelInfo{
		{"webhook", d.config.Webhook.URL != "", "set WEBHOOK_URL", truncateURL(d.config.Webhook.URL)},
		{"email", d.config.Email.APIKey != "" && d.config.Email.To != "", "set RESEND_API_KEY + ALERT_EMAIL_TO", d.config.Email.To},
		{"sms", d.config.SMS.AccountSID != "" && d.config.SMS.To != "", "set TWILIO_SID + ALERT_SMS_TO", maskPhone(d.config.SMS.To)},
		{"push/ios", d.config.APNs.KeyPath != "" && d.config.APNs.DeviceToken != "", "set APNS_KEY_PATH + APNS_DEVICE_TOKEN", d.config.APNs.BundleID},
		{"push/fcm", d.config.FCM.CredentialsPath != "" && d.config.FCM.DeviceToken != "", "set FCM_CREDENTIALS_PATH + FCM_DEVICE_TOKEN", d.config.FCM.ProjectID},
	}

	log.Println("[logwatch] Notifications:")
	for _, ch := range all {
		if ch.enabled {
			log.Printf("[logwatch]   ✓ %-10s → %s", ch.name, ch.detail)
		} else {
			log.Printf("[logwatch]   ✗ %-10s → not configured (%s)", ch.name, ch.hint)
		}
	}
}

// ChannelCount returns the number of active notification channels.
func (d *Dispatcher) ChannelCount() int {
	return len(d.channels)
}

// --- Rate limiter ---
//
// Two-phase to keep timestamps honest with the bounded queue: rateLimitCheck
// is a pure read of "is this (channel, container) currently rate-limited";
// commitRateLimit stamps lastSent only after the alert successfully
// enqueued. Without the split, a rate check that updates lastSent followed
// by a queue-full drop would silence the next *real* alert with a slot
// for a dropped one.

type rateLimiter struct {
	lastSent time.Time
}

// rateLimitCheck returns (limited, key). The caller is responsible for
// invoking commitRateLimit(key) iff the alert was successfully accepted
// downstream and limited == false. When interval is 0 (no limit
// configured for this channel), returns (false, "").
func (d *Dispatcher) rateLimitCheck(channelName, containerName string) (bool, string) {
	interval := d.config.RateLimits.IntervalFor(channelName)
	if interval == 0 {
		return false, ""
	}
	key := channelName + ":" + containerName

	d.mu.Lock()
	defer d.mu.Unlock()

	rl, exists := d.limiters[key]
	if !exists {
		return false, key
	}
	if time.Since(rl.lastSent) < interval {
		return true, key
	}
	return false, key
}

// commitRateLimit stamps lastSent for the given key. Safe to call with an
// empty key (no-op) so callers can pass through the value from
// rateLimitCheck unconditionally.
func (d *Dispatcher) commitRateLimit(key string) {
	if key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if rl, exists := d.limiters[key]; exists {
		rl.lastSent = time.Now()
		return
	}
	d.limiters[key] = &rateLimiter{lastSent: time.Now()}
}

// --- Helpers ---

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func truncateURL(u string) string {
	if len(u) <= 50 {
		return u
	}
	return u[:47] + "..."
}

func maskPhone(phone string) string {
	if len(phone) <= 4 {
		return phone
	}
	return phone[:len(phone)-4] + "****"
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func formatAlertTitle(alert Alert) string {
	icon := "⚠️"
	switch alert.Severity {
	case SeverityMalicious:
		icon = "🚨"
	case SeveritySuspicious:
		icon = "⚠️"
	case SeverityAlert:
		icon = "ℹ️"
	}
	return fmt.Sprintf("%s [%s] %s — %s", icon, alert.Severity, alert.ContainerName, alert.Reason)
}
