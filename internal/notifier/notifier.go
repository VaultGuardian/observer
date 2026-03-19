package notifier

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Severity levels for alert routing.
type Severity string

const (
	SeverityMalicious  Severity = "malicious"
	SeveritySuspicious Severity = "suspicious"
	SeverityAlert      Severity = "alert"
)

// Alert is the unified payload sent to all notification channels.
type Alert struct {
	Severity      Severity  `json:"severity" yaml:"severity"`
	ContainerID   string    `json:"container_id" yaml:"container_id"`
	ContainerName string    `json:"container_name" yaml:"container_name"`
	LogLine       string    `json:"log_line" yaml:"log_line"`
	Reason        string    `json:"reason" yaml:"reason"`
	Classification string  `json:"classification,omitempty" yaml:"classification,omitempty"`
	Confidence    float64   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	Timestamp     time.Time `json:"timestamp" yaml:"timestamp"`
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
type Dispatcher struct {
	channels []Notifier
	config   *Config
	limiters map[string]*rateLimiter // keyed by "channelName:containerName"
	mu       sync.RWMutex
}

// NewDispatcher creates a dispatcher from the given config. It auto-detects
// which channels to enable based on environment variables: if the required
// secret for a channel is set, the channel is registered.
func NewDispatcher(cfg *Config) (*Dispatcher, error) {
	d := &Dispatcher{
		config:   cfg,
		limiters: make(map[string]*rateLimiter),
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

	return d, nil
}

// Dispatch sends an alert to all channels that are configured to receive
// alerts of the given severity, respecting rate limits.
func (d *Dispatcher) Dispatch(ctx context.Context, alert Alert) {
	allowedChannels := d.config.Routing.ChannelsFor(alert.Severity)

	for _, ch := range d.channels {
		if !contains(allowedChannels, ch.Name()) {
			continue
		}

		// Rate limit check
		if d.isRateLimited(ch.Name(), alert.ContainerName) {
			continue
		}

		go func(n Notifier) {
			if err := n.Send(ctx, alert); err != nil {
				log.Printf("[notifier] %s send failed: %v", n.Name(), err)
			}
		}(ch)
	}
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

type rateLimiter struct {
	lastSent time.Time
}

func (d *Dispatcher) isRateLimited(channelName, containerName string) bool {
	interval := d.config.RateLimits.IntervalFor(channelName)
	if interval == 0 {
		return false
	}

	key := channelName + ":" + containerName

	d.mu.Lock()
	defer d.mu.Unlock()

	rl, exists := d.limiters[key]
	if !exists {
		d.limiters[key] = &rateLimiter{lastSent: time.Now()}
		return false
	}

	if time.Since(rl.lastSent) < interval {
		return true
	}

	rl.lastSent = time.Now()
	return false
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
