package notifier

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all notification settings. Secrets come from env vars,
// behavior settings come from the YAML config file.
type Config struct {
	Webhook WebhookConfig `yaml:"-"` // secrets from env only
	Email   EmailConfig   `yaml:"-"`
	SMS     SMSConfig     `yaml:"-"`
	APNs    APNsConfig    `yaml:"-"`
	FCM     FCMConfig     `yaml:"-"`

	Routing    RoutingConfig     `yaml:"routing"`
	RateLimits RateLimitConfig   `yaml:"rate_limits"`
	QuietHours *QuietHoursConfig `yaml:"quiet_hours,omitempty"`
}

// --- Channel configs (populated from env vars) ---

type WebhookConfig struct {
	URL     string            // WEBHOOK_URL
	Method  string            // WEBHOOK_METHOD (default: POST)
	Headers map[string]string // WEBHOOK_HEADERS (comma-separated key=value pairs)
}

type EmailConfig struct {
	APIKey string // RESEND_API_KEY
	To     string // ALERT_EMAIL_TO
	From   string // ALERT_EMAIL_FROM (default: "VaultGuardian Observer <onboarding@resend.dev>")
}

type SMSConfig struct {
	AccountSID string // TWILIO_SID
	AuthToken  string // TWILIO_AUTH_TOKEN
	From       string // TWILIO_FROM
	To         string // ALERT_SMS_TO
}

type APNsConfig struct {
	KeyPath     string // APNS_KEY_PATH (path to .p8 file)
	KeyID       string // APNS_KEY_ID
	TeamID      string // APNS_TEAM_ID
	BundleID    string // APNS_BUNDLE_ID
	DeviceToken string // APNS_DEVICE_TOKEN
	Production  bool   // APNS_PRODUCTION (default: false → sandbox)
}

type FCMConfig struct {
	CredentialsPath string // FCM_CREDENTIALS_PATH (path to service account JSON)
	ProjectID       string // FCM_PROJECT_ID
	DeviceToken     string // FCM_DEVICE_TOKEN
}

// --- Behavior configs (from YAML) ---

type RoutingConfig struct {
	Malicious  []string `yaml:"malicious"`
	Suspicious []string `yaml:"suspicious"`
	Alert      []string `yaml:"alert"`
}

func (r RoutingConfig) ChannelsFor(sev Severity) []string {
	switch sev {
	case SeverityMalicious:
		return r.Malicious
	case SeveritySuspicious:
		return r.Suspicious
	case SeverityAlert:
		return r.Alert
	}
	return r.Alert
}

type RateLimitConfig struct {
	Webhook string `yaml:"webhook"` // duration string: "5s", "1m", etc.
	Email   string `yaml:"email"`
	SMS     string `yaml:"sms"`
	PushIOS string `yaml:"push_ios"`
	PushFCM string `yaml:"push_fcm"`
}

func (r RateLimitConfig) IntervalFor(channelName string) time.Duration {
	var raw string
	switch channelName {
	case "webhook":
		raw = r.Webhook
	case "email":
		raw = r.Email
	case "sms":
		raw = r.SMS
	case "push/ios":
		raw = r.PushIOS
	case "push/fcm":
		raw = r.PushFCM
	}
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0
	}
	return d
}

type QuietHoursConfig struct {
	Start    string   `yaml:"start"`    // "23:00"
	End      string   `yaml:"end"`      // "07:00"
	Channels []string `yaml:"channels"` // which channels to silence
}

// LoadConfig reads secrets from env vars and behavior from the YAML config
// file. If the YAML doesn't exist, it auto-generates a sensible default.
func LoadConfig(dataDir string) (*Config, error) {
	cfg := &Config{}

	// --- Secrets from env vars (TrimSpace guards against .env trailing whitespace) ---
	cfg.Webhook = WebhookConfig{
		URL:     strings.TrimSpace(os.Getenv("WEBHOOK_URL")),
		Method:  getEnvDefault("WEBHOOK_METHOD", "POST"),
		Headers: parseHeadersEnv(os.Getenv("WEBHOOK_HEADERS")),
	}

	cfg.Email = EmailConfig{
		APIKey: strings.TrimSpace(os.Getenv("RESEND_API_KEY")),
		To:     strings.TrimSpace(os.Getenv("ALERT_EMAIL_TO")),
		From:   getEnvDefault("ALERT_EMAIL_FROM", "VaultGuardian Observer <onboarding@resend.dev>"),
	}

	cfg.SMS = SMSConfig{
		AccountSID: strings.TrimSpace(os.Getenv("TWILIO_SID")),
		AuthToken:  strings.TrimSpace(os.Getenv("TWILIO_AUTH_TOKEN")),
		From:       strings.TrimSpace(getEnvDefault("TWILIO_FROM", "")),
		To:         strings.TrimSpace(os.Getenv("ALERT_SMS_TO")),
	}

	cfg.APNs = APNsConfig{
		KeyPath:     strings.TrimSpace(os.Getenv("APNS_KEY_PATH")),
		KeyID:       strings.TrimSpace(os.Getenv("APNS_KEY_ID")),
		TeamID:      strings.TrimSpace(os.Getenv("APNS_TEAM_ID")),
		BundleID:    getEnvDefault("APNS_BUNDLE_ID", "com.vaultguardian.logwatch"),
		DeviceToken: strings.TrimSpace(os.Getenv("APNS_DEVICE_TOKEN")),
		Production:  os.Getenv("APNS_PRODUCTION") == "true",
	}

	cfg.FCM = FCMConfig{
		CredentialsPath: strings.TrimSpace(os.Getenv("FCM_CREDENTIALS_PATH")),
		ProjectID:       strings.TrimSpace(os.Getenv("FCM_PROJECT_ID")),
		DeviceToken:     strings.TrimSpace(os.Getenv("FCM_DEVICE_TOKEN")),
	}

	// --- Behavior from YAML ---
	configPath := dataDir + "/notifications.yaml"

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Auto-generate default config on first run
		if err := generateDefaultConfig(configPath); err != nil {
			log.Printf("[notifier] Could not write default config: %v (using built-in defaults)", err)
		} else {
			log.Printf("[notifier] Generated default config at %s", configPath)
		}
	}

	// Try to load YAML; fall back to built-in defaults if it fails
	if data, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			log.Printf("[notifier] Invalid config YAML: %v (using built-in defaults)", err)
			applyDefaults(cfg)
		}
	} else {
		applyDefaults(cfg)
	}

	return cfg, nil
}

func applyDefaults(cfg *Config) {
	cfg.Routing = RoutingConfig{
		Malicious:  []string{"webhook", "email", "sms", "push/ios", "push/fcm"},
		Suspicious: []string{"webhook", "email"},
		Alert:      []string{"webhook"},
	}
	cfg.RateLimits = RateLimitConfig{
		Webhook: "5s",
		Email:   "60s",
		SMS:     "300s",
		PushIOS: "30s",
		PushFCM: "30s",
	}
}

func generateDefaultConfig(path string) error {
	content := `# VaultGuardian Observer — Notification Config
# Auto-generated on first run. Edit to customize.
#
# Secrets (API keys, tokens) are configured via environment variables.
# This file controls behavior only: routing, rate limits, quiet hours.

# Severity routing — which channels fire for which threat level.
# Available channels: webhook, email, sms, push/ios, push/fcm
routing:
  malicious:  [webhook, email, sms, push/ios, push/fcm]  # all hands on deck
  suspicious: [webhook, email]                             # important, not urgent
  alert:      [webhook]                                    # informational

# Rate limits per channel per container (prevents alert floods).
# Set to "0s" to disable rate limiting for a channel.
rate_limits:
  webhook:  "5s"
  email:    "60s"
  sms:      "300s"
  push_ios: "30s"
  push_fcm: "30s"

# Quiet hours — silence noisy channels overnight.
# Uncomment to enable.
# quiet_hours:
#   start: "23:00"
#   end: "07:00"
#   channels: [sms, push/ios, push/fcm]
`
	return os.WriteFile(path, []byte(content), 0644)
}

// --- Helpers ---

func getEnvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseHeadersEnv parses "Key1=Value1,Key2=Value2" into a map.
func parseHeadersEnv(raw string) map[string]string {
	headers := make(map[string]string)
	if raw == "" {
		return headers
	}
	for _, pair := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

// FormatAlertBody returns a multi-line plain text summary of an alert.
func FormatAlertBody(alert Alert) string {
	return fmt.Sprintf(
		"Severity: %s\nContainer: %s (%s)\nReason: %s\nLog line: %s\nTime: %s",
		alert.Severity,
		alert.ContainerName,
		shortContainerID(alert.ContainerID),
		alert.Reason,
		truncateStr(alert.LogLine, 500),
		alert.Timestamp.Format(time.RFC3339),
	)
}

func shortContainerID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}
