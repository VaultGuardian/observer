package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookNotifier sends alerts as JSON to any HTTP endpoint.
// Works out of the box with Slack, Discord, Teams, PagerDuty,
// Opsgenie, Telegram, n8n, Zapier, and any custom webhook.
type WebhookNotifier struct {
	config     WebhookConfig
	httpClient *http.Client
}

// WebhookPayload is the JSON body sent to the webhook endpoint.
// Designed to be compatible with Slack/Discord incoming webhooks
// while carrying full alert context for custom integrations.
type WebhookPayload struct {
	// Slack/Discord compatible fields
	Text string `json:"text"`

	// Full structured data for custom consumers
	Alert  Alert  `json:"alert"`
	Source string `json:"source"`
}

func NewWebhookNotifier(cfg WebhookConfig) *WebhookNotifier {
	if cfg.Method == "" {
		cfg.Method = "POST"
	}
	return &WebhookNotifier{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (w *WebhookNotifier) Name() string { return "webhook" }

func (w *WebhookNotifier) Send(ctx context.Context, alert Alert) error {
	payload := WebhookPayload{
		Text:   formatAlertTitle(alert),
		Alert:  alert,
		Source: "vaultguardian-observer",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, w.config.Method, w.config.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "VaultGuardian-Observer/1.0")

	// Apply custom headers (for auth tokens, etc.)
	for k, v := range w.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	return nil
}