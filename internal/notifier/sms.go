package notifier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SMSNotifier sends alert SMS messages via the Twilio REST API.
type SMSNotifier struct {
	config     SMSConfig
	httpClient *http.Client
}

func NewSMSNotifier(cfg SMSConfig) *SMSNotifier {
	return &SMSNotifier{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (s *SMSNotifier) Name() string { return "sms" }

func (s *SMSNotifier) Send(ctx context.Context, alert Alert) error {
	// Build the SMS body — keep it short, SMS has a 1600 char limit
	// and you pay per segment (160 chars each)
	body := fmt.Sprintf("[VG] %s\n%s: %s\n%s",
		strings.ToUpper(string(alert.Severity)),
		alert.ContainerName,
		truncateStr(alert.Reason, 120),
		alert.Timestamp.Format("15:04:05"),
	)

	endpoint := fmt.Sprintf(
		"https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json",
		s.config.AccountSID,
	)

	form := url.Values{
		"To":   {s.config.To},
		"From": {s.config.From},
		"Body": {body},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("creating SMS request: %w", err)
	}

	req.SetBasicAuth(s.config.AccountSID, s.config.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("SMS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("twilio returned %d: %s", resp.StatusCode, string(respBody))
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}
