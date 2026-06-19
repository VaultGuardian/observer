package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"time"
)

// EmailNotifier sends alert emails via the Resend API.
type EmailNotifier struct {
	config     EmailConfig
	httpClient *http.Client
}

func NewEmailNotifier(cfg EmailConfig) *EmailNotifier {
	if cfg.From == "" {
		// Resend's pre-verified sandbox sender — works without domain
		// verification, so first-time installs send successfully out of
		// the box. Users override via ALERT_EMAIL_FROM once they verify
		// their own domain in their Resend account.
		cfg.From = "VaultGuardian Observer <onboarding@resend.dev>"
	}
	return &EmailNotifier{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (e *EmailNotifier) Name() string { return "email" }

func (e *EmailNotifier) Send(ctx context.Context, alert Alert) error {
	subject := formatAlertTitle(alert)
	body := formatEmailHTML(alert)

	payload := map[string]interface{}{
		"from":    e.config.From,
		"to":      []string{e.config.To},
		"subject": subject,
		"html":    body,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling email payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.resend.com/emails", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("creating email request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.config.APIKey)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("email request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend returned %d: %s", resp.StatusCode, string(respBody))
	}

	io.Copy(io.Discard, resp.Body)
	return nil
}

// esc is a shorthand for html.EscapeString. Every dynamic field interpolated
// into the HTML email body MUST pass through this function to prevent injection.
//
// v0.52 P0 fix: prior to this fix, all dynamic
// fields were interpolated via raw fmt.Sprintf %s — an attacker sending
// GET /<script>alert(1)</script> would render executable HTML in the
// operator's email client. Ironic for a security product.
func esc(s string) string {
	return html.EscapeString(s)
}

func formatEmailHTML(alert Alert) string {
	severityColor := "#f59e0b"
	switch alert.Severity {
	case SeverityMalicious:
		severityColor = "#ef4444"
	case SeveritySuspicious:
		severityColor = "#f59e0b"
	case SeverityAlert:
		severityColor = "#3b82f6"
	}

	// Build evidence section (REC enrichment — may or may not be available)
	evidenceHTML := ""
	if alert.Evidence != nil && alert.Evidence.HasEvidence() {
		t := alert.Evidence.Transport
		evidenceHTML = fmt.Sprintf(`
      <div style="margin-top:16px;padding:12px;background:#fefce8;border:1px solid #fde68a;border-radius:6px;">
        <div style="font-weight:600;font-size:13px;color:#92400e;margin-bottom:8px;">Response Evidence</div>
        <table style="width:100%%;border-collapse:collapse;font-size:13px;">
          <tr>
            <td style="padding:4px 0;color:#6b7280;width:120px;">Correlation</td>
            <td style="padding:4px 0;">%s (%d candidates)</td>
          </tr>`,
			esc(string(alert.Evidence.CorrelationConfidence)), alert.Evidence.CandidateCount)

		if t != nil {
			evidenceHTML += fmt.Sprintf(`
          <tr>
            <td style="padding:4px 0;color:#6b7280;">Response Code</td>
            <td style="padding:4px 0;font-weight:600;">%d</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#6b7280;">Content-Type</td>
            <td style="padding:4px 0;">%s</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#6b7280;">Content-Length</td>
            <td style="padding:4px 0;">%d bytes</td>
          </tr>
          <tr>
            <td style="padding:4px 0;color:#6b7280;">Body Hash</td>
            <td style="padding:4px 0;"><code style="background:#f3f4f6;padding:2px 6px;border-radius:3px;font-size:11px;">sha256:%.16s</code></td>
          </tr>`,
				t.StatusCode, esc(t.ContentType), t.ContentLength, esc(t.BodyPreviewHash))
		}

		if alert.Evidence.Disclosure != nil {
			evidenceHTML += fmt.Sprintf(`
          <tr>
            <td style="padding:4px 0;color:#6b7280;">Disclosure</td>
            <td style="padding:4px 0;font-weight:600;">%s</td>
          </tr>`,
				esc(alert.Evidence.Disclosure.DisclosureSummary))
		}

		if alert.Evidence.SafeBodyPreview != "" {
			evidenceHTML += fmt.Sprintf(`
          <tr>
            <td colspan="2" style="padding:8px 0 0 0;">
              <div style="padding:8px;background:#f3f4f6;border-radius:4px;font-family:'SF Mono',Monaco,monospace;font-size:11px;white-space:pre-wrap;color:#374151;">%s</div>
            </td>
          </tr>`,
				esc(truncateStr(alert.Evidence.SafeBodyPreview, 500)))
		}

		evidenceHTML += `
        </table>
      </div>`
	} else if alert.Evidence != nil {
		// Evidence was attempted but unavailable — show why
		evidenceHTML = fmt.Sprintf(`
      <div style="margin-top:16px;padding:8px 12px;background:#f3f4f6;border-radius:6px;font-size:12px;color:#9ca3af;">
        Response Evidence: %s
      </div>`, esc(string(alert.Evidence.Status)))
	}

	// Server-identity row. Shown only when a hostname is present:
	// "hostname (ip)" when the egress IP was detected, hostname alone
	// otherwise. Both values are attacker-irrelevant but escaped defensively
	// per the esc() P0 invariant. Empty hostname adds no markup at all.
	serverRow := ""
	if alert.Hostname != "" {
		serverVal := esc(alert.Hostname)
		if alert.ServerIP != "" {
			serverVal = fmt.Sprintf(`%s <span style="color:#9ca3af;">(%s)</span>`,
				esc(alert.Hostname), esc(alert.ServerIP))
		}
		serverRow = fmt.Sprintf(`
        <tr>
          <td style="padding:8px 0;color:#6b7280;width:120px;">Server</td>
          <td style="padding:8px 0;">%s</td>
        </tr>`, serverVal)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:24px;background:#f9fafb;">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;border:1px solid #e5e7eb;overflow:hidden;">
    <div style="padding:16px 24px;background:%s;color:#fff;">
      <h2 style="margin:0;font-size:16px;font-weight:600;">VaultGuardian Observer Alert</h2>
    </div>
    <div style="padding:24px;">
      <table style="width:100%%;border-collapse:collapse;font-size:14px;">%s
        <tr>
          <td style="padding:8px 0;color:#6b7280;width:120px;">Severity</td>
          <td style="padding:8px 0;font-weight:600;">%s</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#6b7280;">Container</td>
          <td style="padding:8px 0;">%s <span style="color:#9ca3af;">(%s)</span></td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#6b7280;">Reason</td>
          <td style="padding:8px 0;">%s</td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#6b7280;">Matched Via</td>
          <td style="padding:8px 0;"><code style="background:#f3f4f6;padding:2px 6px;border-radius:3px;font-size:12px;">%s</code></td>
        </tr>
        <tr>
          <td style="padding:8px 0;color:#6b7280;">Time</td>
          <td style="padding:8px 0;">%s</td>
        </tr>
      </table>
      <div style="margin-top:16px;padding:12px;background:#f3f4f6;border-radius:6px;font-family:'SF Mono',Monaco,monospace;font-size:13px;word-break:break-all;color:#374151;">
        %s
      </div>%s
      <div style="margin-top:8px;font-family:'SF Mono',Monaco,monospace;font-size:10px;color:#9ca3af;">
        event=%s hash=%s
      </div>
    </div>
    <div style="padding:12px 24px;background:#f9fafb;border-top:1px solid #e5e7eb;font-size:12px;color:#9ca3af;">
      Sent by VaultGuardian Observer
    </div>
  </div>
</body>
</html>`,
		severityColor,               // not attacker-controlled (switch output)
		serverRow,                   // already escaped field-by-field above
		esc(string(alert.Severity)), // enum but escape defensively
		esc(alert.ContainerName),    // ATTACKER-CONTROLLED
		esc(alert.ContainerID[:minInt(12, len(alert.ContainerID))]), // hex but escape defensively
		esc(alert.Reason),                          // LLM-GENERATED
		esc(alert.MatchedVia),                      // internal but escape defensively
		alert.Timestamp.Format(time.RFC3339),       // time.Format — safe
		esc(truncateStr(alert.LogLine, 1000)),      // ATTACKER-CONTROLLED — raw log line
		evidenceHTML,                               // already escaped field-by-field above
		esc(alert.EventID),                         // UUID — safe but escape defensively
		esc(truncateStr(alert.NormalizedHash, 16)), // hex — safe but escape defensively
	)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
