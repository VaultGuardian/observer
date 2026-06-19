package notifier

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// capturingNotifier records the last alert it was handed. Send runs on the
// dispatcher's worker goroutine, so access is mutex-guarded.
type capturingNotifier struct {
	mu   sync.Mutex
	last Alert
	got  chan struct{}
}

func newCapturingNotifier() *capturingNotifier {
	return &capturingNotifier{got: make(chan struct{}, 1)}
}

func (c *capturingNotifier) Send(ctx context.Context, alert Alert) error {
	c.mu.Lock()
	c.last = alert
	c.mu.Unlock()
	select {
	case c.got <- struct{}{}:
	default:
	}
	return nil
}

func (c *capturingNotifier) Name() string { return "webhook" }

func (c *capturingNotifier) lastAlert(t *testing.T) Alert {
	t.Helper()
	select {
	case <-c.got:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert delivery")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// newCapturingDispatcher mirrors newTestDispatcher but wires a capturing
// notifier and lets the caller seed server-identity labels on the config.
func newCapturingDispatcher(t *testing.T, n *capturingNotifier, hostname, ip string) *Dispatcher {
	t.Helper()
	cfg := &Config{
		Routing: RoutingConfig{
			Malicious:  []string{n.Name()},
			Suspicious: []string{n.Name()},
			Alert:      []string{n.Name()},
		},
		Hostname: hostname,
		ServerIP: ip,
	}
	d := &Dispatcher{
		channels: []Notifier{n},
		config:   cfg,
		limiters: make(map[string]*rateLimiter),
		queues:   make(map[string]chan Alert),
		stopCh:   make(chan struct{}),
	}
	q := make(chan Alert, defaultQueueSize)
	d.queues[n.Name()] = q
	d.wg.Add(1)
	go d.runWorker(n, q)
	return d
}

// TestDispatchStampsServerIdentity verifies the dispatcher stamps Hostname and
// ServerIP from its config onto the delivered alert — even though the inbound
// Alert leaves those fields empty.
func TestDispatchStampsServerIdentity(t *testing.T) {
	n := newCapturingNotifier()
	d := newCapturingDispatcher(t, n, "edge-01", "10.0.0.5")
	defer d.Stop(context.Background())

	d.Dispatch(context.Background(), Alert{Severity: SeverityMalicious})

	got := n.lastAlert(t)
	if got.Hostname != "edge-01" {
		t.Errorf("Hostname = %q, want %q", got.Hostname, "edge-01")
	}
	if got.ServerIP != "10.0.0.5" {
		t.Errorf("ServerIP = %q, want %q", got.ServerIP, "10.0.0.5")
	}
}

// TestDispatchEmptyServerIdentity verifies an unconfigured dispatcher leaves
// the labels empty (so the email/webhook simply omits them).
func TestDispatchEmptyServerIdentity(t *testing.T) {
	n := newCapturingNotifier()
	d := newCapturingDispatcher(t, n, "", "")
	defer d.Stop(context.Background())

	d.Dispatch(context.Background(), Alert{Severity: SeverityMalicious})

	got := n.lastAlert(t)
	if got.Hostname != "" {
		t.Errorf("Hostname = %q, want empty", got.Hostname)
	}
	if got.ServerIP != "" {
		t.Errorf("ServerIP = %q, want empty", got.ServerIP)
	}
}

// TestFormatEmailHTMLServerRow checks the Server row renders host + IP when
// present and is escaped, and is absent entirely when the hostname is empty.
func TestFormatEmailHTMLServerRow(t *testing.T) {
	withHost := formatEmailHTML(Alert{
		Severity: SeverityMalicious,
		Hostname: "edge-01",
		ServerIP: "10.0.0.5",
	})
	if !strings.Contains(withHost, ">Server<") {
		t.Error("expected a Server row when hostname is set")
	}
	if !strings.Contains(withHost, "edge-01") || !strings.Contains(withHost, "10.0.0.5") {
		t.Error("expected hostname and IP rendered in the Server row")
	}

	// Escaping: a hostile hostname must not produce raw markup.
	escaped := formatEmailHTML(Alert{
		Severity: SeverityMalicious,
		Hostname: "<script>x</script>",
	})
	if strings.Contains(escaped, "<script>x</script>") {
		t.Error("hostname was not HTML-escaped")
	}
	if !strings.Contains(escaped, "&lt;script&gt;") {
		t.Error("expected escaped hostname entity in output")
	}

	noHost := formatEmailHTML(Alert{Severity: SeverityMalicious})
	if strings.Contains(noHost, ">Server<") {
		t.Error("Server row must be absent when hostname is empty")
	}
}
