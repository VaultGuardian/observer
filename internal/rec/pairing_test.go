// internal/rec/pairing_test.go
//
// Session A plumbing tests: RequestTimestamp travels from the wire pairing
// into CapturedResponse, and TransportEvidence carries RequestDuration /
// LatencySource only for wire-paired responses. ResponseLatency (correlation
// skew, retired in Session B) must stay computed exactly as before.
package rec

import (
	"bufio"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// pairingStream builds an httpStream over a synthetic server→client flow,
// wired to the given sniffer — the same shape httpStreamFactory.New produces,
// minus the goroutine and the tcpreader (runResponse takes the reader
// directly, so no live capture machinery is needed).
func pairingStream(s *sniffer) *httpStream {
	return &httpStream{
		// Server→client direction: flowKey() reverses this to the canonical
		// client→server key that handleInlineRequest stores requests under.
		netFlow:   gopacket.NewFlow(layers.EndpointIPv4, []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}),
		transFlow: gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 80}, []byte{0x9c, 0x40}),
		sniffer:   s,
		maxBody:   DefaultMaxBodyBytes,
	}
}

func TestPairedResponseCarriesRequestTimestamp(t *testing.T) {
	s := newSniffer(NewRingBuffer(DefaultBufferConfig()), "", []int{80}, 64,
		DefaultMaxBodyBytes, DefaultVXLANPort, false,
		DefaultReassemblyConfig(), DefaultFlowConfig())

	var got []CapturedResponse
	s.onCapture = func(c CapturedResponse) { got = append(got, c) }

	hs := pairingStream(s)
	fk := hs.flowKey()

	before := time.Now()
	s.handleInlineRequest(fk, 1, []byte("GET /a HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"))
	// Guarantee the response timestamp lands strictly after the request's.
	time.Sleep(2 * time.Millisecond)

	hs.runResponse(bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi")))

	if len(got) != 1 {
		t.Fatalf("expected 1 captured response, got %d", len(got))
	}
	c := got[0]
	if c.Method != "GET" || c.Path != "/a" {
		t.Fatalf("response not paired with request: method=%q path=%q", c.Method, c.Path)
	}
	if c.RequestTimestamp.IsZero() {
		t.Fatal("paired response has zero RequestTimestamp")
	}
	if c.RequestTimestamp.Before(before) {
		t.Fatalf("RequestTimestamp %v predates request parse %v", c.RequestTimestamp, before)
	}
	if d := c.Timestamp.Sub(c.RequestTimestamp); d <= 0 {
		t.Fatalf("expected positive wire-pair duration, got %v", d)
	}
}

func TestOrphanResponseHasNoRequestTimestamp(t *testing.T) {
	s := newSniffer(NewRingBuffer(DefaultBufferConfig()), "", []int{80}, 64,
		DefaultMaxBodyBytes, DefaultVXLANPort, false,
		DefaultReassemblyConfig(), DefaultFlowConfig())

	var got []CapturedResponse
	s.onCapture = func(c CapturedResponse) { got = append(got, c) }

	hs := pairingStream(s)

	// No request enqueued — the response queues as an orphan candidate and
	// onCapture does not fire until cleanup expires it.
	hs.runResponse(bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi")))

	if len(got) != 0 {
		t.Fatalf("orphan response fired onCapture immediately: %+v", got)
	}
}

// testEvidenceCollector mirrors the white-box liveCollector setup used by
// the existing collector tests (collector_test.go).
func testEvidenceCollector() *liveCollector {
	lc := &liveCollector{
		buffer:      NewRingBuffer(DefaultBufferConfig()),
		vipPins:     make(map[string]*vipPin),
		vipEvidence: make(map[string]CapturedResponse),
	}
	lc.running.Store(true)
	return lc
}

func TestTransportEvidenceRequestDuration_Paired(t *testing.T) {
	lc := testEvidenceCollector()
	now := time.Now()

	lc.buffer.Insert(CapturedResponse{
		Timestamp:        now,
		RequestTimestamp: now.Add(-150 * time.Millisecond),
		Method:           "GET",
		Path:             "/x",
		StatusCode:       200,
		ContentType:      "text/plain",
		ContentLength:    2,
		BodyPreview:      []byte("hi"),
		BodyPreviewHash:  HashBody([]byte("hi")),
	})

	logTS := now.Add(-100 * time.Millisecond)
	ev := lc.Lookup(LookupRequest{
		Method:     "GET",
		Path:       "/x",
		StatusCode: 200,
		Timestamp:  logTS,
		Window:     time.Second,
	})
	if ev == nil || ev.Transport == nil {
		t.Fatalf("Lookup returned no transport evidence: %+v", ev)
	}

	if ev.Transport.RequestDuration != 150*time.Millisecond {
		t.Errorf("RequestDuration = %v, want 150ms", ev.Transport.RequestDuration)
	}
	if ev.Transport.LatencySource != "wire_pair" {
		t.Errorf("LatencySource = %q, want \"wire_pair\"", ev.Transport.LatencySource)
	}
	// ResponseLatency stays the pre-existing correlation-skew computation:
	// absDuration(captured timestamp − log line timestamp).
	if want := absDuration(now.Sub(logTS)); ev.Transport.ResponseLatency != want {
		t.Errorf("ResponseLatency = %v, want %v (unchanged computation)", ev.Transport.ResponseLatency, want)
	}
}

func TestTransportEvidenceRequestDuration_Orphan(t *testing.T) {
	lc := testEvidenceCollector()
	now := time.Now()

	// Orphan: no request info, zero RequestTimestamp.
	lc.buffer.Insert(CapturedResponse{
		Timestamp:       now,
		StatusCode:      200,
		ContentType:     "text/plain",
		ContentLength:   2,
		BodyPreview:     []byte("hi"),
		BodyPreviewHash: HashBody([]byte("hi")),
	})

	logTS := now.Add(-100 * time.Millisecond)
	ev := lc.Lookup(LookupRequest{
		Method:     "GET",
		Path:       "/x",
		StatusCode: 200,
		Timestamp:  logTS,
		Window:     time.Second,
	})
	if ev == nil || ev.Transport == nil {
		t.Fatalf("Lookup returned no transport evidence: %+v", ev)
	}

	if ev.Transport.CaptureMode != "single_segment_preview_orphan" {
		t.Fatalf("expected orphan capture mode, got %q", ev.Transport.CaptureMode)
	}
	if ev.Transport.RequestDuration != 0 {
		t.Errorf("orphan RequestDuration = %v, want 0", ev.Transport.RequestDuration)
	}
	if ev.Transport.LatencySource != "" {
		t.Errorf("orphan LatencySource = %q, want empty", ev.Transport.LatencySource)
	}
	if want := absDuration(now.Sub(logTS)); ev.Transport.ResponseLatency != want {
		t.Errorf("ResponseLatency = %v, want %v (unchanged computation)", ev.Transport.ResponseLatency, want)
	}
}
