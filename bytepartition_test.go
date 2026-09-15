// bytepartition_test.go - Part 4: the coordinator key's response-byte-count
// partition. Same request shape with different response lengths must open
// separate investigations; same length still huddles; graveyard tombstones
// only suppress same-length siblings; the evidence-push key built for PinVIP
// is the key the event joined with.
package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/analyzer"
	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/patternstore"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/watcher"
)

// pinKeyCollector extends fakeCollector to capture the correlation key
// passed to PinVIP, so tests can prove PinVIP and Process share one key.
type pinKeyCollector struct {
	fakeCollector
	onPin func(key string)
}

func (p *pinKeyCollector) PinVIP(eventID, correlationKey string, _ rec.LookupRequest) {
	p.onPin(correlationKey)
}

// httpBytesEvent returns an HTTP 200 event whose raw line logs the given
// response byte count field ("-" = unknown, per nginx).
func httpBytesEvent(id, bytesField string) *event.Event {
	return &event.Event{
		ID:             id,
		SourceType:     "docker",
		SourceName:     "captain-nginx",
		NormalizedLine: "blog.example.com POST /xmlrpc.php HTTP/1.1 200",
		Line:           fmt.Sprintf(`1.2.3.4 - - [t] "POST /xmlrpc.php HTTP/1.1" 200 %s`, bytesField),
		Hash:           "hash_" + id,
		Timestamp:      time.Now(),
	}
}

func maliciousLLMResult() *analyzer.AnalysisResult {
	return &analyzer.AnalysisResult{
		Verdict: patternstore.VerdictMalicious,
		Source:  "llm",
		Reason:  "xmlrpc brute-force payload",
	}
}

// partitionHarness wires a resultRouter to a coordinator whose evidence
// check both records the snapshots it sees and returns a configurable
// decision.
type partitionHarness struct {
	router   *resultRouter
	coord    *coordinator.Coordinator
	mu       sync.Mutex
	checked  []coordinator.PendingAlert
	decision coordinator.EvidenceDecision
}

func newPartitionHarness(t *testing.T) *partitionHarness {
	t.Helper()
	h := &partitionHarness{}
	h.coord = coordinator.New(
		t.Context(),
		coordinator.Config{},
		func(coordinator.FinalAlert) {},
		func(p *coordinator.PendingAlert) coordinator.EvidenceDecision {
			h.mu.Lock()
			h.checked = append(h.checked, *p)
			d := h.decision
			h.mu.Unlock()
			return d
		},
		func(coordinator.VerifyRequest) *coordinator.VerifyResult { return nil },
		coordinator.NewSelfSuppressor(),
	)
	h.router = &resultRouter{
		cfg:              Config{},
		collector:        &fakeCollector{},
		alertCoordinator: h.coord,
		sink:             newHTTPOutcomeSink(Config{}),
	}
	return h
}

const partitionKey858 = "blog.example.com|POST|/xmlrpc.php|200|b=858"

func TestBytePartition_DifferentBytesSeparateSameBytesHuddle(t *testing.T) {
	h := newPartitionHarness(t)

	// Same shape, different byte counts → two investigations.
	h.router.routeAlert(httpBytesEvent("evt_a", "858"), maliciousLLMResult(), watcher.LogLine{})
	h.router.routeAlert(httpBytesEvent("evt_b", "1204"), maliciousLLMResult(), watcher.LogLine{})
	if pending, _ := h.coord.Stats(); pending != 2 {
		t.Fatalf("pending = %d, want 2 (different byte counts must not share an investigation)", pending)
	}

	// Same bytes → joins the existing huddle, EventCount increments.
	h.router.routeAlert(httpBytesEvent("evt_c", "858"), maliciousLLMResult(), watcher.LogLine{})
	if pending, _ := h.coord.Stats(); pending != 2 {
		t.Fatalf("pending = %d, want still 2 (same-length sibling must huddle)", pending)
	}
	h.coord.TryResolveVIP(partitionKey858)
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.checked) != 1 {
		t.Fatalf("evidence checks = %d, want 1 (key must address the b=858 investigation)", len(h.checked))
	}
	if h.checked[0].EventCount != 2 {
		t.Errorf("EventCount = %d, want 2 (evt_a + evt_c huddled)", h.checked[0].EventCount)
	}
	if h.checked[0].EventID != "evt_a" {
		t.Errorf("investigation origin = %q, want evt_a", h.checked[0].EventID)
	}
}

func TestBytePartition_UnknownBytesIsItsOwnPartition(t *testing.T) {
	h := newPartitionHarness(t)

	h.router.routeAlert(httpBytesEvent("evt_known", "858"), maliciousLLMResult(), watcher.LogLine{})
	// nginx logs "-" when the byte count is unknown; extractResponseBytes
	// returns 0 and the key partitions to b=unknown - never synthesized.
	h.router.routeAlert(httpBytesEvent("evt_unknown1", "-"), maliciousLLMResult(), watcher.LogLine{})
	if pending, _ := h.coord.Stats(); pending != 2 {
		t.Fatalf("pending = %d, want 2 (unknown-bytes event must not join a known-bytes huddle)", pending)
	}

	// A second unknown-bytes sibling huddles with the first.
	h.router.routeAlert(httpBytesEvent("evt_unknown2", "-"), maliciousLLMResult(), watcher.LogLine{})
	if pending, _ := h.coord.Stats(); pending != 2 {
		t.Fatalf("pending = %d, want still 2 (unknown huddles with unknown)", pending)
	}
	h.coord.TryResolveVIP("blog.example.com|POST|/xmlrpc.php|200|b=unknown")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.checked) != 1 || h.checked[0].EventCount != 2 {
		t.Errorf("unknown-partition check: got %d checks (EventCount %v), want 1 check with EventCount 2",
			len(h.checked), eventCounts(h.checked))
	}
}

func TestBytePartition_GraveyardSuppressesOnlySameLength(t *testing.T) {
	h := newPartitionHarness(t)
	h.decision = coordinator.EvidenceDecision{
		Downgraded: true,
		Reason:     "transport evidence confirms rejection",
	}

	// Finalize the b=858 investigation via the evidence push path.
	h.router.routeAlert(httpBytesEvent("evt_first", "858"), maliciousLLMResult(), watcher.LogLine{})
	h.coord.TryResolveVIP(partitionKey858)
	if pending, graveyard := h.coord.Stats(); pending != 0 || graveyard != 1 {
		t.Fatalf("after finalize: pending=%d graveyard=%d, want 0/1", pending, graveyard)
	}

	// A same-length sibling inside the graveyard window is still suppressed.
	h.router.routeAlert(httpBytesEvent("evt_same", "858"), maliciousLLMResult(), watcher.LogLine{})
	if pending, _ := h.coord.Stats(); pending != 0 {
		t.Errorf("pending = %d after same-length sibling, want 0 (tombstone must suppress b=858)", pending)
	}

	// A DIFFERENT-length sibling opens a NEW investigation instead of
	// vanishing into the tombstone - the divergent-length success case.
	h.router.routeAlert(httpBytesEvent("evt_divergent", "1204"), maliciousLLMResult(), watcher.LogLine{})
	if pending, _ := h.coord.Stats(); pending != 1 {
		t.Errorf("pending = %d after divergent-length sibling, want 1 (b=1204 must open its own investigation)", pending)
	}
}

// TestBytePartition_EvidencePushAddressesJoinedInvestigation proves the key
// is built once and shared by PinVIP and Process: the VIP push callback key
// recorded at PinVIP time resolves the exact investigation the event joined.
func TestBytePartition_EvidencePushAddressesJoinedInvestigation(t *testing.T) {
	h := newPartitionHarness(t)

	var pinnedKeys []string
	pinRecorder := &pinKeyCollector{onPin: func(key string) { pinnedKeys = append(pinnedKeys, key) }}
	h.router.collector = pinRecorder

	h.router.routeAlert(httpBytesEvent("evt_push", "858"), maliciousLLMResult(), watcher.LogLine{})
	if len(pinnedKeys) != 1 {
		t.Fatalf("PinVIP keys recorded = %d, want 1", len(pinnedKeys))
	}
	if pinnedKeys[0] != partitionKey858 {
		t.Fatalf("PinVIP key = %q, want %q", pinnedKeys[0], partitionKey858)
	}

	// Dispatch through the recorded key, exactly as the VIP push does.
	h.coord.TryResolveVIP(pinnedKeys[0])
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.checked) != 1 || h.checked[0].EventID != "evt_push" {
		t.Errorf("evidence check via pinned key: %d checks, want 1 for evt_push", len(h.checked))
	}
}

func eventCounts(snaps []coordinator.PendingAlert) []int {
	out := make([]int, len(snaps))
	for i, s := range snaps {
		out[i] = s.EventCount
	}
	return out
}
