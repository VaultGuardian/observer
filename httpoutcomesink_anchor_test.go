// httpoutcomesink_anchor_test.go
package main

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/requestcorr"
)

// Real strings from the soak box: the swarm container names the sink actually
// sees, and the values an operator types (or pastes out of coordinator logs)
// into LINEAGE_ANCHOR_SOURCES.
const (
	liveNginxContainer = "captain-nginx.1.4ab3nsk74355533fkk0iadqza"
	liveWPContainer    = "wp.1.lu52qmkbhnt3zrqsboyo11f88"
)

func anchorCfg(names ...string) Config {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return Config{LineageEnabled: true, LineageAnchorSources: set}
}

// The bug: matching was exact against the sink's bare source name, so the
// documented "captain-nginx" never matched the running container and the
// feature stayed silently off. Both sides are normalized now, with the raw
// comparison kept so pasted full names and non-docker sources still work.
func TestAnchorSourceMatching(t *testing.T) {
	cases := []struct {
		name       string
		configured []string
		source     string
		want       bool
	}{
		// The documented value must match the live container name.
		{"service_name_matches_swarm_container", []string{"captain-nginx"}, liveNginxContainer, true},
		// Copied from coordinator logs, which print the scope key.
		{"scoped_service_name_matches", []string{"docker:captain-nginx"}, liveNginxContainer, true},
		{"scoped_full_name_matches", []string{"docker:" + liveNginxContainer}, liveNginxContainer, true},
		// A pasted full container name keeps working (raw match, and normalized).
		{"full_name_matches_itself", []string{liveNginxContainer}, liveNginxContainer, true},
		// A plain (non-swarm) container name is unaffected by normalization.
		{"plain_name_matches_itself", []string{"captain-nginx"}, "captain-nginx", true},

		// Normalization must not widen the match to other services.
		{"other_service_swarm_name_does_not_match", []string{"captain-nginx"}, liveWPContainer, false},
		{"other_service_plain_name_does_not_match", []string{"captain-nginx"}, "wp", false},
		{"backend_is_not_the_anchor", []string{liveNginxContainer}, liveWPContainer, false},

		// Non-docker sources match only themselves: no prefix, no suffix.
		{"journal_source_matches_itself", []string{"journal:sshd"}, "journal:sshd", true},
		{"journal_source_needs_its_prefix", []string{"sshd"}, "journal:sshd", false},
		{"journal_prefix_is_not_stripped", []string{"journal:sshd"}, "sshd", false},

		// A swarm-shaped suffix is only stripped when it really is one.
		{"short_id_suffix_is_not_a_task_suffix", []string{"captain-nginx"}, "captain-nginx.1.4ab3ns", false},
		{"dotted_name_without_slot_is_kept", []string{"captain-nginx"}, "captain-nginx.4ab3nsk74355533fkk0iadqza", false},

		{"empty_source_never_anchors", []string{"captain-nginx"}, "", false},
		{"no_anchors_configured", nil, liveNginxContainer, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newHTTPOutcomeSink(anchorCfg(tc.configured...))
			if got := s.isAnchorSource(tc.source); got != tc.want {
				t.Errorf("isAnchorSource(%q) with config %v = %v, want %v",
					tc.source, tc.configured, got, tc.want)
			}
		})
	}
}

// The startup line must show what sources are actually matched against, so a
// mis-typed anchor is visible at boot rather than as a lineage that never
// anchors. Duplicates collapse; order is stable.
func TestNormalizedAnchorNamesForStartupLog(t *testing.T) {
	cases := []struct {
		name       string
		configured []string
		want       []string
	}{
		{"all_three_spellings_collapse", []string{
			"captain-nginx", "docker:captain-nginx", liveNginxContainer,
		}, []string{"captain-nginx"}},
		{"sorted_and_mixed_sources", []string{
			"journal:sshd", "docker:" + liveWPContainer, "captain-nginx",
		}, []string{"captain-nginx", "journal:sshd", "wp"}},
		{"none_configured", nil, []string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := anchorCfg(tc.configured...)
			got := normalizedAnchorNames(cfg.LineageAnchorSources)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("normalizedAnchorNames(%v) = %v, want %v", tc.configured, got, tc.want)
			}
		})
	}
}

// End-to-end on the real path: the double-escalation coalesce (one request
// logged by both nginx and its backend) must work with the live swarm
// container name as the anchor's source, against a config of "captain-nginx".
// Before the fix the nginx observation was unanchored, so nothing coalesced.
func TestSinkCoalescesWithSwarmAnchorContainerName(t *testing.T) {
	clk := &manualClock{t: time.Unix(1_700_000_000, 0)}
	sink := newHTTPOutcomeSink(anchorCfg("captain-nginx"))
	sink.tracker = requestcorr.New(requestcorr.Config{}, clk)

	var mu sync.Mutex
	notifs := 0
	writes := []string{}
	mkNotify := func() func() bool { return func() bool { mu.Lock(); notifs++; mu.Unlock(); return true } }
	mkWrite := func(who string) func(bool) {
		return func(bool) { mu.Lock(); writes = append(writes, who); mu.Unlock() }
	}

	sink.Emit(httpOutcome{
		eventID: "ev_backend", rawLine: rawWithVgrid, source: liveWPContainer,
		outcome: requestcorr.OutcomeEscalated, timestamp: clk.Now(),
		notify: mkNotify(), writeFinding: mkWrite("backend"),
	})
	sink.Emit(httpOutcome{
		eventID: "ev_nginx", rawLine: rawWithVgrid, source: liveNginxContainer,
		outcome: requestcorr.OutcomeEscalated, timestamp: clk.Now(),
		notify: mkNotify(), writeFinding: mkWrite("nginx"),
	})

	mu.Lock()
	if notifs != 1 {
		mu.Unlock()
		t.Fatalf("expected exactly 1 notification (deduped), got %d", notifs)
	}
	mu.Unlock()

	clk.advance(requestcorr.DefaultSettleWindow + time.Second)
	sink.apply(sink.tracker.Tick())

	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 1 || writes[0] != "nginx" {
		t.Fatalf("expected 1 representative row from the nginx anchor, got %v", writes)
	}
	c := sink.correlationStats()
	if c.Counters.ObservationsAbsorbed != 1 || c.Counters.NotificationsAvoided != 1 {
		t.Fatalf("counters off: absorbed=%d avoided=%d",
			c.Counters.ObservationsAbsorbed, c.Counters.NotificationsAvoided)
	}
}
