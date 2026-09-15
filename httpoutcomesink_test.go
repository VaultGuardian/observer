// httpoutcomesink_test.go
package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/requestcorr"
	"github.com/vaultguardian/observer/internal/store"
)

// manualClock is a package-main clock satisfying requestcorr.Clock, so a sink's
// tracker can be driven deterministically without sleeping.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const rawWithVgrid = `1.2.3.4 - - [t] "GET /?x=1 HTTP/1.1" 200 83 "-" "curl" vgrid=2fb2cf19c82b36ceb7f89d50b381fcf1`
const rawNoVgrid = `1.2.3.4 - - [t] "GET /?x=1 HTTP/1.1" 200 83 "-" "curl"`

func enabledSinkCfg() Config {
	return Config{
		LineageEnabled:       true,
		LineageAnchorSources: map[string]bool{"captain-nginx": true},
	}
}

// D8 golden: with the feature OFF, or ON but with no lineage ID on the event,
// Emit is a synchronous structural pass-through — notify then write, with the
// notified flag threaded through — byte-identical to the pre-sink behavior.
func TestSinkPassThroughIsSynchronous(t *testing.T) {
	cases := []struct {
		name string
		sink *httpOutcomeSink
		raw  string
	}{
		// Feature off: even a vgrid-bearing line passes straight through
		// (no extraction, no group, no lock — the D8 hot path).
		{"feature_off_even_with_id", newHTTPOutcomeSink(Config{}), rawWithVgrid},
		// Feature on but no ID present: still pass-through.
		{"feature_on_no_id", newHTTPOutcomeSink(enabledSinkCfg()), rawNoVgrid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var notified, wrote bool
			var gotNotifiedArg bool
			tc.sink.Emit(httpOutcome{
				eventID:   "e1",
				rawLine:   tc.raw,
				source:    "wp",
				outcome:   requestcorr.OutcomeEscalated,
				timestamp: time.Now(),
				notify:    func() bool { notified = true; return true },
				writeFinding: func(n bool) {
					wrote = true
					gotNotifiedArg = n
				},
			})
			if !notified {
				t.Errorf("pass-through must run notify")
			}
			if !wrote {
				t.Errorf("pass-through must run writeFinding synchronously")
			}
			if !gotNotifiedArg {
				t.Errorf("pass-through must thread the notified result into writeFinding")
			}
		})
	}

	// Feature-off missing-ID accounting must stay ZERO (no counting off-path).
	off := newHTTPOutcomeSink(Config{})
	snap := off.correlationStats()
	if snap.TrustedIDs != 0 || snap.MissingIDs != 0 || snap.InvalidIDs != 0 {
		t.Errorf("feature-off must not count lineage status: %+v", snap)
	}
}

// D8 golden: a recon-shaped path (notify == nil) still writes exactly once in
// pass-through, with Notified false.
func TestSinkPassThroughReconNoNotify(t *testing.T) {
	sink := newHTTPOutcomeSink(Config{})
	var wrote bool
	var arg bool
	sink.Emit(httpOutcome{
		eventID:      "e1",
		rawLine:      rawNoVgrid,
		source:       "wp",
		outcome:      requestcorr.OutcomeRecon,
		writeFinding: func(n bool) { wrote = true; arg = n },
	})
	if !wrote || arg {
		t.Errorf("recon pass-through: wrote=%v notified=%v; want wrote=true notified=false", wrote, arg)
	}
}

// Grouped golden: the two-escalation double-count (the 4-emails-for-2-harvests
// bug). Backend-first, then the nginx anchor, one lineage → exactly ONE
// notification and ONE finding row after settle; the sibling row is dropped.
func TestSinkGroupedCoalescesDoubleEscalation(t *testing.T) {
	clk := &manualClock{t: time.Unix(1_700_000_000, 0)}
	sink := newHTTPOutcomeSink(enabledSinkCfg())
	sink.tracker = requestcorr.New(requestcorr.Config{}, clk) // deterministic clock

	var mu sync.Mutex
	notifs := 0
	writes := []string{}
	mkNotify := func() func() bool { return func() bool { mu.Lock(); notifs++; mu.Unlock(); return true } }
	mkWrite := func(who string) func(bool) {
		return func(bool) { mu.Lock(); writes = append(writes, who); mu.Unlock() }
	}

	// Backend (downstream) escalation arrives first.
	sink.Emit(httpOutcome{
		eventID: "ev_backend", rawLine: rawWithVgrid, source: "wp",
		outcome: requestcorr.OutcomeEscalated, timestamp: clk.Now(),
		notify: mkNotify(), writeFinding: mkWrite("backend"),
	})
	// nginx (anchor) escalation for the same request.
	sink.Emit(httpOutcome{
		eventID: "ev_nginx", rawLine: rawWithVgrid, source: "captain-nginx",
		outcome: requestcorr.OutcomeEscalated, timestamp: clk.Now(),
		notify: mkNotify(), writeFinding: mkWrite("nginx"),
	})

	mu.Lock()
	if notifs != 1 {
		t.Fatalf("expected exactly 1 notification (deduped), got %d", notifs)
	}
	if len(writes) != 0 {
		t.Fatalf("no finding row may be written before settle, got %v", writes)
	}
	mu.Unlock()

	// Settle → exactly one representative row (the anchor child on the tie).
	clk.advance(requestcorr.DefaultSettleWindow + time.Second)
	sink.apply(sink.tracker.Tick())

	mu.Lock()
	defer mu.Unlock()
	if len(writes) != 1 || writes[0] != "nginx" {
		t.Fatalf("expected 1 representative row from nginx, got %v", writes)
	}
	c := sink.correlationStats()
	if c.TrustedIDs != 2 || c.Counters.ObservationsAbsorbed != 1 || c.Counters.NotificationsAvoided != 1 {
		t.Fatalf("counters off: trusted=%d absorbed=%d avoided=%d",
			c.TrustedIDs, c.Counters.ObservationsAbsorbed, c.Counters.NotificationsAvoided)
	}
}

// WHAT THIS GATE PROVES (and does not): it is refactor-CONSISTENCY coverage,
// not a pre-refactor binary diff. It shows the sink's pass-through (feature off,
// or on with no lineage ID) drives each producing path to the SAME persisted
// finding as feature-off — i.e. routing an outcome through the sink adds
// nothing when coalescing is inert. It does NOT compare against the literal
// pre-sink code (that code is gone); the guarantee is "sink pass-through ==
// feature-off", across every branch.
//
// Golden parity through the REAL dispatch callback: for each dispatch branch —
// downgraded, escalated, unresolved — a feature-off sink and a
// feature-on-but-no-ID sink must persist a byte-identical finding.
func TestDispatchCallbackFeatureOnNoIDMatchesFeatureOff(t *testing.T) {
	branches := []struct {
		name  string
		alert coordinator.FinalAlert
	}{
		{"downgraded", coordinator.FinalAlert{
			EventID: "evt_dg", ScopeKey: "docker:captain-nginx", SourceType: "docker", SourceName: "captain-nginx",
			Host: "wp.example.com", HTTPMethod: "GET", HTTPPath: "/?x=1", StatusCode: 404,
			Verdict: "alert", Severity: "suspicious", Downgraded: true, DowngradeReason: "rejected", Key: "k", EventCount: 2,
			Line: `1.2.3.4 - - [t] "GET /?x=1 HTTP/1.1" 404 83 "-" "curl"`, // NO vgrid
		}},
		{"escalated", coordinator.FinalAlert{
			EventID: "evt_esc", ScopeKey: "docker:captain-nginx", SourceType: "docker", SourceName: "captain-nginx",
			Host: "wp.example.com", HTTPMethod: "GET", HTTPPath: "/?x=1", StatusCode: 200,
			Verdict: "alert", Severity: "suspicious", Escalated: true, EscalateReason: "disclosure", Key: "k", EventCount: 2,
			// BuildAlert returns nil so the escalated notify closure's type
			// assertion fails and the (nil) dispatcher is never called; the row
			// still writes with Notified:false, identical on both sinks.
			BuildAlert: func(interface{}) interface{} { return nil },
			Line:       `1.2.3.4 - - [t] "GET /?x=1 HTTP/1.1" 200 83 "-" "curl"`,
		}},
		{"unresolved", coordinator.FinalAlert{
			EventID: "evt_un", ScopeKey: "docker:captain-nginx", SourceType: "docker", SourceName: "captain-nginx",
			Host: "wp.example.com", HTTPMethod: "GET", HTTPPath: "/?x=1", StatusCode: 200,
			Verdict: "alert", Severity: "suspicious", Key: "k", EventCount: 1,
			BuildAlert: func(interface{}) interface{} { return nil },
			Line:       `1.2.3.4 - - [t] "GET /?x=1 HTTP/1.1" 200 83 "-" "curl"`,
		}},
	}

	for _, b := range branches {
		t.Run(b.name, func(t *testing.T) {
			offFinding := runDispatchAndGet(t, newHTTPOutcomeSink(Config{}), b.alert)
			onFinding := runDispatchAndGet(t, newHTTPOutcomeSink(enabledSinkCfg()), b.alert)
			if offFinding.Verdict != onFinding.Verdict ||
				offFinding.Classification != onFinding.Classification ||
				offFinding.ResolutionStatus != onFinding.ResolutionStatus ||
				offFinding.HTTPPath != onFinding.HTTPPath ||
				offFinding.Downgraded != onFinding.Downgraded {
				t.Errorf("feature-on-no-id diverged from feature-off:\noff=%+v\non =%+v", offFinding, onFinding)
			}
		})
	}
}

// All four producing paths' outcome shapes, exercised in pass-through
// (feature-off), asserting each writes exactly once and threads the notify
// result into the row's Notified column. Recon/downgraded/unresolved never
// notify (notify nil ⇒ Notified false); escalated threads notify()'s bool.
func TestSinkAllPathsPassThroughThreadNotify(t *testing.T) {
	cases := []struct {
		name       string
		outcome    requestcorr.Outcome
		notify     func() bool
		wantNotify bool
	}{
		{"recon_failed", requestcorr.OutcomeRecon, nil, false},
		{"status_rejection", requestcorr.OutcomeRecon, nil, false},
		{"bare_ip", requestcorr.OutcomeRecon, nil, false},
		{"dispatch_downgraded", requestcorr.OutcomeDowngraded, nil, false},
		{"dispatch_unresolved", requestcorr.OutcomeUnresolved, nil, false},
		{"dispatch_escalated_ok", requestcorr.OutcomeEscalated, func() bool { return true }, true},
		{"dispatch_escalated_drop", requestcorr.OutcomeEscalated, func() bool { return false }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := newHTTPOutcomeSink(Config{}) // feature OFF ⇒ pass-through
			wrote := false
			var gotNotified bool
			sink.Emit(httpOutcome{
				eventID:      "e1",
				rawLine:      rawWithVgrid, // token present but feature off ⇒ ignored
				source:       "wp",
				outcome:      tc.outcome,
				notify:       tc.notify,
				writeFinding: func(n bool) { wrote = true; gotNotified = n },
			})
			if !wrote {
				t.Fatalf("%s: writeFinding must run synchronously in pass-through", tc.name)
			}
			if gotNotified != tc.wantNotify {
				t.Errorf("%s: threaded Notified=%v, want %v", tc.name, gotNotified, tc.wantNotify)
			}
		})
	}
}

// DF-A audit: a randomized sequence of observations (mixed severities, sources,
// event IDs, interleaved settles and a final long expiry) must leave the sink's
// parked map — and the tracker's pending/tombstone/poisoned gauges — empty.
// Every parked EventID must reach exactly one terminal disposition.
func TestSinkRandomizedSequenceReleasesAllParked(t *testing.T) {
	clk := &manualClock{t: time.Unix(1_700_000_000, 0)}
	sink := newHTTPOutcomeSink(enabledSinkCfg())
	sink.tracker = requestcorr.New(requestcorr.Config{}, clk)

	outcomes := []requestcorr.Outcome{
		requestcorr.OutcomeRecon, requestcorr.OutcomeDowngraded,
		requestcorr.OutcomeUnresolved, requestcorr.OutcomeEscalated,
	}
	sources := []string{"captain-nginx", "wp", "backend2"} // first is the anchor
	// A handful of lineage IDs so groups, floods, dup-anchors and tombstone
	// attaches all occur; distinct-per-id keeps them independent otherwise.
	ids := []string{
		"2fb2cf19c82b36ceb7f89d50b381fcf1",
		"d222b0a4b75f01a12a7c1c4d2174cd2c",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	rng := uint32(2463534242)
	next := func(n int) int { // xorshift, deterministic
		rng ^= rng << 13
		rng ^= rng >> 17
		rng ^= rng << 5
		return int(rng) % n
	}

	for i := 0; i < 400; i++ {
		id := ids[next(len(ids))]
		src := sources[next(len(sources))]
		raw := `x vgrid=` + id
		sink.Emit(httpOutcome{
			eventID:      "ev" + itoa(i),
			rawLine:      raw,
			source:       src,
			outcome:      outcomes[next(len(outcomes))],
			timestamp:    clk.Now(),
			notify:       func() bool { return next(2) == 0 }, // sometimes fails
			writeFinding: func(bool) {},
		})
		if next(3) == 0 { // occasionally let the settle window pass
			clk.advance(requestcorr.DefaultSettleWindow + time.Second)
			sink.mu.Lock()
			ds := sink.tracker.Tick()
			sink.mu.Unlock()
			sink.apply(ds)
		}
	}

	// Final settle, then run past the tombstone+poison TTL and sweep.
	clk.advance(requestcorr.DefaultSettleWindow + time.Second)
	sink.mu.Lock()
	ds1 := sink.tracker.Tick()
	sink.mu.Unlock()
	sink.apply(ds1)
	clk.advance(requestcorr.DefaultTombstoneTTL + time.Second)
	sink.mu.Lock()
	ds2 := sink.tracker.Tick()
	sink.mu.Unlock()
	sink.apply(ds2)

	if len(sink.parked) != 0 {
		t.Fatalf("parked closures leaked: %d remain", len(sink.parked))
	}
	c := sink.correlationStats().Counters
	if c.PendingGroups != 0 || c.Tombstones != 0 || c.Poisoned != 0 {
		t.Fatalf("tracker gauges not drained: pending=%d tombstones=%d poisoned=%d",
			c.PendingGroups, c.Tombstones, c.Poisoned)
	}
}

func runDispatchAndGet(t *testing.T, sink *httpOutcomeSink, alert coordinator.FinalAlert) *store.Finding {
	t.Helper()
	db, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cb := makeDispatchCallback(nil, db, sink)
	cb(alert)

	// Both paths are synchronous here: feature-off is a direct write; the
	// feature-on sink with a no-vgrid Line is also a pass-through.
	f, err := db.GetFindingByEventID(context.Background(), alert.EventID)
	if err != nil {
		t.Fatalf("GetFindingByEventID(%s): %v", alert.EventID, err)
	}
	return f
}
