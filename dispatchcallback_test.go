// dispatchcallback_test.go - regression coverage for the coordinator
// human-correction scope double-prefix bug. The dispatch callback must persist
// the BARE source name in store.Finding.SourceName so the correction API's
// reconstruction (SourceType + ":" + SourceName) yields the canonical scope
// ("docker:captain-nginx") rather than a phantom "docker:docker:captain-nginx"
// the analyzer never matches.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/coordinator"
	"github.com/vaultguardian/observer/internal/rec"
	"github.com/vaultguardian/observer/internal/store"
)

func TestDispatchCallbackPersistsBareSourceName(t *testing.T) {
	tests := []struct {
		name    string
		alert   coordinator.FinalAlert
		wantSrc string
	}{
		{
			// Normal path: SourceName carried through from PendingAlert.
			name: "carried_source_name",
			alert: coordinator.FinalAlert{
				EventID:         "evt_carried",
				ScopeKey:        "docker:captain-nginx",
				SourceType:      "docker",
				SourceName:      "captain-nginx",
				Verdict:         "alert",
				Severity:        "alert",
				Downgraded:      true,
				DowngradeReason: "recon",
				Timestamp:       time.Now(),
			},
			wantSrc: "captain-nginx",
		},
		{
			// Fallback path (e.g. catch-all inline construction left SourceName
			// empty): strip the SourceType prefix off ScopeKey.
			name: "fallback_strips_prefix",
			alert: coordinator.FinalAlert{
				EventID:         "evt_fallback",
				ScopeKey:        "docker:captain-nginx",
				SourceType:      "docker",
				SourceName:      "",
				Verdict:         "alert",
				Severity:        "alert",
				Downgraded:      true,
				DowngradeReason: "recon",
				Timestamp:       time.Now(),
			},
			wantSrc: "captain-nginx",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db, err := store.Init(t.TempDir())
			if err != nil {
				t.Fatalf("store.Init: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })

			// dispatch is nil-safe here: the Downgraded branch persists the
			// finding without ever touching the dispatcher.
			cb := makeDispatchCallback(nil, db)
			cb(tc.alert)

			f, err := db.GetFindingByEventID(context.Background(), tc.alert.EventID)
			if err != nil {
				t.Fatalf("GetFindingByEventID: %v", err)
			}

			if f.SourceName != tc.wantSrc {
				t.Fatalf("persisted SourceName = %q, want bare %q", f.SourceName, tc.wantSrc)
			}
			if f.SourceName == tc.alert.ScopeKey {
				t.Fatalf("persisted SourceName must be bare, not the full ScopeKey %q", tc.alert.ScopeKey)
			}
			// The correction API reconstructs scope this way; it must equal the
			// canonical scope, not double-prefix it.
			if got := f.SourceType + ":" + f.SourceName; got != "docker:captain-nginx" {
				t.Fatalf("reconstructed scope = %q, want %q (NOT docker:docker:captain-nginx)", got, "docker:captain-nginx")
			}
		})
	}
}

// TestDispatchCallbackEvidenceBearingPendingStaysOutOfTimeout is the cross-layer
// guard for the reconciler-mislabel fix: the third dispatch branch persists an
// evidence-bearing suspicious/alert finding as pending, and the reconciler's
// timeout query must never select it (which would wrongly stamp it
// evidence_unavailable and drop it from the review queue). A control finding
// with no evidence stays eligible.
func TestDispatchCallbackEvidenceBearingPendingStaysOutOfTimeout(t *testing.T) {
	ctx := context.Background()
	db, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cb := makeDispatchCallback(nil, db)

	// Evidence-bearing pending: reaches the third branch (BuildAlert non-nil,
	// not escalated, not downgraded) with high-confidence evidence attached.
	cb(coordinator.FinalAlert{
		EventID:    "evt_evidence_pending",
		ScopeKey:   "docker:captain-nginx",
		SourceType: "docker",
		SourceName: "captain-nginx",
		Verdict:    "alert",
		Severity:   "alert",
		HTTPMethod: "GET",
		HTTPPath:   "/api/.env",
		StatusCode: 200,
		Timestamp:  time.Now().Add(-time.Hour),
		Evidence:   &rec.Evidence{Status: rec.EvidenceAvailableHighConfidence},
		BuildAlert: func(evidence interface{}) interface{} { return nil },
	})

	// Control: evidence-less pending stays eligible for the timeout path.
	cb(coordinator.FinalAlert{
		EventID:    "evt_no_evidence_pending",
		ScopeKey:   "docker:captain-nginx",
		SourceType: "docker",
		SourceName: "captain-nginx",
		Verdict:    "alert",
		Severity:   "alert",
		HTTPMethod: "GET",
		HTTPPath:   "/api/.env",
		StatusCode: 200,
		Timestamp:  time.Now().Add(-time.Hour),
		BuildAlert: func(evidence interface{}) interface{} { return nil },
	})

	got, err := db.QueryUnresolvedMalicious(ctx, time.Minute, 50)
	if err != nil {
		t.Fatalf("QueryUnresolvedMalicious: %v", err)
	}

	for _, f := range got {
		if f.EventID == "evt_evidence_pending" {
			t.Fatalf("evidence-bearing pending finding must not be selected by the timeout query")
		}
	}
	var sawControl bool
	for _, f := range got {
		if f.EventID == "evt_no_evidence_pending" {
			sawControl = true
		}
	}
	if !sawControl {
		t.Fatalf("evidence-less pending finding should remain eligible for the timeout query")
	}
}
