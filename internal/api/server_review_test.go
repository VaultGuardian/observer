package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/store"
)

// newReviewTestServer builds a Server with only the store wired up —
// handleDecisionReview touches nothing else.
func newReviewTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Init(t.TempDir())
	if err != nil {
		t.Fatalf("init store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return &Server{store: st}, st
}

func recordDecision(t *testing.T, st *store.Store, eventID string) int64 {
	t.Helper()
	ctx := context.Background()
	err := st.RecordLLMDecision(ctx, &store.LLMDecision{
		EventID:        eventID,
		Timestamp:      time.Now(),
		Tier:           "classify",
		Model:          "test-model",
		Classification: "malicious",
	})
	if err != nil {
		t.Fatalf("record decision: %v", err)
	}
	ds, err := st.ListLLMDecisions(ctx, store.LLMDecisionFilter{Limit: 500})
	if err != nil || len(ds) == 0 {
		t.Fatalf("list decisions: %v (got %d)", err, len(ds))
	}
	for _, d := range ds {
		if d.EventID == eventID {
			return d.ID
		}
	}
	t.Fatalf("decision for event %q not found", eventID)
	return 0
}

func recordPendingFinding(t *testing.T, st *store.Store, eventID string) {
	t.Helper()
	err := st.RecordFinding(context.Background(), &store.Finding{
		EventID:    eventID,
		Timestamp:  time.Now().Add(-time.Hour),
		SourceType: "nginx",
		SourceName: "docker:test",
		Verdict:    "malicious",
		HTTPMethod: "GET",
		HTTPPath:   "/api/.env",
		HTTPStatus: 200,
	})
	if err != nil {
		t.Fatalf("record finding %s: %v", eventID, err)
	}
}

func postReview(t *testing.T, srv *Server, id int64, status string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"id": %d, "review": {"status": %q, "reviewed_by": "test"}}`, id, status)
	req := httptest.NewRequest(http.MethodPost, "/api/decisions/review", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.handleDecisionReview(w, req)
	return w
}

// TestDecisionReviewResolvesLinkedFinding: an "ignored" review is a triage
// decision — it must resolve the linked pending finding via human_review
// without touching its verdict.
func TestDecisionReviewResolvesLinkedFinding(t *testing.T) {
	ctx := context.Background()
	srv, st := newReviewTestServer(t)
	const eventID = "evt_rv1"

	recordPendingFinding(t, st, eventID)
	id := recordDecision(t, st, eventID)

	if w := postReview(t, srv, id, "ignored"); w.Code != http.StatusOK {
		t.Fatalf("review returned %d: %s", w.Code, w.Body.String())
	}

	d, err := st.GetLLMDecision(ctx, id)
	if err != nil {
		t.Fatalf("get decision: %v", err)
	}
	if d.ReviewStatus != "ignored" {
		t.Fatalf("review_status = %q; want ignored", d.ReviewStatus)
	}

	f, err := st.GetFindingByEventID(ctx, eventID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.ResolutionStatus != "resolved" {
		t.Fatalf("resolution_status = %q; want resolved", f.ResolutionStatus)
	}
	if f.Verdict != "malicious" {
		t.Fatalf("verdict = %q; want malicious (review must not change verdicts)", f.Verdict)
	}
	// Terminal state: a later resolution attempt must be rejected by the guard.
	if err := st.UpdateFindingResolution(ctx, eventID, "evidence_unavailable", "timeout", ""); err == nil {
		t.Fatalf("expected resolved finding to reject further updates")
	}
}

// TestDecisionReviewNoopOnResolvedFinding: reviewing a decision whose finding
// is already resolved still succeeds — the resolution step is a silent no-op.
func TestDecisionReviewNoopOnResolvedFinding(t *testing.T) {
	ctx := context.Background()
	srv, st := newReviewTestServer(t)
	const eventID = "evt_rv2"

	recordPendingFinding(t, st, eventID)
	id := recordDecision(t, st, eventID)

	if err := st.UpdateFindingResolution(ctx, eventID, "resolved", "rec_evidence", "downgraded"); err != nil {
		t.Fatalf("pre-resolve: %v", err)
	}

	if w := postReview(t, srv, id, "confirmed"); w.Code != http.StatusOK {
		t.Fatalf("review returned %d: %s", w.Code, w.Body.String())
	}

	d, err := st.GetLLMDecision(ctx, id)
	if err != nil {
		t.Fatalf("get decision: %v", err)
	}
	if d.ReviewStatus != "confirmed" {
		t.Fatalf("review_status = %q; want confirmed", d.ReviewStatus)
	}

	f, err := st.GetFindingByEventID(ctx, eventID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.ResolutionStatus != "resolved" || f.Verdict != "downgraded" {
		t.Fatalf("finding changed by no-op review: status=%q verdict=%q", f.ResolutionStatus, f.Verdict)
	}
}

// TestDecisionReviewWithoutLinkedFinding: a decision whose event never
// produced a finding reviews cleanly — resolve-if-exists, no error.
func TestDecisionReviewWithoutLinkedFinding(t *testing.T) {
	srv, st := newReviewTestServer(t)
	id := recordDecision(t, st, "")

	if w := postReview(t, srv, id, "ignored"); w.Code != http.StatusOK {
		t.Fatalf("review returned %d: %s", w.Code, w.Body.String())
	}
}
