package store

import (
	"context"
	"testing"
	"time"
)

// TestGetLLMDecisionCountsIncludesIgnored: every review status is counted
// individually, and the four statuses partition the total.
func TestGetLLMDecisionCountsIncludesIgnored(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	for _, evt := range []string{"evt_c1", "evt_c2", "evt_c3", "evt_c4"} {
		err := s.RecordLLMDecision(ctx, &LLMDecision{
			EventID:        evt,
			Timestamp:      time.Now(),
			Tier:           "classify",
			Model:          "test-model",
			Classification: "malicious",
		})
		if err != nil {
			t.Fatalf("record decision %s: %v", evt, err)
		}
	}

	// One decision each → confirmed, corrected, ignored; the fourth stays pending.
	for evt, status := range map[string]string{
		"evt_c1": "confirmed",
		"evt_c2": "corrected",
		"evt_c3": "ignored",
	} {
		ds, err := s.ListLLMDecisions(ctx, LLMDecisionFilter{EventID: evt, Limit: 1})
		if err != nil || len(ds) != 1 {
			t.Fatalf("list decision %s: %v (got %d)", evt, err, len(ds))
		}
		if err := s.UpdateLLMDecisionReview(ctx, ds[0].ID, LLMReview{Status: status, ReviewedBy: "test"}); err != nil {
			t.Fatalf("review %s as %s: %v", evt, status, err)
		}
	}

	c, err := s.GetLLMDecisionCounts(ctx)
	if err != nil {
		t.Fatalf("get counts: %v", err)
	}
	if c.Pending != 1 || c.Confirmed != 1 || c.Corrected != 1 || c.Ignored != 1 {
		t.Fatalf("counts = pending:%d confirmed:%d corrected:%d ignored:%d; want 1 each",
			c.Pending, c.Confirmed, c.Corrected, c.Ignored)
	}
	if sum := c.Pending + c.Confirmed + c.Corrected + c.Ignored; sum != c.Total {
		t.Fatalf("status counts sum to %d; total is %d", sum, c.Total)
	}
	if c.Total != 4 {
		t.Fatalf("total = %d; want 4", c.Total)
	}
}
