package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/llm"
	"github.com/vaultguardian/observer/internal/normalizer"
	"github.com/vaultguardian/observer/internal/patternstore"
)

// countingScheduler is a test LLMScheduler that records how many times a slot
// was requested. Capacity is generous so the leader always succeeds — the point
// of the test is that only the leader ever asks for a slot.
type countingScheduler struct {
	sem           chan struct{}
	tryAcquires   atomic.Int64
	blockAcquires atomic.Int64
}

func newCountingScheduler(capacity int) *countingScheduler {
	return &countingScheduler{sem: make(chan struct{}, capacity)}
}

func (s *countingScheduler) TryAcquire() (func(), bool) {
	s.tryAcquires.Add(1)
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, true
	default:
		return nil, false
	}
}

func (s *countingScheduler) AcquireBlocking(ctx context.Context) (func(), bool) {
	s.blockAcquires.Add(1)
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, true
	case <-ctx.Done():
		return nil, false
	}
}

// TestAnalyze_SingleflightCollapsesBurst fires a burst of identical events
// (same scope + normalized line, unique IDs) at Analyze before any verdict is
// learned. Without in-flight dedup each would miss the cache, take a slot, and
// call the LLM. With singleflight they coalesce into one LLM call and one learn,
// while each event still resolves as a distinct event.
func TestAnalyze_SingleflightCollapsesBurst(t *testing.T) {
	const burst = 20

	var llmCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls.Add(1)
		// Hold the call open so the whole burst piles into the same flight
		// before the leader's verdict is learned and cached.
		time.Sleep(200 * time.Millisecond)
		verdictJSON := `{"classification":"safe","confidence":0.95,"reason":"static asset request, normal traffic","action":"allow","pattern_type":"prefix","pattern":"captain.admin.kovicloud.com GET /favicon.ico"}`
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": verdictJSON}},
			},
			"usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	patterns, err := patternstore.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	llmClient := llm.NewClient(server.URL, "test-model", "", "low", "medium")
	scheduler := newCountingScheduler(8)
	a := New(normalizer.NewRegistry(), patterns, llmClient, scheduler)

	const line = "captain.admin.kovicloud.com GET /favicon.ico HTTP/1.1 200"

	results := make([]AnalysisResult, burst)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := 0; i < burst; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			evt := &event.Event{
				ID:          event.NewID(),
				SourceType:  "docker",
				SourceName:  "captain-nginx",
				Line:        line,
				Stream:      "stdout",
				Timestamp:   time.Now(),
				ProcessedAt: time.Now(),
			}
			start.Wait() // release all goroutines together for a real burst
			results[i] = a.Analyze(context.Background(), evt)
		}(i)
	}
	start.Done()
	done.Wait()

	// --- The fix: one LLM call and one slot for the whole burst. ---
	if got := llmCalls.Load(); got != 1 {
		t.Errorf("LLM endpoint called %d times, want 1 (stampede not collapsed)", got)
	}
	if got := scheduler.tryAcquires.Load(); got != 1 {
		t.Errorf("scheduler TryAcquire called %d times, want 1", got)
	}

	// Every event resolves to the same allow verdict via the LLM path...
	leaders := 0
	for i, r := range results {
		if r.Verdict != patternstore.VerdictAllow {
			t.Errorf("result[%d] verdict = %q, want %q", i, r.Verdict, patternstore.VerdictAllow)
		}
		if r.Source != "llm" {
			t.Errorf("result[%d] source = %q, want \"llm\"", i, r.Source)
		}
		if r.LLMVerdict != nil {
			leaders++
		}
	}
	// ...but exactly one (the leader) carries the full verdict, so exactly one
	// llm_decisions audit row is written for the coalesced burst.
	if leaders != 1 {
		t.Errorf("%d results carried LLMVerdict != nil, want exactly 1 (the leader)", leaders)
	}

	// The verdict was learned: an identical event now hits the pattern cache.
	h := results[0].Event.Hash
	nl := results[0].Event.NormalizedLine
	if m := patterns.Match("docker:captain-nginx", h, nl); m == nil || m.Verdict != patternstore.VerdictAllow {
		t.Errorf("pattern store did not learn allow verdict after burst: got %+v", m)
	}
}
