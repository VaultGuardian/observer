package patternstore

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const lrScope = "docker:lr-test"

// lrHash builds a syntactically valid 64-char hash value from a seed.
func lrHash(seed int) string {
	return fmt.Sprintf("%064d", seed)
}

func lrStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

// hashEntry fetches the stored pattern for a hash directly (same package).
func hashEntry(s *Store, scope string, v Verdict, hash string) *LearnedPattern {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, ok := s.scopes[scope]
	if !ok {
		return nil
	}
	bucket := s.getBucket(sc, v)
	if bucket == nil {
		return nil
	}
	return bucket.Hashes[hash]
}

// fillHashBucketToCap stuffs the bucket's hash map directly so the auto-learn
// cap check sees a full tier without paying for 100k Learn calls.
func fillHashBucketToCap(s *Store, scope string, v Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.getOrCreateScope(scope)
	bucket := s.getBucket(sc, v)
	for i := 0; len(bucket.Hashes) < MaxAutoHashesPerBucket; i++ {
		h := fmt.Sprintf("fill%060d", i)
		bucket.Hashes[h] = &LearnedPattern{Type: PatternHash, Value: h, Source: "auto"}
	}
}

func TestLearnHash_NewBelowCap_Inserted(t *testing.T) {
	s := lrStore(t)
	got := s.LearnHash(lrScope, VerdictAllow, lrHash(1), "first", "line one", "evt_1")
	if got != LearnInserted {
		t.Errorf("LearnHash new hash = %v, want LearnInserted", got)
	}
	if p := hashEntry(s, lrScope, VerdictAllow, lrHash(1)); p == nil || p.Reason != "first" {
		t.Errorf("hash entry after insert = %+v, want reason %q", p, "first")
	}
}

func TestLearnHash_ExistingBelowCap_DuplicateWithOverwrite(t *testing.T) {
	s := lrStore(t)
	s.LearnHash(lrScope, VerdictAllow, lrHash(2), "old reason", "line", "evt_old")
	before := hashEntry(s, lrScope, VerdictAllow, lrHash(2))
	beforeCreated := before.CreatedAt

	time.Sleep(2 * time.Millisecond)
	got := s.LearnHash(lrScope, VerdictAllow, lrHash(2), "new reason", "line", "evt_new")
	if got != LearnDuplicate {
		t.Errorf("LearnHash existing hash = %v, want LearnDuplicate", got)
	}

	// Overwrite semantics preserved: reason, lineage, and timestamp refresh.
	after := hashEntry(s, lrScope, VerdictAllow, lrHash(2))
	if after.Reason != "new reason" {
		t.Errorf("reason after duplicate learn = %q, want %q (overwrite must refresh)", after.Reason, "new reason")
	}
	if after.CreatedFromEventID != "evt_new" {
		t.Errorf("lineage after duplicate learn = %q, want %q", after.CreatedFromEventID, "evt_new")
	}
	if !after.CreatedAt.After(beforeCreated) {
		t.Errorf("timestamp not refreshed: before=%v after=%v", beforeCreated, after.CreatedAt)
	}
}

func TestLearnHash_AtCap_RejectedIncludingExistingHash(t *testing.T) {
	s := lrStore(t)
	// Seed one real entry, then fill the tier to the cap.
	s.LearnHash(lrScope, VerdictAllow, lrHash(3), "seeded", "line", "evt_seed")
	fillHashBucketToCap(s, lrScope, VerdictAllow)

	// New hash at cap: rejected.
	if got := s.LearnHash(lrScope, VerdictAllow, lrHash(4), "r", "line", "evt_a"); got != LearnRejected {
		t.Errorf("new hash at cap = %v, want LearnRejected", got)
	}
	if p := hashEntry(s, lrScope, VerdictAllow, lrHash(4)); p != nil {
		t.Errorf("rejected hash was inserted: %+v", p)
	}

	// EXISTING hash at cap: also rejected (bucketAtCap has no key-existence
	// check; preserved behavior), and the stored entry is untouched.
	if got := s.LearnHash(lrScope, VerdictAllow, lrHash(3), "clobber", "line", "evt_b"); got != LearnRejected {
		t.Errorf("existing hash at cap = %v, want LearnRejected", got)
	}
	if p := hashEntry(s, lrScope, VerdictAllow, lrHash(3)); p == nil || p.Reason != "seeded" {
		t.Errorf("entry changed by rejected learn: %+v, want reason %q", p, "seeded")
	}
}

func TestLearnWithResult_ValidationFailure_Rejected(t *testing.T) {
	s := lrStore(t)
	// Hash values must be 64 chars; this one is not.
	got, err := s.learnWithResult(lrScope, VerdictAllow, LearnedPattern{
		Type:   PatternHash,
		Value:  "short",
		Source: "auto",
	})
	if got != LearnRejected || err == nil {
		t.Errorf("invalid hash = (%v, %v), want (LearnRejected, error)", got, err)
	}
}

func TestLearnWithResult_SliceDedup_Duplicate(t *testing.T) {
	s := lrStore(t)
	line := "nginx worker process started with pid 1234"
	p := LearnedPattern{
		Type:         PatternPrefix,
		Value:        "nginx worker process started",
		Source:       "human",
		OriginalLine: line,
	}
	if got, err := s.learnWithResult(lrScope, VerdictSuppress, p); got != LearnInserted || err != nil {
		t.Fatalf("first prefix learn = (%v, %v), want (LearnInserted, nil)", got, err)
	}
	got, err := s.learnWithResult(lrScope, VerdictSuppress, p)
	if got != LearnDuplicate || err != nil {
		t.Errorf("repeat prefix learn = (%v, %v), want (LearnDuplicate, nil)", got, err)
	}

	// The slice must still hold exactly one entry (no-op preserved).
	s.mu.RLock()
	n := len(s.getBucket(s.scopes[lrScope], VerdictSuppress).Prefixes)
	s.mu.RUnlock()
	if n != 1 {
		t.Errorf("prefix slice has %d entries after dedup no-op, want 1", n)
	}
}

func TestLearnWithResult_UnknownVerdict_Rejected(t *testing.T) {
	s := lrStore(t)
	got, err := s.learnWithResult(lrScope, Verdict("bogus"), LearnedPattern{
		Type:   PatternHash,
		Value:  strings.Repeat("a", 64),
		Source: "auto",
	})
	if got != LearnRejected || err == nil {
		t.Errorf("unknown verdict = (%v, %v), want (LearnRejected, error)", got, err)
	}
}
