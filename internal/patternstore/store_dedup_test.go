package patternstore

import "testing"

func suppressPrefix(val string) LearnedPattern {
	return LearnedPattern{
		Type:         PatternPrefix,
		Value:        val,
		Source:       "llm",
		Reason:       "routine noise",
		OriginalLine: val,
	}
}

// Learning the same prefix repeatedly — as happens when a line is reclassified
// before its pattern propagates under retry-queue backlog — must not
// accumulate duplicate slice-tier entries. This is the regression that
// produced the 24× fwupd / 21× "Reached target" duplicates in
// patternstore.json.
func TestLearnDedupsSlicePrefix(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	const val = "Starting fwupd.service - Firmware update daemon..."
	for i := 0; i < 6; i++ {
		if err := s.Learn("journal:systemd", VerdictSuppress, suppressPrefix(val)); err != nil {
			t.Fatalf("Learn #%d: %v", i, err)
		}
	}
	if got := len(s.ListPatterns("journal:systemd", VerdictSuppress)); got != 1 {
		t.Fatalf("after 6 identical learns: got %d prefix patterns, want 1", got)
	}
}

// Distinct values in the same tier are still appended — dedup keys on value,
// not on tier membership.
func TestLearnKeepsDistinctPrefixes(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	_ = s.Learn("journal:systemd", VerdictSuppress, suppressPrefix("Reached target basic.target - Basic System."))
	_ = s.Learn("journal:systemd", VerdictSuppress, suppressPrefix("Reached target paths.target - System Paths Unit."))
	if got := len(s.ListPatterns("journal:systemd", VerdictSuppress)); got != 2 {
		t.Fatalf("got %d patterns, want 2 distinct", got)
	}
}

// A revoked entry must NOT block a re-learn of the same value: revoke means
// "re-evaluate via the LLM," and if the LLM re-learns the pattern it should be
// re-added (matchTiers skips the revoked copy). This preserves existing revoke
// semantics rather than silently making the dedup resurrect or permanently
// suppress re-learning.
func TestLearnRevokedDoesNotBlockRelearn(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	const val = "Disconnecting authenticating user root <IP> port <PORT>: bye"
	if err := s.Learn("journal:sshd", VerdictSuppress, suppressPrefix(val)); err != nil {
		t.Fatalf("initial Learn: %v", err)
	}
	if !s.RevokePattern("journal:sshd", VerdictSuppress, val, "test") {
		t.Fatalf("RevokePattern returned false")
	}
	// Re-learn after revoke: should be appended (no active copy exists).
	if err := s.Learn("journal:sshd", VerdictSuppress, suppressPrefix(val)); err != nil {
		t.Fatalf("re-Learn after revoke: %v", err)
	}
	// A second identical re-learn should now be deduped against the active copy.
	if err := s.Learn("journal:sshd", VerdictSuppress, suppressPrefix(val)); err != nil {
		t.Fatalf("second re-Learn: %v", err)
	}
	// Exactly one active prefix should match this value.
	active := 0
	for _, p := range s.ListPatterns("journal:sshd", VerdictSuppress) {
		if p.Value == val && p.RevokedAt == nil {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("expected exactly 1 active copy after revoke+relearn, got %d", active)
	}
}
