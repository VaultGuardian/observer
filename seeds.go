package main

import "github.com/vaultguardian/observer/internal/patternstore"

// denySeeds defines curated attack indicators seeded into the global deny list.
// These are manually chosen, not learned — they apply to all sources.
// The pattern store uses substring matching for seeded patterns.
//
// DESIGN DECISION (v0.15, 2026-03-24):
//   Seeds trimmed from 25 to 6 patterns. Only "always malicious regardless of
//   context" patterns remain. Reconnaissance-shaped patterns (.env, /etc/passwd,
//   UNION SELECT, DROP TABLE) moved to the intelligent pipeline where the LLM
//   evaluates intent × outcome. the team, code review, ,  all agreed.
//
//   Rationale: Seeds bypass LLM classification, evidence check, and coordinator
//   downgrade. With 97%+ cache hit rates, seeds save one LLM call worth fractions
//   of a penny but prevent the system from correctly suppressing failed probes.
var denySeeds = []struct {
	Pattern string
	Reason  string
}{
	// Reverse shells — presence in a log means active exploitation
	{"bash -i >& /dev/tcp", "Bash reverse shell"},
	{"nc -e /bin/sh", "Netcat reverse shell"},

	// Encoded/remote execution — download-and-execute chains
	{"base64 -d | bash", "Encoded command execution"},
	{"curl | sh", "Remote code execution via curl pipe"},
	{"wget | sh", "Remote code execution via wget pipe"},

	// Destructive filesystem commands
	{"rm -rf /", "Destructive filesystem command"},
}

// seedDenyPatterns loads curated attack indicators into the pattern store.
func seedDenyPatterns(store *patternstore.Store) {
	for _, s := range denySeeds {
		store.SeedDenyPattern(s.Pattern, s.Reason)
	}
}
