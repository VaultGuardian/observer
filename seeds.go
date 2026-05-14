// seeds.go
package main

import "github.com/vaultguardian/observer/internal/patternstore"

// maliciousSeeds defines curated attack indicators seeded into the global malicious list.
// These are manually chosen, not learned — they apply to all sources.
// The pattern store uses substring matching for seeded patterns.
//
// DESIGN DECISION (v0.15, 2026-03-24):
//
//	Seeds trimmed from 25 to 6 patterns. Only "always malicious regardless of
//	context" patterns remain. Reconnaissance-shaped patterns (.env, /etc/passwd,
//	UNION SELECT, DROP TABLE) moved to the intelligent pipeline where the LLM
//	evaluates intent × outcome. the team, code review, ,  all agreed.
//
//	Rationale: Seeds bypass LLM classification, evidence check, and coordinator
//	downgrade. With 97%+ cache hit rates, seeds save one LLM call worth fractions
//	of a penny but prevent the system from correctly suppressing failed probes.
//
// DESIGN DECISION (v0.37, 2026-04-21):
//
//	Added data exfiltration CONTENT seeds. The original v0.15 decision removed
//	REQUEST PATH seeds (/etc/passwd, .env) because scanners spam those paths and
//	the probe usually fails. That was correct — the PATH is recon. But the FILE
//	CONTENTS appearing in any log stream is ALWAYS confirmed exploitation.
//	"root:x:0:0:root" in a web app container's output means the attacker already
//	won. No LLM needed. the team, the design review agreed.
var maliciousSeeds = []struct {
	Pattern string
	Reason  string
}{
	// ── Reverse shells — presence in a log means active exploitation ──
	{"bash -i >& /dev/tcp", "Bash reverse shell"},
	{"nc -e /bin/sh", "Netcat reverse shell"},

	// ── Encoded/remote execution — download-and-execute chains ──
	{"base64 -d | bash", "Encoded command execution"},
	{"curl | sh", "Remote code execution via curl pipe"},
	{"wget | sh", "Remote code execution via wget pipe"},

	// ── Destructive filesystem commands ──
	{"rm -rf /", "Destructive filesystem command"},

	// ── Data exfiltration CONTENT — file contents, not paths ──
	// If these strings appear in ANY log (Docker, nginx, journald), the
	// attacker has already achieved code execution and is dumping data.
	// The path "/etc/passwd" in a URL is recon (might 404).
	// The string "root:x:0:0:root" in output is confirmed exfiltration.
	{"root:x:0:0:root", "System credential file contents (/etc/passwd) in output"},
	{"BEGIN RSA PRIVATE KEY", "RSA private key in output"},
	{"BEGIN OPENSSH PRIVATE KEY", "SSH private key in output"},
	{"BEGIN EC PRIVATE KEY", "EC private key in output"},
	{"BEGIN PRIVATE KEY", "Private key in output"},
}

// seedMaliciousPatterns loads curated attack indicators into the pattern store.
func seedMaliciousPatterns(store *patternstore.Store) {
	for _, s := range maliciousSeeds {
		store.SeedMaliciousPattern(s.Pattern, s.Reason)
	}
}
