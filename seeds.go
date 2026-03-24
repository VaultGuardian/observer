package main

import "github.com/vaultguardian/logwatch/internal/patternstore"

// denySeeds defines curated attack indicators seeded into the global deny list.
// These are manually chosen, not learned — they apply to all sources.
// The pattern store uses substring matching for seeded patterns.
var denySeeds = []struct {
	Pattern string
	Reason  string
}{
	// Destructive commands
	{"rm -rf /", "Destructive filesystem command"},
	{"chmod 777", "Overly permissive file permissions"},
	{"iptables -F", "Firewall flush"},

	// Sensitive file access
	{"/etc/shadow", "Shadow password file access"},
	{"/etc/passwd", "Password file access"},
	{".bash_history", "History file access"},
	{"authorized_keys", "SSH key manipulation"},

	// Reverse shells
	{"reverse shell", "Reverse shell keyword"},
	{"nc -e /bin/sh", "Netcat reverse shell"},
	{"bash -i >& /dev/tcp", "Bash reverse shell"},
	{"python -c 'import socket", "Python reverse shell"},
	{"perl -e 'use Socket", "Perl reverse shell"},

	// Remote code execution
	{"curl | sh", "Remote code execution via curl pipe"},
	{"wget | sh", "Remote code execution via wget pipe"},
	{"base64 -d | bash", "Encoded command execution"},

	// SQL injection
	{"UNION SELECT", "SQL injection"},
	{"DROP TABLE", "SQL injection / destructive query"},

	// Command injection
	{"; ls -la", "Command injection"},
	{"&& cat /etc", "Command injection"},

	// Reconnaissance
	{"phpinfo()", "PHP information disclosure"},
	{"../../etc/passwd", "Path traversal attack"},
	{"curl ifconfig.me", "External IP reconnaissance"},
	{"wget -q -O-", "Stealthy remote download"},

	// Persistence
	{"crontab -e", "Cron job modification"},
}

// seedDenyPatterns loads curated attack indicators into the pattern store.
func seedDenyPatterns(store *patternstore.Store) {
	for _, s := range denySeeds {
		store.SeedDenyPattern(s.Pattern, s.Reason)
	}
}
