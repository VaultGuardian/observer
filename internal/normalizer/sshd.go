package normalizer

import (
	"regexp"
	"strings"
)

// SshdNormalizer handles sshd/auth log lines.
//
// Typical sshd log formats:
//
//	Mar 17 15:10:04 hostname sshd[12345]: Accepted publickey for drew from 192.168.1.50 port 54321 ssh2
//	Mar 17 15:10:04 hostname sshd[12345]: Failed password for invalid user admin from 10.0.0.1 port 43210 ssh2
//	Mar 17 15:10:04 hostname sshd[12345]: Connection closed by 10.0.0.1 port 43210 [preauth]
//	Mar 17 15:10:04 hostname sshd[12345]: pam_unix(sshd:session): session opened for user drew(uid=1000)
//
// We strip: syslog timestamp, hostname, PID, source IP, port number, UID.
// We PRESERVE: action (Accepted/Failed/Connection closed), auth method,
// username (important for security context), and structural markers.
type SshdNormalizer struct{}

func (s *SshdNormalizer) Family() string { return "sshd" }

var (
	// Syslog prefix: "Mar 17 15:10:04 hostname sshd[12345]: "
	reSshdSyslogPrefix = regexp.MustCompile(`^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+sshd\[\d+\]:\s*`)

	// Journald-style prefix: might just have "sshd[12345]: "
	reSshdJournalPrefix = regexp.MustCompile(`^sshd\[\d+\]:\s*`)

	// PID in brackets anywhere: [12345]
	reSshdPid = regexp.MustCompile(`\[\d+\]`)

	// "from <IP> port <PORT>"
	reSshdFromIP = regexp.MustCompile(`from\s+\S+\s+port\s+\d+`)

	// "by <IP> port <PORT>" (Connection closed by ...)
	reSshdByIP = regexp.MustCompile(`by\s+\S+\s+port\s+\d+`)

	// UID in parentheses: (uid=1000)
	reSshdUID = regexp.MustCompile(`\(uid=\d+\)`)

	// Session ID: session 12345
	reSshdSession = regexp.MustCompile(`session\s+\d+`)

	// SHA256 fingerprint: SHA256:xyzabc123...
	reSshdFingerprint = regexp.MustCompile(`SHA256:\S+`)

	// "Invalid user <name>" — the username is always attacker-fabricated
	// (the account does not exist on this host). Normalizing it to <USER>
	// means all "Invalid user" brute-force attempts hash to the same
	// normalized line regardless of which made-up username the scanner
	// tried. Without this, every unique username ("uftp", "liugt",
	// "uploader", ...) produces a cache miss and a separate LLM call.
	//
	// We do NOT normalize usernames in "Failed password for <name>" (no
	// "invalid user" qualifier) because that targets a real local account
	// and the username has security context worth preserving.
	reSshdInvalidUser = regexp.MustCompile(`(?i)(invalid user )\S+`)
)

func (s *SshdNormalizer) Normalize(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Strip syslog prefix (timestamp + hostname + sshd[PID]:)
	line = reSshdSyslogPrefix.ReplaceAllString(line, "")

	// Strip journald-style prefix
	line = reSshdJournalPrefix.ReplaceAllString(line, "")

	// Normalize "from IP port PORT" → "from <IP> port <PORT>"
	line = reSshdFromIP.ReplaceAllString(line, "from <IP> port <PORT>")

	// Normalize "by IP port PORT" → "by <IP> port <PORT>"
	line = reSshdByIP.ReplaceAllString(line, "by <IP> port <PORT>")

	// Strip UIDs
	line = reSshdUID.ReplaceAllString(line, "(uid=<UID>)")

	// Strip session IDs
	line = reSshdSession.ReplaceAllString(line, "session <SID>")

	// Normalize "Invalid user <name>" → "Invalid user <USER>"
	// See reSshdInvalidUser for the rationale.
	line = reSshdInvalidUser.ReplaceAllString(line, "${1}<USER>")

	// Strip fingerprints
	line = reSshdFingerprint.ReplaceAllString(line, "SHA256:<FP>")

	// Strip any remaining PIDs in brackets
	line = reSshdPid.ReplaceAllString(line, "[<PID>]")

	// Collapse whitespace
	line = strings.Join(strings.Fields(line), " ")

	return line
}
