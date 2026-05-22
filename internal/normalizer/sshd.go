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
//	Mar 17 15:10:04 hostname sshd[12345]: Disconnecting invalid user admin 10.0.0.1 port 43210: Too many authentication failures [preauth]
//	Mar 17 15:10:04 hostname sshd[12345]: PAM 3 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.1
//
// We strip: syslog timestamp, hostname, PID, source IP, port number, UID,
// rhost IP, and PAM failure counts.
// We PRESERVE: action (Accepted/Failed/Connection closed), auth method,
// real usernames (security context), and structural markers.
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
	// and the username has security context worth preserving. With the IP
	// and port now collapsed (below), a real-account brute-force from many
	// source IPs still collapses to one pattern per targeted username
	// instead of one per (username, IP, port) tuple.
	reSshdInvalidUser = regexp.MustCompile(`(?i)(invalid user )\S+`)

	// "PAM N more authentication failure(s)" — pam_unix emits a running
	// retry count, and the suffix is singular at 1 ("failure") and plural
	// otherwise ("failures"). Both the count and the suffix vary per
	// attacker, so without collapsing them every retry tier produces a
	// distinct normalized line. (v0.56: SSH brute-force cache-miss fix.)
	reSshdPAMCount = regexp.MustCompile(`(?i)PAM \d+ more authentication failures?`)

	// "rhost=<IP>" — PAM auth-failure lines carry the source IP as an
	// rhost= field with no "from"/"by" keyword and no "port", so neither
	// reSshdFromIP nor reSshdByIP catches it. Every attacker IP otherwise
	// produces a unique line. (v0.56: SSH brute-force cache-miss fix.)
	reSshdRhost = regexp.MustCompile(`rhost=\S+`)

	// Bare IPv4 / IPv6 not captured by the from/by rules. Lines such as
	// "Disconnecting invalid user X <IP> port <PORT>: Too many
	// authentication failures" place the IP directly after the username
	// with no "from" keyword. Applied AFTER the from/by rules so the
	// literal "<IP>" tokens those rules emit are left untouched (they
	// contain no dotted-quad / colon-group to match).
	// (v0.56: SSH brute-force cache-miss fix.)
	reSshdBareIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reSshdBareIPv6 = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}\b`)

	// Bare "port <N>" left over after a bare IP is stripped (same set of
	// "no from/by" lines). The from/by rules already emit the literal
	// "port <PORT>", which has no digits and is left untouched.
	// (v0.56: SSH brute-force cache-miss fix.)
	reSshdBarePort = regexp.MustCompile(`\bport \d+\b`)
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

	// Collapse PAM retry count + singular/plural suffix while the line
	// structure is still intact.
	line = reSshdPAMCount.ReplaceAllString(line, "PAM <N> more authentication failures")

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

	// Strip rhost= source IPs (PAM auth-failure lines).
	line = reSshdRhost.ReplaceAllString(line, "rhost=<IP>")

	// Strip any remaining bare IPs (lines without a from/by keyword), then
	// the bare port that trails them.
	line = reSshdBareIPv4.ReplaceAllString(line, "<IP>")
	line = reSshdBareIPv6.ReplaceAllString(line, "<IP>")
	line = reSshdBarePort.ReplaceAllString(line, "port <PORT>")

	// Strip any remaining PIDs in brackets
	line = reSshdPid.ReplaceAllString(line, "[<PID>]")

	// Collapse whitespace
	line = strings.Join(strings.Fields(line), " ")

	return line
}
