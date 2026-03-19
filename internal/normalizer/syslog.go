package normalizer

import (
	"regexp"
	"strings"
)

// SyslogNormalizer handles generic syslog-formatted lines.
//
// Standard syslog format:
//   Mar 17 15:10:04 hostname service[PID]: message
//
// This normalizer strips the syslog envelope (timestamp, hostname, service[PID])
// to expose the raw message, then applies generic variable stripping.
// For services with their own normalizer (sshd, nginx), the Registry
// will route to those instead — this handles everything else.
type SyslogNormalizer struct {
	generic GenericNormalizer
}

func (s *SyslogNormalizer) Family() string { return "syslog" }

var (
	// Full syslog prefix: "Mar 17 15:10:04 hostname service[12345]: "
	reSyslogFullPrefix = regexp.MustCompile(`^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\[\d+\]:\s*`)

	// Syslog prefix without PID: "Mar 17 15:10:04 hostname service: "
	reSyslogNoPidPrefix = regexp.MustCompile(`^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:\s*`)

	// Journald timestamp prefix: "Mar 17 15:10:04 "
	reJournaldPrefix = regexp.MustCompile(`^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+`)
)

func (s *SyslogNormalizer) Normalize(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Strip full syslog prefix (with PID)
	stripped := reSyslogFullPrefix.ReplaceAllString(line, "")
	if stripped != line {
		return s.generic.Normalize(stripped)
	}

	// Strip syslog prefix without PID
	stripped = reSyslogNoPidPrefix.ReplaceAllString(line, "")
	if stripped != line {
		return s.generic.Normalize(stripped)
	}

	// Strip just the journald timestamp
	stripped = reJournaldPrefix.ReplaceAllString(line, "")
	if stripped != line {
		return s.generic.Normalize(stripped)
	}

	// Didn't match any syslog pattern, fall through to generic
	return s.generic.Normalize(line)
}
