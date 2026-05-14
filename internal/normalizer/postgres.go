package normalizer

import (
	"regexp"
	"strings"
)

// PostgresNormalizer handles PostgreSQL log lines.
//
// Typical formats:
//
//	2026-03-17 15:10:04.123 UTC [12345] LOG:  database system is ready to accept connections
//	2026-03-17 15:10:04.123 UTC [12345] user@db LOG:  duration: 1.234 ms  statement: SELECT * FROM users WHERE id = 42
//	2026-03-17 15:10:04.123 UTC [12345] ERROR:  relation "nonexistent" does not exist
//	LOG:  checkpoint starting: time
//
// We strip: timestamp, PID, session context (user@db), durations, numeric literals
// in SQL, and specific parameter values.
// We PRESERVE: log level, message structure, SQL shape.
type PostgresNormalizer struct{}

func (p *PostgresNormalizer) Family() string { return "postgres" }

var (
	// Postgres timestamp prefix: "2026-03-17 15:10:04.123 UTC "
	rePgTimestamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*\s+\w+\s+`)

	// PID in brackets: [12345]
	rePgPid = regexp.MustCompile(`\[\d+\]\s*`)

	// Session context: user@db or user@
	rePgSession = regexp.MustCompile(`\S+@\S*\s+`)

	// Duration in log: "duration: 1.234 ms"
	rePgDuration = regexp.MustCompile(`duration:\s+[\d\.]+\s+ms`)

	// SQL numeric literals: WHERE id = 42, LIMIT 100, OFFSET 50
	rePgSQLNum = regexp.MustCompile(`(?i)(=|<|>|LIMIT|OFFSET|IN\s*\()\s*\d+`)

	// SQL string literals: WHERE name = 'drew'
	rePgSQLStr = regexp.MustCompile(`'[^']*'`)

	// Transaction IDs and log sequence numbers
	rePgTxnID = regexp.MustCompile(`\b(?:txn|xid|lsn)\s*:?\s*[\d/]+`)

	// Checkpoint progress numbers
	rePgCheckpointNums = regexp.MustCompile(`\b\d+\s+(?:buffers|bytes|files|segments|records)`)
)

func (p *PostgresNormalizer) Normalize(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Strip timestamp prefix
	line = rePgTimestamp.ReplaceAllString(line, "")

	// Strip PID
	line = rePgPid.ReplaceAllString(line, "")

	// Strip session context (user@db) — comes before log level
	// Only strip if followed by a log level keyword
	if idx := strings.Index(line, " LOG:"); idx > 0 && idx < 50 {
		possibleSession := line[:idx]
		if strings.Contains(possibleSession, "@") {
			line = line[idx+1:]
		}
	}
	if idx := strings.Index(line, " ERROR:"); idx > 0 && idx < 50 {
		possibleSession := line[:idx]
		if strings.Contains(possibleSession, "@") {
			line = line[idx+1:]
		}
	}
	if idx := strings.Index(line, " WARNING:"); idx > 0 && idx < 50 {
		possibleSession := line[:idx]
		if strings.Contains(possibleSession, "@") {
			line = line[idx+1:]
		}
	}

	// Normalize durations
	line = rePgDuration.ReplaceAllString(line, "duration: <DUR> ms")

	// Normalize SQL numeric literals
	line = rePgSQLNum.ReplaceAllStringFunc(line, func(match string) string {
		// Preserve the operator/keyword, replace the number
		for _, prefix := range []string{"=", "<", ">", "LIMIT", "limit", "OFFSET", "offset"} {
			if strings.HasPrefix(strings.TrimSpace(match), prefix) {
				return prefix + " <N>"
			}
		}
		return "<N>"
	})

	// Normalize SQL string literals
	line = rePgSQLStr.ReplaceAllString(line, "'<STR>'")

	// Normalize checkpoint numbers
	line = rePgCheckpointNums.ReplaceAllStringFunc(line, func(match string) string {
		parts := strings.Fields(match)
		if len(parts) == 2 {
			return "<N> " + parts[1]
		}
		return match
	})

	// Collapse whitespace
	line = strings.Join(strings.Fields(line), " ")

	return line
}
