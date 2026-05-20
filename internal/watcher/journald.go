package watcher

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// journalEntry is the JSON structure from `journalctl --output=json`.
// Field names use journald's native double-underscore convention.
type journalEntry struct {
	// Core fields
	Message           string `json:"MESSAGE"`
	SyslogIdentifier  string `json:"SYSLOG_IDENTIFIER"`
	SystemdUnit       string `json:"_SYSTEMD_UNIT"`
	Priority          string `json:"PRIORITY"`
	PID               string `json:"_PID"`
	UID               string `json:"_UID"`
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"` // microseconds since epoch

	// Transport — how the message reached journald
	Transport string `json:"_TRANSPORT"` // "syslog", "journal", "stdout", "kernel"

	// Process info
	Comm     string `json:"_COMM"`
	Exe      string `json:"_EXE"`
	CmdLine  string `json:"_CMDLINE"`
	Hostname string `json:"_HOSTNAME"`
}

// defaultNoiseUnits are systemd units that produce high-volume, low-security-value
// log entries. Filtering these before the pipeline saves LLM calls and pattern store space.
// Users can override via JOURNALD_EXCLUDE_UNITS env var.
//
// Entries are matched case-insensitively against both _SYSTEMD_UNIT (trusted,
// kernel-attached) and SYSLOG_IDENTIFIER (for entries without a unit, like kernel).
//
// SECURITY: Self-suppression (observer) uses _SYSTEMD_UNIT exclusively.
// An attacker can spoof SYSLOG_IDENTIFIER but cannot spoof _SYSTEMD_UNIT,
// which the kernel attaches.
var defaultNoiseUnits = map[string]bool{
	"systemd-resolved":    true, // DNS resolver — constant chatter
	"systemd-timesyncd":   true, // NTP sync — periodic, harmless
	"systemd-networkd":    true, // Network config — startup noise
	"systemd-logind":      true, // Session tracking — noisy on multi-user
	"systemd-journald":    true, // Journal rotation messages
	"systemd-udevd":       true, // Device events
	"snapd":               true, // Snap daemon (if present)
	"cron":                true, // Cron job execution — predictable
	"anacron":             true, // Delayed cron
	"dbus-daemon":         true, // D-Bus system messages
	"polkitd":             true, // PolicyKit auth agent
	"udisksd":             true, // Disk management
	"networkd-dispatcher": true, // Network event scripts
	"multipathd":          true, // Multipath I/O
	"irqbalance":          true, // IRQ balancing
	"fwupd":               true, // Firmware update daemon
	"thermald":            true, // Thermal management
	"dockerd":             true, // Docker daemon chatter
	"containerd":          true, // Container runtime chatter
}

// JournaldWatcher streams entries from systemd journal via journalctl subprocess.
// Zero CGO, zero dependencies — works on any Linux box with journalctl.
type JournaldWatcher struct {
	handler      LogHandler
	excludeUnits map[string]bool // all keys stored lowercase
	selfUnit     string          // our own systemd unit name for self-suppression
}

// NewJournaldWatcher creates a watcher that streams journal entries.
// excludeUnits merges with defaultNoiseUnits. Pass nil for defaults only.
// selfUnit is the systemd unit name for Observer (e.g. "observer.service").
// If empty, defaults to "observer.service".
func NewJournaldWatcher(handler LogHandler, excludeUnits map[string]bool, selfUnit string) *JournaldWatcher {
	// Store all keys lowercase for case-insensitive matching
	merged := make(map[string]bool, len(defaultNoiseUnits)+len(excludeUnits))
	for k, v := range defaultNoiseUnits {
		merged[strings.ToLower(k)] = v
	}
	for k, v := range excludeUnits {
		merged[strings.ToLower(k)] = v
	}

	if selfUnit == "" {
		selfUnit = "observer.service"
	}

	return &JournaldWatcher{
		handler:      handler,
		excludeUnits: merged,
		selfUnit:     selfUnit,
	}
}

// Run starts streaming journal entries. Blocks until ctx is cancelled.
// Automatically restarts journalctl if the subprocess exits unexpectedly.
func (j *JournaldWatcher) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := j.stream(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("[journald] journalctl exited unexpectedly: %v — restarting in 2s", err)
		time.Sleep(2 * time.Second)
	}
}

// stream runs one journalctl subprocess and processes its output.
func (j *JournaldWatcher) stream(ctx context.Context) error {
	// --since=now: only new entries, don't replay history on startup.
	// --output=json: structured output with all fields.
	// --follow: tail mode, like `journalctl -f`.
	cmd := exec.CommandContext(ctx, "journalctl",
		"--follow",
		"--output=json",
		"--since=now",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	log.Println("[journald] Streaming journal entries...")

	scanner := bufio.NewScanner(stdout)
	// Journal entries can be large (kernel dumps, etc.) — increase buffer.
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry journalEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Some journal entries have binary data that doesn't marshal cleanly.
			// Skip silently — these are almost never security-relevant.
			continue
		}

		// Skip empty messages
		if entry.Message == "" {
			continue
		}

		// --- Self-suppression (anti-spoof) ---
		// Filter our own logs using _SYSTEMD_UNIT, which is kernel-attached
		// and cannot be spoofed by an attacker. An attacker CAN spoof
		// SYSLOG_IDENTIFIER="observer" to hide behind our noise filter,
		// but they CANNOT spoof _SYSTEMD_UNIT.
		if entry.SystemdUnit == j.selfUnit {
			continue
		}

		// Identify the source — SYSLOG_IDENTIFIER is the cleanest identifier.
		// Falls back to _COMM (process name) if identifier isn't set.
		sourceName := entry.SyslogIdentifier
		if sourceName == "" {
			sourceName = entry.Comm
		}
		if sourceName == "" {
			sourceName = "unknown"
		}

		// --- Noise filter (case-insensitive, _SYSTEMD_UNIT only) ---
		// Only checks the trusted kernel-attached unit name.
		// SYSLOG_IDENTIFIER is NOT checked because it can be spoofed.
		if j.isNoiseUnit(entry.SystemdUnit) {
			continue
		}

		// Parse timestamp from __REALTIME_TIMESTAMP (microseconds since epoch).
		ts := time.Now()
		if entry.RealtimeTimestamp != "" {
			if usec, err := parseInt64(entry.RealtimeTimestamp); err == nil {
				ts = time.UnixMicro(usec)
			}
		}

		// Stream field: use transport type for journal entries
		stream := "journal"
		if entry.Transport != "" {
			stream = entry.Transport
		}

		j.handler(LogLine{
			SourceType: "journal",
			SourceName: sourceName,
			Line:       entry.Message,
			Stream:     stream,
			Timestamp:  ts,
			Metadata: map[string]string{
				"unit":     entry.SystemdUnit,
				"priority": entry.Priority,
				"pid":      entry.PID,
				"uid":      entry.UID,
				"hostname": entry.Hostname,
			},
		})
	}

	// v0.52: Check scanner error before cmd.Wait(). If the scanner hit
	// ErrTooLong (entry > 256KB buffer) or another error, it stopped
	// scanning but journalctl --follow is still running. Without killing
	// the process, cmd.Wait() blocks forever.
	if err := scanner.Err(); err != nil {
		log.Printf("[journald] Scanner error: %v — killing journalctl", err)
		cmd.Process.Kill()
		cmd.Wait()
		return fmt.Errorf("journal scanner: %w", err)
	}

	// Wait for process to exit
	return cmd.Wait()
}

// isNoiseUnit checks if a journal entry should be suppressed.
// ONLY checks _SYSTEMD_UNIT (trusted, kernel-attached). Does NOT check
// SYSLOG_IDENTIFIER because it can be spoofed by any process.
// Entries without a _SYSTEMD_UNIT (kernel, early boot) are never noise-filtered.
func (j *JournaldWatcher) isNoiseUnit(systemdUnit string) bool {
	if systemdUnit == "" {
		return false
	}
	unitBase := strings.ToLower(stripUnitSuffix(systemdUnit))
	return j.excludeUnits[unitBase]
}

// stripUnitSuffix removes .service, .socket, .timer, .scope suffixes from a unit name.
func stripUnitSuffix(unit string) string {
	for _, suffix := range []string{".service", ".socket", ".timer", ".scope", ".slice"} {
		if strings.HasSuffix(unit, suffix) {
			return strings.TrimSuffix(unit, suffix)
		}
	}
	return unit
}

// parseInt64 parses a string as int64. Avoids importing strconv for one function.
func parseInt64(s string) (int64, error) {
	var n int64
	neg := false
	i := 0
	if len(s) > 0 && s[0] == '-' {
		neg = true
		i = 1
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, &json.UnmarshalTypeError{Value: s}
		}
		n = n*10 + int64(s[i]-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

// ParseExcludeUnits parses a comma-separated list of unit names into a set.
func ParseExcludeUnits(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	units := make(map[string]bool)
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			units[name] = true
		}
	}
	return units
}
