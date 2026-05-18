package policy

import (
	"log"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/vaultguardian/observer/internal/event"
	"github.com/vaultguardian/observer/internal/store"
)

// Engine is the deterministic policy layer that runs before the LLM pipeline.
// It evaluates events against seed rules and trusted-IP allowlists.
//
// Design principles (design consensus, April 2026):
//   - Policy is identity, not inference. AI can't know "is this Drew?"
//   - Deterministic: regex match + table lookup, no LLM, no ML
//   - Generic: first rules target journald SSH, but interface supports any source
//   - One road: results flow through shared outcome handler, no bypass lanes
//   - Observable: every match recorded as first-class finding
type Engine struct {
	store *store.Store
	rules []Rule

	// Stats
	matches     atomic.Int64
	escalations atomic.Int64
	allows      atomic.Int64
	alerts      atomic.Int64
}

// Rule is a single deterministic policy rule.
type Rule struct {
	// ID uniquely identifies this rule (e.g. "ssh_login", "useradd")
	ID string

	// SourceFilter limits which events this rule examines.
	// Empty string means "any source type."
	SourceType string // "journal", "docker", "audit", "" for any
	SourceName string // "sshd", "sudo", "" for any within SourceType

	// MatchKernelUnits, when non-empty, requires the kernel-attached
	// _SYSTEMD_UNIT of a journald event (carried in evt.Metadata["unit"])
	// to normalize to one of these values. Use this for high-confidence
	// rules where the attacker could otherwise spoof SYSLOG_IDENTIFIER —
	// e.g. a container writing SYSLOG_IDENTIFIER="sshd" to journald.
	//
	// Normalization strips ".service"/".scope" and any "@instance" suffix:
	//   "ssh.service"             -> "ssh"
	//   "sshd@1.2.3.4-22.service" -> "sshd"
	//   "docker-abc123.scope"     -> "docker-abc123"
	//
	// Matching is case-insensitive. When set, this is the trust anchor;
	// SourceName above can be left empty to avoid double-filtering.
	MatchKernelUnits []string

	// Pattern is the compiled regex to match against the event line.
	Pattern *regexp.Regexp

	// Extract pulls structured fields from the matched line.
	// Called only when Pattern matches. Returns partial Result with
	// extracted fields populated.
	Extract func(matches []string) Result

	// NeedsTrustCheck is true if this rule should consult the trusted_ips table.
	// When true AND the extracted IP is trusted → action becomes "allow".
	// When true AND the extracted IP is NOT trusted → action stays as defined.
	NeedsTrustCheck bool

	// DefaultAction is the action when the rule matches (and trust check passes).
	// "escalate" for unknown SSH, "alert" for useradd, etc.
	DefaultAction string
}

// New creates a policy engine with the default seed rules.
func New(db *store.Store) *Engine {
	e := &Engine{
		store: db,
		rules: defaultRules(),
	}
	log.Printf("[policy] Initialized with %d rules", len(e.rules))
	return e
}

// Evaluate checks an event against all policy rules.
// Returns Result{Matched: false} if no rule fires — the event should
// continue to the normal LLM pipeline.
//
// Called from makeLogHandler after event creation, before a.Analyze().
func (e *Engine) Evaluate(evt *event.Event) Result {
	for _, rule := range e.rules {
		// Source filter: skip rules that don't apply to this event type
		if rule.SourceType != "" && evt.SourceType != rule.SourceType {
			continue
		}
		if rule.SourceName != "" && !strings.EqualFold(evt.SourceName, rule.SourceName) {
			continue
		}
		// Kernel-attached unit filter (anti-spoof). When set, the rule only
		// fires for events whose _SYSTEMD_UNIT normalizes to one of the
		// listed units. The unit is recorded by the journald watcher in
		// evt.Metadata["unit"]; for non-journald sources it's empty and
		// the rule won't match.
		if len(rule.MatchKernelUnits) > 0 {
			if !unitMatches(evt.Metadata["unit"], rule.MatchKernelUnits) {
				continue
			}
		}

		// Pattern match
		matches := rule.Pattern.FindStringSubmatch(evt.Line)
		if matches == nil {
			continue
		}

		// Extract structured fields
		result := rule.Extract(matches)
		result.Matched = true
		result.RuleID = rule.ID
		result.Action = rule.DefaultAction

		// Trust check: if the rule requires it and we have an IP, consult the allowlist
		if rule.NeedsTrustCheck && result.SourceIP != "" {
			trusted, err := e.store.IsTrustedIP(result.SourceIP)
			if err != nil {
				log.Printf("[policy] Trust check failed for %s: %v (treating as untrusted)", result.SourceIP, err)
				trusted = false
			}

			if trusted {
				result.Action = "allow"
				result.Reason = "Trusted IP: " + result.SourceIP
				e.allows.Add(1)
				e.matches.Add(1)
				log.Printf("[policy] ALLOW rule=%s ip=%s user=%s (trusted)",
					rule.ID, result.SourceIP, result.Username)
				return result
			}
		}

		// Rule matched, not trusted (or no trust check needed)
		e.matches.Add(1)
		switch result.Action {
		case "escalate":
			e.escalations.Add(1)
		case "alert":
			e.alerts.Add(1)
		}

		log.Printf("[policy] MATCH rule=%s action=%s ip=%s user=%s reason=%s",
			rule.ID, result.Action, result.SourceIP, result.Username, result.Reason)
		return result
	}

	return Result{Matched: false}
}

// Stats returns current policy engine counters.
func (e *Engine) Stats() (matches, escalations, allows, alerts int64) {
	return e.matches.Load(), e.escalations.Load(), e.allows.Load(), e.alerts.Load()
}

// =============================================================================
// Default Seed Rules
// =============================================================================

// defaultRules returns the v0.34 seed rules.
// Conservative set per design consensus:
//   - SSH success from unknown IP → escalate (the big one)
//   - useradd → escalate (persistence)
//   - usermod privilege grant → escalate (privilege escalation)
//   - authorized_keys modification → escalate (key injection)
//   - failed sudo → alert (someone inside trying to escalate)
func defaultRules() []Rule {
	return []Rule{
		// ----- SSH Success -----
		// Matches: "Accepted password for root from 1.2.3.4 port 43822 ssh2"
		// Matches: "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2"
		//
		// Anti-spoof: requires the kernel-attached _SYSTEMD_UNIT, not the
		// freely-settable SYSLOG_IDENTIFIER. A container writing
		// `SYSLOG_IDENTIFIER="sshd"` to journald cannot fake "ssh.service"
		// as its cgroup-derived unit. Debian's unit is "ssh", RHEL's is
		// "sshd"; both are accepted.
		{
			ID:               "ssh_login",
			SourceType:       "journal",
			MatchKernelUnits: []string{"ssh", "sshd"},
			Pattern:          regexp.MustCompile(`Accepted\s+(password|publickey|keyboard-interactive)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`),
			Extract: func(m []string) Result {
				return Result{
					AuthMethod: m[1],
					Username:   m[2],
					SourceIP:   m[3],
					Reason:     "Successful SSH login from unknown IP " + m[3] + " as " + m[2] + " (" + m[1] + ")",
					Metadata: map[string]string{
						"port": m[4],
					},
				}
			},
			NeedsTrustCheck: true,
			DefaultAction:   "escalate",
		},

		// ----- New User Created -----
		// Matches: "new user: name=backdoor, UID=1001, ..."
		{
			ID:         "useradd",
			SourceType: "journal",
			SourceName: "", // can come from useradd, adduser, or sshd context
			Pattern:    regexp.MustCompile(`new user:\s+name=(\S+)`),
			Extract: func(m []string) Result {
				return Result{
					Username: m[1],
					Reason:   "New user created: " + m[1],
				}
			},
			NeedsTrustCheck: false,
			DefaultAction:   "escalate",
		},

		// ----- Privilege Grant (usermod) -----
		// Matches: "add 'deploy' to group 'sudo'"
		// Matches: "usermod ... -aG sudo deploy"
		{
			ID:         "privilege_grant",
			SourceType: "journal",
			Pattern:    regexp.MustCompile(`(?i)(?:add\s+'?(\S+?)'?\s+to\s+group\s+'?(sudo|wheel|root|admin)'?|usermod\s+.*-aG\s+.*(sudo|wheel|root|admin)\s+(\S+))`),
			Extract: func(m []string) Result {
				user := m[1]
				group := m[2]
				if user == "" {
					user = m[4]
				}
				if group == "" {
					group = m[3]
				}
				return Result{
					Username: user,
					Reason:   "Privilege escalation: user " + user + " added to " + group,
				}
			},
			NeedsTrustCheck: false,
			DefaultAction:   "escalate",
		},

		// ----- authorized_keys modification -----
		// Catches sudo/sshd/audit context lines mentioning authorized_keys
		{
			ID:         "authorized_keys",
			SourceType: "journal",
			Pattern:    regexp.MustCompile(`(?i)authorized_keys`),
			Extract: func(m []string) Result {
				return Result{
					Reason: "SSH authorized_keys file accessed or modified",
				}
			},
			NeedsTrustCheck: false,
			DefaultAction:   "escalate",
		},

		// ----- Failed Sudo (someone inside, trying to escalate) -----
		// Matches: "user NOT in sudoers" or "3 incorrect password attempts"
		// Alert only, not escalate — noisy but indicates compromise.
		//
		// Residual spoof risk: this rule matches against the spoofable
		// SYSLOG_IDENTIFIER "sudo" rather than a kernel-attached unit.
		// Tightening with MatchKernelUnits is impractical because sudo
		// inherits its cgroup from the parent session (e.g. ssh@N.service,
		// user@1000.service, session-N.scope) — there is no canonical
		// "sudo.service" unit to match on. A container writing fake sudo
		// lines to journald can therefore trip this rule. Mitigation:
		// it's "alert", not "escalate", and the trusted_ips allowlist
		// handles the legitimate operator case.
		{
			ID:         "sudo_failure",
			SourceType: "journal",
			SourceName: "sudo",
			Pattern:    regexp.MustCompile(`(?:NOT in sudoers|incorrect password attempt|authentication failure.*sudo)`),
			Extract: func(m []string) Result {
				return Result{
					Reason: "Failed sudo attempt — possible privilege escalation",
				}
			},
			NeedsTrustCheck: false,
			DefaultAction:   "alert",
		},

		// ----- PAM Session (redundant after SSH policy) -----
		// pam_unix logs "session opened/closed" after every SSH login.
		// The ssh_login rule already handles the authentication event —
		// whether escalated (unknown IP) or allowed (trusted IP).
		// Without this rule, PAM lines fall through to the LLM and get
		// classified as "suspicious" independently, creating duplicate alerts.
		{
			ID:         "pam_session",
			SourceType: "journal",
			Pattern:    regexp.MustCompile(`pam_unix\(\S+:session\):\s+session\s+(opened|closed)\s+for\s+user\s+(\S+)`),
			Extract: func(m []string) Result {
				return Result{
					Username: m[2],
					Reason:   "PAM session " + m[1] + " for " + m[2] + " (handled by SSH policy)",
				}
			},
			NeedsTrustCheck: false,
			DefaultAction:   "allow",
		},
	}
}

// unitMatches reports whether the unit (e.g. "ssh.service" from
// evt.Metadata["unit"]) normalizes to any of the allowed unit names.
// Empty unit returns false — rules with MatchKernelUnits set are journald-
// scoped and an event with no unit can't satisfy them.
func unitMatches(unit string, allowed []string) bool {
	if unit == "" {
		return false
	}
	normalized := normalizeUnit(unit)
	for _, a := range allowed {
		if strings.EqualFold(normalized, a) {
			return true
		}
	}
	return false
}

// normalizeUnit strips ".service"/".scope"/".socket"/etc. suffixes and any
// "@instance" portion from a systemd unit name, returning the lowercase base.
//
//	"ssh.service"             -> "ssh"
//	"sshd@1.2.3.4-22.service" -> "sshd"
//	"user@1000.service"       -> "user"
//	"docker-abc123.scope"     -> "docker-abc123"
func normalizeUnit(unit string) string {
	u := unit
	if dot := strings.LastIndexByte(u, '.'); dot >= 0 {
		u = u[:dot]
	}
	if at := strings.IndexByte(u, '@'); at >= 0 {
		u = u[:at]
	}
	return strings.ToLower(u)
}
