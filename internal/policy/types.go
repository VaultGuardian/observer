package policy

// Result is the outcome of a policy evaluation.
// Returned by Engine.Evaluate for every event — Matched=false means
// "policy has no opinion, continue to LLM pipeline."
//
// Design: generic, not journald-specific. The first rules target SSH/access
// seeds from journald, but the interface supports auditd, file watchers,
// Docker exec events, or any future source.
type Result struct {
	// Matched is true if a policy rule fired for this event.
	// When true, the event should short-circuit the LLM pipeline.
	Matched bool

	// Action is what Observer should do:
	//   "escalate" — record finding + send email immediately
	//   "alert"    — record finding, no email (dashboard review)
	//   "allow"    — trusted/known-good, suppress silently
	Action string

	// RuleID identifies which policy rule fired (e.g. "ssh_login_unknown_ip").
	// Used for stats, debugging, and dashboard display.
	RuleID string

	// Reason is the human-readable explanation shown in findings and emails.
	Reason string

	// Extracted fields — populated by the matching rule even if not all
	// are used for the current action. Future-proofing per code review's advice:
	// "extract username, auth method, source IP now, even if you only use IP today."
	SourceIP   string
	Username   string
	AuthMethod string

	// Metadata holds rule-specific extras for dashboard display.
	Metadata map[string]string
}