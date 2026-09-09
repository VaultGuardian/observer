package api

// =============================================================================
// Pinned "already in the desired state" responses
// =============================================================================
//
// The hosted command channel (internal/sync lane C) executes dashboard
// commands against these local handlers and must distinguish two kinds of 4xx:
//
//	"you asked for something invalid"          -> rejected, terminal failure
//	"that is already true, nothing to do"      -> converged, terminal success
//
// The second kind is what makes commands effect-convergent, which is the
// property the receipt ledger's residual crash window relies on: a command
// replayed after a crash between the local mutation and the receipt commit
// must reach the same end state without the operator seeing a spurious
// failure.
//
// Convergence is therefore matched on the response text, so the response text
// is a contract, not a copy decision. Handlers write these constants instead
// of string literals and lane C matches on the same constants, so an edit here
// changes both sides together. converged_test.go pins the literal values, so a
// well-meaning rewording fails the test suite rather than silently turning
// convergence back into failure.
const (
	// ConvergedPatternNotFound is POST /api/patterns/delete's 404 when the
	// pattern is not in the store. For a delete command that is success:
	// somebody (or an earlier delivery of this same command) already removed
	// it.
	ConvergedPatternNotFound = "Pattern not found"

	// ConvergedTrustedIPExists is POST /api/trusted-ips' 400 when the address
	// or range is already trusted. Emitted as a substring of a message that
	// also names the address, so lane C matches on containment.
	ConvergedTrustedIPExists = "already trusted"

	// ConvergedTrustedIPNotFound is POST /api/trusted-ips/delete's 404 when
	// the row is already gone.
	ConvergedTrustedIPNotFound = "Trusted IP not found"
)

// ConvergedResponses lists every pinned string, for lane C's matcher and for
// the test that asserts the handlers actually emit them.
func ConvergedResponses() []string {
	return []string{
		ConvergedPatternNotFound,
		ConvergedTrustedIPExists,
		ConvergedTrustedIPNotFound,
	}
}
