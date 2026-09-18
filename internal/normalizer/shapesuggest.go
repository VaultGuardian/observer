// internal/normalizer/shapesuggest.go

package normalizer

import (
	"log"
	"strings"
	"sync"
)

// isFormatAgnostic reports whether a normalizer applies no format-specific
// handling - i.e. whether the source would benefit from a declared shape
// profile.
//
// This is deliberately a behavior test, not a Family() == "generic" test.
// DockerNormalizer has its own family name but delegates ENTIRELY to
// GenericNormalizer (see docker.go), so a container named "edge" is in
// exactly the position an unnamed generic source is: IPs and long numbers
// flattened, user-agent and request line untouched. Docker is the primary
// collector, so checking the family string alone would mean this never fired
// for the deployments the feature exists for.
func isFormatAgnostic(n Normalizer) bool {
	switch n.(type) {
	case *GenericNormalizer, *DockerNormalizer:
		return true
	default:
		return false
	}
}

// shapeSuggestMaxSamples caps how many lines are examined per source key
// before the check is abandoned for that source permanently.
//
// Without a cap, a generic source that never emits access logs - most of
// them - would pay a substring scan and occasionally a grammar match on
// every line for the life of the process, forever, to answer a question
// whose answer never changes. A few hundred lines is far more than enough
// to see an access log if one is coming.
const shapeSuggestMaxSamples = 500

// shapeSuggestState tracks which source keys have been reported, and how many
// lines have been examined for those that have not.
type shapeSuggestState struct {
	mu      sync.Mutex
	done    map[string]bool // reported, or gave up: never look again
	samples map[string]int  // lines examined so far, per source key
}

// maybeSuggestShapeProfile emits at most ONE advisory line per source key per
// process, when a source is resolving to GenericNormalizer and its lines
// parse as combined access logs.
//
// Two properties are load-bearing:
//
// It is advisory. It does not change normalization, it does not select a
// profile, and it does not record anything that later affects one. Log
// content must never cause a profile to be selected, switched or
// un-selected - only the operator's explicit configuration does that. This
// function exists to tell a human that writing that configuration would help.
//
// It fires once. A busy reverse proxy emits access lines continuously, so a
// per-line or per-batch warning would bury the journal and make the message
// worse than useless. One line per source key, then silence.
//
// The detector is the shape profile itself, not a looser sniffer. "Looks like
// combined access format" means exactly "http-combined-v1 would accept it",
// so the suggestion can never point an operator at a profile that would then
// decline their lines.
func (r *Registry) maybeSuggestShapeProfile(scopeKey, line string) {
	// Cheap pre-filter. A combined access line always carries a protocol
	// token, so one substring scan skips the grammar check for the
	// overwhelming majority of service-log lines.
	if !strings.Contains(line, "HTTP/") {
		return
	}

	if !r.claimSuggestSample(scopeKey) {
		return
	}

	// Parsed outside the lock: the grammar check must not serialize the
	// collector's goroutines.
	if _, ok := httpCombinedV1.Normalize(line); !ok {
		return
	}

	if !r.claimSuggestReport(scopeKey) {
		return
	}

	// The source key appears exactly once, inside a copy-pasteable value, so
	// the operator can act on this without consulting the documentation.
	log.Printf("[normalizer] generic normalizer in use for a source emitting combined access-log lines; "+
		"set NORMALIZER_HINTS_JSON='{%q:%q}' to keep method, path and status and drop volatile fields",
		scopeKey, ProfileHTTPCombinedV1)
}

// claimSuggestSample reports whether this line should be examined, counting
// it against the per-source sample cap.
func (r *Registry) claimSuggestSample(scopeKey string) bool {
	r.suggest.mu.Lock()
	defer r.suggest.mu.Unlock()

	if r.suggest.done[scopeKey] {
		return false
	}

	r.suggest.samples[scopeKey]++
	if r.suggest.samples[scopeKey] > shapeSuggestMaxSamples {
		// Give up on this source for good.
		r.suggest.done[scopeKey] = true
		delete(r.suggest.samples, scopeKey)
		return false
	}

	return true
}

// claimSuggestReport reports whether this goroutine owns the single warning
// for this source key. Re-checked under the lock because the grammar match
// ran outside it, so concurrent collectors can race to here.
func (r *Registry) claimSuggestReport(scopeKey string) bool {
	r.suggest.mu.Lock()
	defer r.suggest.mu.Unlock()

	if r.suggest.done[scopeKey] {
		return false
	}

	r.suggest.done[scopeKey] = true
	delete(r.suggest.samples, scopeKey)
	return true
}
