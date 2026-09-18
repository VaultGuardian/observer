// internal/normalizer/shapeprofile.go

package normalizer

import "sort"

// ShapeProfile is a DECLARED log grammar.
//
// A profile is never inferred. It applies to a source because the operator
// named it in NORMALIZER_HINTS_JSON, and for no other reason: nothing about
// the content of a log line may cause a profile to be selected, switched or
// un-selected at runtime. There is no sniffing, no confidence score, no
// promotion and no learning.
//
// Profiles exist because Registry.Lookup resolves by NAME. A reverse proxy
// called "edge", "router" or "gateway" emitting byte-identical combined
// access logs falls to GenericNormalizer purely because its name does not
// happen to contain "nginx", so structurally identical requests hash
// differently and the exact-hash tier misses them. A hint lets the operator
// declare the format instead of relying on naming luck.
type ShapeProfile interface {
	// Name returns the profile's stable identifier, as written in
	// NORMALIZER_HINTS_JSON and documented in docs/configuration.md.
	Name() string

	// Normalize parses a log line against the profile's grammar.
	//
	// It returns (normalized, true) when the line satisfies the grammar in
	// full, and ("", false) when it does not. Declining is the safe outcome:
	// the caller falls through to the normal Lookup chain exactly as if no
	// hint existed. Mis-parsing is not safe - a wrong normalized line enters
	// the hash, the learned pattern store and the LLM cache key, and poisons
	// classification without throwing an error. Profiles therefore give no
	// partial credit: a line that is NEARLY the declared format is not the
	// declared format.
	//
	// The line arrives with collector framing and the vgrid lineage token
	// already stripped by Registry.NormalizeEvent, so a profile only ever
	// sees the application's native log content.
	Normalize(line string) (string, bool)
}

// Shipped profile names. These strings are operator-facing: they appear in
// env files and in docs/configuration.md, so they are part of the interface
// and do not change once released.
const (
	// ProfileHTTPCombinedV1 is the strict combined-access-log grammar.
	ProfileHTTPCombinedV1 = "http-combined-v1"
)

// shippedProfiles is the complete set of profiles this build understands.
// Populated once at init and read-only thereafter.
var shippedProfiles = map[string]ShapeProfile{
	ProfileHTTPCombinedV1: httpCombinedV1,
}

// LookupProfile resolves a profile by its exact name. Matching is exact and
// case-sensitive on purpose: a near-miss is a configuration error the
// operator needs told about, not something to guess at.
func LookupProfile(name string) (ShapeProfile, bool) {
	p, ok := shippedProfiles[name]
	return p, ok
}

// ProfileNames returns every valid profile name, sorted. Used to build
// actionable configuration errors - an operator who typo'd a profile name
// should not have to read the source to find the right spelling.
func ProfileNames() []string {
	names := make([]string, 0, len(shippedProfiles))
	for name := range shippedProfiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
