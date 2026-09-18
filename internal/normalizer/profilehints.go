// internal/normalizer/profilehints.go

package normalizer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ProfileHints maps a source key to the shape profile the operator declared
// for it.
//
// Keys use the same scope forms Registry.Lookup already understands, and no
// others:
//
//	"source_type:source_name"  - matches event.ScopeKey(), e.g. "docker:edge"
//	"source_name"              - bare name, across every collector type
//
// The value type is a resolved ShapeProfile rather than a name string, so an
// unvalidated hint set is unrepresentable: ParseProfileHints is the only way
// to build one, and it fails rather than producing a map with a bad entry.
type ProfileHints map[string]ShapeProfile

// ParseProfileHints parses and validates the NORMALIZER_HINTS_JSON document.
//
// An empty or unset value returns no hints and no error - that is today's
// behavior, bit for bit.
//
// Everything else fails loudly. Malformed JSON and unknown profile names stop
// startup rather than warning and continuing, because a typo'd profile name
// that silently degraded to GenericNormalizer is the exact failure this
// feature exists to prevent: normalization would quietly get worse, with no
// error anywhere and only a slow drift in cache hit rate to show for it.
func ParseProfileHints(raw string) (ProfileHints, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	var decoded map[string]string
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, fmt.Errorf(
			"NORMALIZER_HINTS_JSON must be a JSON object mapping a source key to a profile name, "+
				"e.g. {%q:%q} (valid profiles: %s): %w",
			"docker:edge", ProfileHTTPCombinedV1, strings.Join(ProfileNames(), ", "), err)
	}
	if decoded == nil {
		// Literal JSON null parses cleanly into a nil map. Treat it as the
		// configuration error it is rather than as "unset" - an operator who
		// wrote null meant something, and silently ignoring it would be the
		// same silent degradation the loud failures above exist to prevent.
		return nil, fmt.Errorf(
			"NORMALIZER_HINTS_JSON is null; unset the variable to disable shape profiles, "+
				"or set a JSON object (valid profiles: %s)",
			strings.Join(ProfileNames(), ", "))
	}

	// Validate in sorted key order so the same bad document always reports
	// the same offending key.
	keys := make([]string, 0, len(decoded))
	for k := range decoded {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	hints := make(ProfileHints, len(decoded))
	for _, rawKey := range keys {
		key := strings.TrimSpace(rawKey)
		if key == "" {
			return nil, fmt.Errorf(
				"NORMALIZER_HINTS_JSON has an empty source key; keys are %q or a bare %q",
				"source_type:source_name", "source_name")
		}

		profileName := strings.TrimSpace(decoded[rawKey])
		if profileName == "" {
			return nil, fmt.Errorf(
				"NORMALIZER_HINTS_JSON: source key %q has an empty profile name (valid profiles: %s)",
				key, strings.Join(ProfileNames(), ", "))
		}

		profile, ok := LookupProfile(profileName)
		if !ok {
			return nil, fmt.Errorf(
				"NORMALIZER_HINTS_JSON: source key %q names unknown profile %q (valid profiles: %s)",
				key, profileName, strings.Join(ProfileNames(), ", "))
		}

		hints[key] = profile
	}

	return hints, nil
}

// profileFor returns the shape profile the operator declared for this event's
// source, if any.
//
// Precedence mirrors Lookup's own first two steps: the scope key is more
// specific than the bare source name, so it wins. A scope-key hint does not
// leak across collector types.
//
// The hint map is written once at construction and never mutated, so this
// needs no lock on the hot path.
func (r *Registry) profileFor(scopeKey, sourceName string) (ShapeProfile, bool) {
	if len(r.profileHints) == 0 {
		return nil, false
	}
	if p, ok := r.profileHints[scopeKey]; ok {
		return p, true
	}
	if p, ok := r.profileHints[sourceName]; ok {
		return p, true
	}
	return nil, false
}
