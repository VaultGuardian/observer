// internal/normalizer/httpcombined.go

package normalizer

import (
	"regexp"
	"strings"
)

// httpCombinedV1Profile implements the strict combined-access-log grammar.
//
// Accepted grammar - and nothing else:
//
//	client ident user [timestamp] "request" status bytes "referer" "user-agent"
//	client ident user [timestamp] "request" status bytes "referer" "user-agent" "xff"
//
// The four-quoted-field form is nginx's $http_x_forwarded_for extension. It
// is included because it is what real deployments emit: every access line in
// this repository's own corpus carries the trailing field. The five-field
// CapRover vhost variant is NOT accepted - that format is already served by
// the name-matched nginx normalizer, so declining it costs nothing.
//
// On acceptance the output is built by joinAccessParts, the same helper
// NginxNormalizer uses, so a hinted proxy and a name-matched nginx container
// produce a byte-identical normalized line and the same hash for the same
// request. That identity is the entire point: it is what lets an exact-hash
// lookup catch the backend twin of an attack instead of paying full T1+T2.
//
// Everything here is fail-closed. Each guard below exists because a line that
// trips it is AMBIGUOUS, and the cost of guessing wrong is a poisoned pattern
// store rather than a visible error.
type httpCombinedV1Profile struct{}

// httpCombinedV1 is the singleton registered in shippedProfiles.
var httpCombinedV1 ShapeProfile = &httpCombinedV1Profile{}

func (p *httpCombinedV1Profile) Name() string { return ProfileHTTPCombinedV1 }

var (
	// reHTTPCombined is the whole grammar, anchored end to end. Every field
	// is positional; there is no optional slack except the trailing XFF
	// field. Anchoring is what rejects leading and trailing garbage.
	//
	// Field notes:
	//   client - IPv4, bare IPv6 or a hostname. Deliberately excludes the
	//            quote character, so a quoted first field declines.
	//   ident  - identd response, conventionally "-" but a real token is
	//            accepted and stripped; it must not contain quotes/brackets.
	//   user   - HTTP auth username, same treatment as ident. "- -" and
	//            "- alice" both parse and normalize identically, so a client
	//            authenticating does not split an otherwise identical
	//            request into two hashes.
	//   ts     - shape-checked against reNginxBracketTS below.
	//   status - exactly three digits.
	//   bytes  - digits, or "-" for a response with no body.
	reHTTPCombined = regexp.MustCompile(
		`^([A-Za-z0-9_.:-]+)` + // client
			`[ \t]+([^"\[\]\s]+)` + // ident
			`[ \t]+([^"\[\]\s]+)` + // user
			`[ \t]+(\[[^\[\]]*\])` + // [timestamp]
			`[ \t]+"([^"]*)"` + // "request"
			`[ \t]+(\d{3})` + // status
			`[ \t]+(\d+|-)` + // bytes
			`[ \t]+"([^"]*)"` + // "referer"
			`[ \t]+"([^"]*)"` + // "user-agent"
			`(?:[ \t]+"([^"]*)")?$`, // optional "x-forwarded-for"
	)
)

// Index of the capture groups in reHTTPCombined.
const (
	hcGroupTimestamp = 4
	hcGroupRequest   = 5
	hcGroupStatus    = 6
)

// Quote counts for the two accepted shapes: three quoted fields (canonical
// combined) or four (combined plus x-forwarded-for).
const (
	hcQuotesCanonical = 6
	hcQuotesWithXFF   = 8
)

func (p *httpCombinedV1Profile) Normalize(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", false
	}

	// Guard 1: a backslash-escaped quote means the emitter escaped a quote
	// inside a field. Quoted-field parsing cannot recover the true field
	// boundaries from that, so there is no honest reading of the line.
	if strings.Contains(line, `\"`) {
		return "", false
	}

	// Guard 2: the quote count must match one of the two accepted shapes
	// exactly. This is what rejects the five-field CapRover vhost variant
	// (ten quotes), common log format with no referer/user-agent, and any
	// line where a literal quote inside a field has shifted the boundaries.
	if n := strings.Count(line, `"`); n != hcQuotesCanonical && n != hcQuotesWithXFF {
		return "", false
	}

	// Guard 3: exactly one bracket-timestamp-shaped substring in the whole
	// line. Zero means the request time is missing or malformed. Two or more
	// means something else - typically a bot user-agent or a referrer -
	// carries a timestamp-shaped substring, and which bracket group is THE
	// request time is then a guess. Reusing reNginxBracketTS keeps this in
	// lockstep with the nginx access path.
	if len(reNginxBracketTS.FindAllString(line, 2)) != 1 {
		return "", false
	}

	m := reHTTPCombined.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}

	// Guard 4: the single bracket group the grammar matched must be the
	// timestamp itself, fully - not a bracketed field that merely sits in
	// the timestamp's position.
	ts := m[hcGroupTimestamp]
	if reNginxBracketTS.FindString(ts) != ts {
		return "", false
	}

	// Guard 5: the request line must be a real request line. reRequestLine
	// is the nginx access path's own check, so the two stay consistent; it
	// covers the nine methods and both HTTP/1.1 and HTTP/2.0 forms.
	requestLine := m[hcGroupRequest]
	if !reRequestLine.MatchString(requestLine) {
		return "", false
	}

	// Accepted. Rendered by the shared helper so the output is identical to
	// what NginxNormalizer produces for the same line. No host field: the
	// combined grammar has no vhost slot, and the CapRover variant that does
	// is declined by guard 2.
	return joinAccessParts("", requestLine, m[hcGroupStatus]), true
}
