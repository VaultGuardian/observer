// internal/rec/redaction_xmlrpc.go
//
// =============================================================================
// Narrow XML-RPC response redactor - NOT a general XML sanitizer
// =============================================================================
//
// Motivation (flood survivability release, Part 1): WordPress xmlrpc.php
// fault bodies ship as text/html and previously fell through detectFormat's
// generic '<' branch as FormatHTML/ConfidenceLow, so the dual gate withheld
// the preview and findings stalled in needs-review. This parser accepts
// exactly the XML-RPC <methodResponse> grammar and nothing else; anything
// outside that grammar fails closed (no preview at all).
//
// Design rules (committee-locked):
//   - Input: complete HTTP body only (completeness flag from the capture
//     layer), max 2048 bytes, complete XML document.
//   - encoding/xml Decoder.Token() in Strict mode. No CharsetReader, no
//     custom Entity map, no HTML recovery. Element names and namespaces are
//     ALSO checked explicitly - Go strict mode does not fully enforce
//     namespace validity.
//   - Hard limits: depth <= 16, <= 512 tokens, <= 64 members/items per
//     container, member names <= 64 bytes, output <= 2048 bytes. Any breach
//     discards the entire tentative preview.
//   - Rejected outright: every Directive (DOCTYPE, internal or external
//     DTD), every processing instruction except one valid leading XML
//     declaration, comments, namespaces or attributes on the supported
//     element subset, undeclared entities (built-in and numeric character
//     references only), more than one root, trailing non-whitespace.
//   - The canonical output is constructed by EMITTING accepted tokens and
//     fixed markers - raw input ranges are never spliced into the output,
//     and failures never carry input bytes.
//
// A <fault> envelope identifies an RPC fault, not necessarily a failed
// attack. This function does structure + redaction only; existing evidence
// logic decides verdicts.
//
// Known accepted consequence: replacing the faultString value makes
// SensitiveRedactions > 0, which blocks the Lane A durable reclass-cache
// entry for fault bodies. Accepted and measured - never special-case fault
// strings or zero the count.

package rec

import (
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
	"strings"
)

const (
	xmlrpcMaxInputBytes  = 2048
	xmlrpcMaxDepth       = 16
	xmlrpcMaxTokens      = 512
	xmlrpcMaxMembers     = 64 // struct members / array items per container
	xmlrpcMaxNameBytes   = 64
	xmlrpcMaxOutputBytes = 2048
)

// Fixed redaction markers. Every replaced name/value counts toward
// SensitiveRedactions; type tags and structural position are preserved.
const (
	xmlrpcNameMarker   = "[NAME]"
	xmlrpcStringMarker = "[STRING]"
)

// xmlrpcScalarMarkers maps supported scalar TYPE tags to their value marker.
// Tags outside this set and the structural set below are unsupported → fail.
var xmlrpcScalarMarkers = map[string]string{
	"int":              "[INT]",
	"string":           xmlrpcStringMarker,
	"boolean":          "[BOOLEAN]",
	"double":           "[DOUBLE]",
	"dateTime.iso8601": "[DATETIME]",
	"base64":           "[BASE64]",
}

// xmlrpcStructuralElements is the validated protocol-tag subset.
var xmlrpcStructuralElements = map[string]bool{
	"methodResponse": true,
	"params":         true,
	"param":          true,
	"value":          true,
	"fault":          true,
	"struct":         true,
	"member":         true,
	"name":           true,
	"array":          true,
	"data":           true,
}

func xmlrpcElementAllowed(name string) bool {
	if xmlrpcStructuralElements[name] {
		return true
	}
	_, scalar := xmlrpcScalarMarkers[name]
	return scalar
}

// xmlrpcNode is one parsed element: accumulated character data (text and
// CDATA both arrive as xml.CharData) plus element children.
type xmlrpcNode struct {
	name     string
	text     []byte
	children []*xmlrpcNode
}

func (n *xmlrpcNode) textIsWhitespace() bool {
	return len(bytes.TrimSpace(n.text)) == 0
}

// redactXMLRPC parses and redacts an XML-RPC methodResponse body.
// Returns the canonical redacted preview, the redaction count, and ok=false
// on ANY failure (grammar, limits, incompleteness) - the caller must then
// withhold the preview entirely. Failure paths never expose input bytes.
func redactXMLRPC(preview []byte, bodyComplete bool) (string, int, bool) {
	// len(preview) and Content-Length are NOT proof of completeness - only
	// the capture layer's clean end-of-body flag is.
	if !bodyComplete || len(preview) == 0 || len(preview) > xmlrpcMaxInputBytes {
		return "", 0, false
	}

	root, ok := parseXMLRPCTree(trimBOMAndSpace(preview))
	if !ok {
		return "", 0, false
	}

	var e xmlrpcEmitter
	if !e.emitMethodResponse(root) {
		return "", 0, false
	}
	out := e.b.String()
	if len(out) > xmlrpcMaxOutputBytes {
		return "", 0, false
	}
	return out, e.redactions, true
}

// parseXMLRPCTree tokenizes the document under the hard limits and rejection
// rules, returning the root element tree. ok=false on any violation.
func parseXMLRPCTree(doc []byte) (*xmlrpcNode, bool) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	dec.Strict = true
	// No CharsetReader: a non-UTF-8 encoding declaration fails the decode.
	// No Entity map: only built-in (&lt; &gt; &amp; &apos; &quot;) and
	// numeric character references resolve; anything else errors in Strict.

	var (
		root       *xmlrpcNode
		stack      []*xmlrpcNode
		tokenCount int
		rootClosed bool
	)

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Malformed, truncated, bad encoding declaration, undeclared
			// entity, mismatched tags - all fail. Never surface err text:
			// encoding/xml errors can quote input bytes.
			return nil, false
		}
		tokenCount++
		if tokenCount > xmlrpcMaxTokens {
			return nil, false
		}

		switch t := tok.(type) {
		case xml.ProcInst:
			// Only a single valid leading XML declaration is accepted.
			if tokenCount != 1 || t.Target != "xml" {
				return nil, false
			}
		case xml.Directive:
			// Every directive rejected, DOCTYPE (internal or external DTD)
			// included.
			return nil, false
		case xml.Comment:
			// Rejected in this narrow first version.
			return nil, false
		case xml.StartElement:
			if rootClosed {
				return nil, false // second root element
			}
			// Explicit namespace + attribute rejection on the supported
			// subset (len(Attr) > 0 also covers xmlns declarations).
			if t.Name.Space != "" || len(t.Attr) > 0 {
				return nil, false
			}
			if !xmlrpcElementAllowed(t.Name.Local) {
				return nil, false
			}
			if len(stack)+1 > xmlrpcMaxDepth {
				return nil, false
			}
			node := &xmlrpcNode{name: t.Name.Local}
			if len(stack) == 0 {
				if root != nil || t.Name.Local != "methodResponse" {
					return nil, false
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				if (parent.name == "struct" || parent.name == "data") &&
					len(parent.children) >= xmlrpcMaxMembers {
					return nil, false
				}
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			// Strict mode guarantees the end tag matches the open element.
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				rootClosed = true
			}
		case xml.CharData:
			if len(stack) == 0 {
				// Text outside the root: whitespace only (trailing junk and
				// pre-root text both fail here).
				if len(bytes.TrimSpace(t)) > 0 {
					return nil, false
				}
			} else {
				cur := stack[len(stack)-1]
				cur.text = append(cur.text, t...)
			}
		}
	}

	// A complete document: one root, fully closed.
	if root == nil || !rootClosed || len(stack) != 0 {
		return nil, false
	}
	return root, true
}

// =============================================================================
// Grammar validation + canonical emission
// =============================================================================

type xmlrpcEmitter struct {
	b          strings.Builder
	redactions int
}

// emitMethodResponse validates the envelope: exactly one of <params> or
// <fault> (both present, or neither valid, fails).
func (e *xmlrpcEmitter) emitMethodResponse(n *xmlrpcNode) bool {
	if !n.textIsWhitespace() || len(n.children) != 1 {
		return false
	}
	e.b.WriteString("<methodResponse>")
	c := n.children[0]
	switch c.name {
	case "params":
		if !e.emitParams(c) {
			return false
		}
	case "fault":
		if !e.emitFault(c) {
			return false
		}
	default:
		return false
	}
	e.b.WriteString("</methodResponse>")
	return true
}

// emitParams validates the success envelope: <params> with exactly one
// <param> holding exactly one <value> (the XML-RPC response grammar).
func (e *xmlrpcEmitter) emitParams(n *xmlrpcNode) bool {
	if !n.textIsWhitespace() || len(n.children) != 1 || n.children[0].name != "param" {
		return false
	}
	p := n.children[0]
	if !p.textIsWhitespace() || len(p.children) != 1 || p.children[0].name != "value" {
		return false
	}
	e.b.WriteString("<params><param>")
	if !e.emitValue(p.children[0]) {
		return false
	}
	e.b.WriteString("</param></params>")
	return true
}

// emitFault validates the fault envelope: <fault> with exactly one <value>
// holding exactly one <struct>. Inside that struct - and ONLY there - the
// member names faultCode and faultString are preserved literally, each at
// most once (duplicates fail closed). Any other member is redacted like any
// success-payload member.
func (e *xmlrpcEmitter) emitFault(n *xmlrpcNode) bool {
	if !n.textIsWhitespace() || len(n.children) != 1 || n.children[0].name != "value" {
		return false
	}
	v := n.children[0]
	if !v.textIsWhitespace() || len(v.children) != 1 || v.children[0].name != "struct" {
		return false
	}
	st := v.children[0]
	if !st.textIsWhitespace() {
		return false
	}

	e.b.WriteString("<fault><value><struct>")
	seenCode, seenString := false, false
	for _, m := range st.children {
		if m.name != "member" {
			return false
		}
		nameNode, valNode, ok := xmlrpcMemberParts(m)
		if !ok {
			return false
		}
		switch string(nameNode.text) {
		case "faultCode":
			if seenCode {
				return false // duplicate fault member - fail closed
			}
			seenCode = true
			e.b.WriteString("<member><name>faultCode</name>")
			if !e.emitFaultCodeValue(valNode) {
				return false
			}
			e.b.WriteString("</member>")
		case "faultString":
			if seenString {
				return false // duplicate fault member - fail closed
			}
			seenString = true
			e.b.WriteString("<member><name>faultString</name>")
			if !e.emitValue(valNode) {
				return false
			}
			e.b.WriteString("</member>")
		default:
			if !e.emitMember(m) {
				return false
			}
		}
	}
	// A valid fault carries both canonical members.
	if !seenCode || !seenString {
		return false
	}
	e.b.WriteString("</struct></value></fault>")
	return true
}

// emitFaultCodeValue preserves the faultCode value ONLY when it is an <int>
// scalar parsing as a signed 32-bit integer; the emitted digits come from
// re-formatting the parsed value (accepted-token emission), never from
// splicing input. Anything else is redacted like any value.
func (e *xmlrpcEmitter) emitFaultCodeValue(v *xmlrpcNode) bool {
	if v.textIsWhitespace() && len(v.children) == 1 && v.children[0].name == "int" {
		iv := v.children[0]
		if len(iv.children) == 0 {
			if code, err := strconv.ParseInt(strings.TrimSpace(string(iv.text)), 10, 32); err == nil {
				e.b.WriteString("<value><int>")
				e.b.WriteString(strconv.FormatInt(code, 10))
				e.b.WriteString("</int></value>")
				return true
			}
		}
	}
	return e.emitValue(v)
}

// xmlrpcMemberParts validates a <member>: exactly <name> then <value>, the
// name text-only and at most xmlrpcMaxNameBytes bytes.
func xmlrpcMemberParts(m *xmlrpcNode) (nameNode, valNode *xmlrpcNode, ok bool) {
	if !m.textIsWhitespace() || len(m.children) != 2 {
		return nil, nil, false
	}
	if m.children[0].name != "name" || m.children[1].name != "value" {
		return nil, nil, false
	}
	n := m.children[0]
	if len(n.children) != 0 || len(n.text) > xmlrpcMaxNameBytes {
		return nil, nil, false
	}
	return n, m.children[1], true
}

// emitMember redacts an ordinary member: name → [NAME], value redacted
// recursively. A member literally named faultCode/faultString outside the
// validated fault position lands here and is redacted like any other - the
// document stays success-shaped.
func (e *xmlrpcEmitter) emitMember(m *xmlrpcNode) bool {
	_, valNode, ok := xmlrpcMemberParts(m)
	if !ok {
		return false
	}
	e.b.WriteString("<member><name>")
	e.b.WriteString(xmlrpcNameMarker)
	e.b.WriteString("</name>")
	e.redactions++
	if !e.emitValue(valNode) {
		return false
	}
	e.b.WriteString("</member>")
	return true
}

// emitValue redacts a <value>: implicit strings (bare text, CDATA, empty)
// and every scalar become fixed markers preserving the type tag; structs and
// arrays recurse. Mixed content and unsupported shapes fail.
func (e *xmlrpcEmitter) emitValue(v *xmlrpcNode) bool {
	switch len(v.children) {
	case 0:
		// Implicit string: bare <value> text (CDATA included) or empty.
		e.b.WriteString("<value>")
		e.b.WriteString(xmlrpcStringMarker)
		e.b.WriteString("</value>")
		e.redactions++
		return true
	case 1:
		if !v.textIsWhitespace() {
			return false // mixed element + text content
		}
		c := v.children[0]
		if marker, isScalar := xmlrpcScalarMarkers[c.name]; isScalar {
			if len(c.children) != 0 {
				return false // scalars are text-only
			}
			e.b.WriteString("<value><")
			e.b.WriteString(c.name)
			e.b.WriteString(">")
			e.b.WriteString(marker)
			e.b.WriteString("</")
			e.b.WriteString(c.name)
			e.b.WriteString("></value>")
			e.redactions++
			return true
		}
		switch c.name {
		case "struct":
			if !c.textIsWhitespace() {
				return false
			}
			e.b.WriteString("<value><struct>")
			for _, m := range c.children {
				if m.name != "member" || !e.emitMember(m) {
					return false
				}
			}
			e.b.WriteString("</struct></value>")
			return true
		case "array":
			if !c.textIsWhitespace() || len(c.children) != 1 || c.children[0].name != "data" {
				return false
			}
			d := c.children[0]
			if !d.textIsWhitespace() {
				return false
			}
			e.b.WriteString("<value><array><data>")
			for _, item := range d.children {
				if item.name != "value" || !e.emitValue(item) {
					return false
				}
			}
			e.b.WriteString("</data></array></value>")
			return true
		}
		return false
	default:
		return false
	}
}
