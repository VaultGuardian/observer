package rec

import (
	"testing"
	"time"
)

// Canonical trigger: the ThinkPHP RCE probe. nginx (escape=default) rewrites
// each literal backslash (0x5C) as the 4-char sequence \x5C in the access log,
// while REC's sniffer stores the literal wire bytes.
const (
	thinkPHPEscapedPath = `/?s=/Index/\x5Cthink\x5Capp/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=test`
	thinkPHPLiteralPath = `/?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=test`
)

func TestDecodeNginxLogPath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"thinkphp backslash escapes", thinkPHPEscapedPath, thinkPHPLiteralPath},
		{"clean path no escapes", "/phpinfo?a=1", "/phpinfo?a=1"},
		{"empty", "", ""},
		{"double quote", `\x22`, `"`},
		{"control byte LF", `\x0A`, "\n"},
		{"high byte uppercase hex", `\xFF`, string([]byte{0xFF})},
		{"high byte lowercase hex", `\xff`, string([]byte{0xFF})},
		{"literal backslash-x round trip", `\x5Cx5C`, `\x5C`},
		{"malformed single hex digit", `\x5`, `\x5`},
		{"malformed non-hex digits", `\xZZ`, `\xZZ`},
		{"truncated at end of string", `abc\x`, `abc\x`},
		{"multiple sequences with text", `a\x41b\x42c`, "aAbBc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeNginxLogPath(tc.in); got != tc.want {
				t.Errorf("decodeNginxLogPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMatchesVIP_NginxEscapedPath is the core regression: the escaped log path
// must NOT match the literal wire capture (the bug), and the decoded path MUST.
func TestMatchesVIP_NginxEscapedPath(t *testing.T) {
	now := time.Now()
	wireResp := CapturedResponse{
		Timestamp:  now,
		Method:     "GET",
		Path:       thinkPHPLiteralPath, // sniffer stores literal wire bytes
		StatusCode: 200,
	}
	escapedReq := LookupRequest{
		Method:     "GET",
		Path:       thinkPHPEscapedPath, // path as read from the nginx access log
		StatusCode: 200,
		Timestamp:  now,
		Window:     5 * time.Second,
	}

	// Negative control: raw escaped log path does not match literal wire capture.
	if matchesVIP(wireResp, escapedReq) {
		t.Fatal("escaped log path unexpectedly matched literal wire capture (negative control failed)")
	}

	// Positive: after decoding, the path is wire-identical and matches.
	if !matchesVIP(wireResp, normalizeLookupRequest(escapedReq)) {
		t.Fatal("decoded log path failed to match literal wire capture")
	}
}

// TestPinVIP_EscapedPathMatchesLiteralCapture exercises the full VIP path that
// the ThinkPHP probe takes: a malicious event pins with the escaped log path,
// the sniffer later delivers the response with the literal wire path, and the
// coordinator's evidence check (also escaped) then finds the promoted evidence.
func TestPinVIP_EscapedPathMatchesLiteralCapture(t *testing.T) {
	lc := &liveCollector{
		buffer:      NewRingBuffer(DefaultBufferConfig()),
		vipPins:     make(map[string]*vipPin),
		vipEvidence: make(map[string]CapturedResponse),
	}
	lc.running.Store(true)

	now := time.Now()
	const eventID = "evt-thinkphp-1"

	// Malicious-event path (resultrouter): pin with the escaped log path.
	lc.PinVIP(eventID, "corr-key-1", LookupRequest{
		Method:     "GET",
		Path:       thinkPHPEscapedPath,
		StatusCode: 200,
		Timestamp:  now,
		Window:     5 * time.Second,
	})

	// Sniffer delivers the captured response with the literal wire path.
	lc.handleCapturedResponse(CapturedResponse{
		Timestamp:     now,
		Method:        "GET",
		Path:          thinkPHPLiteralPath,
		StatusCode:    200,
		ContentType:   "text/html",
		ContentLength: 12,
		BodyPreview:   []byte("hello world!"),
	})

	if _, ok := lc.vipEvidence[eventID]; !ok {
		t.Fatal("VIP evidence was not promoted: escaped pin never matched the literal wire capture")
	}

	// Coordinator's evidence check uses the escaped log path too.
	ev := lc.Lookup(LookupRequest{
		Method:     "GET",
		Path:       thinkPHPEscapedPath,
		StatusCode: 200,
		Timestamp:  now,
		Window:     5 * time.Second,
	})
	if ev == nil || ev.Transport == nil {
		t.Fatalf("Lookup returned no transport evidence: %+v", ev)
	}
	if ev.Transport.StatusCode != 200 {
		t.Errorf("evidence transport status = %d, want 200", ev.Transport.StatusCode)
	}
}
