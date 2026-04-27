// internal/rec/stream.go
//
// Phase 3: TCP reassembly streams for REC v2.
//
// This file implements the per-direction stream handlers used by gopacket's
// tcpassembly to reconstruct full HTTP messages from segmented TCP traffic.
// It runs in SHADOW MODE for v0.40 — observation only, no writes to the
// canonical evidence buffer. The single-segment parser in sniffer.go is
// still the source of truth for evidence correlation.
//
// =============================================================================
// Why this exists
// =============================================================================
//
// nginx splits response headers and body across separate TCP segments for
// bare-IP / sendfile / static traffic (confirmed in production via
// REC segmentation telemetry, v0.39.2). The single-segment parser sees the
// headers-only segment, parses HTTP 200 with Content-Length: 2401, then
// reads zero body bytes because the body is in the next packet.
//
// tcpassembly reconstructs the byte stream in order. http.ReadResponse
// reads from the reassembled stream and gets headers + full body naturally.
//
// =============================================================================
// the design review's Landmines (must remain handled)
// =============================================================================
//
// Landmine 3 — Goroutine leak (CRITICAL):
//   http.ReadResponse blocks on the reader. If a stream stalls (slowloris,
//   never-completing connection, traffic dropped before FIN) the goroutine
//   hangs forever waiting for bytes. Over hours, thousands of leaked
//   goroutines → OOM kill.
//
//   MITIGATION: time.AfterFunc fires at streamTTL. Calls ReassemblyComplete
//   on the ReaderStream, which causes the next Read() to return io.EOF.
//   The blocked http.ReadResponse returns an error, the goroutine exits
//   cleanly. The deadline timer is stopped if the stream completes
//   normally first.
//
// Landmine 1 (Checksum offload) is handled in sniffer.go — we manually
// construct the layers.TCP from raw bytes we already parsed, so gopacket
// never validates checksums.
//
// Landmine 2 (Mid-stream ghost) is mostly self-healing for HTTP. tcpassembly
// creates streams on first packet seen (with or without SYN). For HTTP
// keep-alive, even if we attach mid-body, the next request on that
// connection starts at a fresh status line and parses cleanly.

package rec

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// =============================================================================
// httpStreamFactory
// =============================================================================
//
// Creates one httpStream per (netFlow, transFlow) pair the assembler sees.
// Each TCP connection produces TWO streams — one for each direction.
// We auto-detect direction from src port: if src port is in our HTTP
// port set, this stream carries server→client responses. Otherwise it
// carries client→server requests.

type httpStreamFactory struct {
	sniffer   *sniffer
	maxBody   int
	streamTTL time.Duration
}

// New is called by tcpassembly when it sees a new TCP flow.
// We start a goroutine to drive http.ReadResponse / http.ReadRequest
// against the reassembled stream.
func (f *httpStreamFactory) New(netFlow, transFlow gopacket.Flow) tcpassembly.Stream {
	s := &httpStream{
		netFlow:   netFlow,
		transFlow: transFlow,
		sniffer:   f.sniffer,
		maxBody:   f.maxBody,
		streamTTL: f.streamTTL,
		createdAt: time.Now(),
		reader:    tcpreader.NewReaderStream(),
	}

	atomic.AddInt64(&f.sniffer.reassemblyStreamsActive, 1)
	atomic.AddInt64(&f.sniffer.reassemblyStreamsTotal, 1)

	go s.run()

	// Return a pointer to the embedded ReaderStream — that's what
	// satisfies the tcpassembly.Stream interface. The assembler will
	// call Reassembled() and ReassemblyComplete() on it.
	return &s.reader
}

// =============================================================================
// httpStream
// =============================================================================

type httpStream struct {
	netFlow, transFlow gopacket.Flow
	sniffer            *sniffer
	maxBody            int
	streamTTL          time.Duration
	createdAt          time.Time
	reader             tcpreader.ReaderStream
}

// run consumes the reassembled byte stream. Lives in its own goroutine.
// MUST exit cleanly even if the stream never completes (Landmine 3).
func (s *httpStream) run() {
	defer atomic.AddInt64(&s.sniffer.reassemblyStreamsActive, -1)

	// Landmine 3: deadline-triggered EOF.
	// If the stream is still alive at streamTTL, force ReassemblyComplete.
	// This makes the next Read() on our ReaderStream return io.EOF, which
	// unblocks the http.ReadResponse goroutine. AfterFunc only fires once;
	// stopping it on normal completion is safe and idempotent.
	deadline := time.AfterFunc(s.streamTTL, func() {
		atomic.AddInt64(&s.sniffer.reassemblyStreamsTimedOut, 1)
		s.reader.ReassemblyComplete()
	})
	defer deadline.Stop()

	// Determine direction from source port.
	//
	// CAREFUL: do not use transFlow.Src().String() here — gopacket's
	// layers.TCPPort.String() returns "80(http)" for well-known ports,
	// "8080(http-alt)" for port 8080, etc. Only ephemeral ports return
	// a plain decimal. Parsing that with strconv.Atoi silently fails and
	// classifies every response stream as a request, then http.ReadRequest
	// is called on response data and either errors or times out.
	//
	// Endpoint.Raw() returns the actual 2-byte port in network byte order.
	// That's the source of truth — no IANA names, no string parsing.
	srcPortBytes := s.transFlow.Src().Raw()
	if len(srcPortBytes) != 2 {
		// Defensive — should never happen for TCP endpoints
		atomic.AddInt64(&s.sniffer.reassemblyParseErrors, 1)
		return
	}
	srcPort := int(binary.BigEndian.Uint16(srcPortBytes))
	isResponse := s.sniffer.knownPorts[srcPort]

	bufReader := bufio.NewReader(&s.reader)

	if isResponse {
		s.runResponse(bufReader)
	} else {
		s.runRequest(bufReader)
	}
}

// runResponse loops parsing HTTP responses out of the reassembled stream.
// HTTP keep-alive connections deliver multiple responses on one TCP flow.
//
// SHADOW MODE: emits comparison logs only. Does NOT write to s.buffer.
// The single-segment parser in handleResponse() is still canonical for v0.40.
func (s *httpStream) runResponse(r *bufio.Reader) {
	for {
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			// EOF / unexpected EOF: stream ended (clean close, deadline,
			// or premature termination). Not a parse error.
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				atomic.AddInt64(&s.sniffer.reassemblyParseErrors, 1)
			}
			return
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.maxBody)))
		resp.Body.Close()

		bodyHash := HashBody(body)
		atomic.AddInt64(&s.sniffer.reassemblyResponses, 1)

		// Comparison log. The "match" between this and the single-segment
		// [rec:diag] line is by visual correlation: same flow, same status,
		// same approximate time. v0.40 shadow mode is observation-only;
		// automated correlation is a v0.40.1 concern.
		log.Printf("[rec:reassembly] RESP status=%d ct=%q cl=%d te=%v ce=%q bodyLen=%d hash=%.16s flow=%s→%s",
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			resp.ContentLength,
			resp.TransferEncoding,
			resp.Header.Get("Content-Encoding"),
			len(body),
			bodyHash,
			s.netFlow.Src().String(),
			s.netFlow.Dst().String())
	}
}

// runRequest loops parsing HTTP requests out of the reassembled stream.
// We don't currently emit comparison logs for requests — the single-segment
// parser already handles requests well (request lines + headers usually fit
// in one segment, the segmentation issue is response-specific). We just
// drain the bytes so the assembler can free them.
func (s *httpStream) runRequest(r *bufio.Reader) {
	for {
		req, err := http.ReadRequest(r)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				atomic.AddInt64(&s.sniffer.reassemblyParseErrors, 1)
			}
			return
		}
		// Drain body — bufio reader needs each request's body fully consumed
		// before the next one can be parsed.
		io.Copy(io.Discard, io.LimitReader(req.Body, int64(s.maxBody)))
		req.Body.Close()
		atomic.AddInt64(&s.sniffer.reassemblyRequests, 1)
	}
}