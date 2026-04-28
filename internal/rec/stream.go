// internal/rec/stream.go
//
// Phase 3 (v0.41 cutover): TCP reassembly is now the CANONICAL writer for
// the REC evidence buffer when REC_REASSEMBLY_ENABLED=true. Single-segment
// parser in sniffer.go becomes pure telemetry — it still fires segmentation
// diagnostics ([rec:diag] log lines + Phase 1 counters) but no longer
// inserts into the buffer or fires the VIP onCapture callback.
//
// =============================================================================
// Why this exists
// =============================================================================
//
// nginx splits response headers and body across separate TCP segments for
// bare-IP / sendfile / static traffic (confirmed in production via the
// v0.39.2 segmentation telemetry — body_missing counter ticking on real
// traffic). The single-segment parser sees the headers-only segment,
// parses HTTP 200 with Content-Length: 2401, then reads zero body bytes
// because the body is in the next packet.
//
// tcpassembly reconstructs the byte stream in order. http.ReadResponse
// reads from the reassembled stream and gets headers + full body
// naturally, regardless of how the upstream server segmented them.
//
// =============================================================================
// the design review's Landmines (must remain handled)
// =============================================================================
//
// Landmine 3 — Goroutine leak (CRITICAL):
//
//	http.ReadResponse blocks on the reader. If a stream stalls (slowloris,
//	never-completing connection, traffic dropped before FIN) the goroutine
//	hangs forever waiting for bytes. Over hours, thousands of leaked
//	goroutines → OOM kill.
//
//	MITIGATION: time.AfterFunc fires at streamTTL. Calls ReassemblyComplete
//	on the ReaderStream, which causes the next Read() to return io.EOF.
//	The blocked http.ReadResponse returns an error, the goroutine exits
//	cleanly. The deadline timer is stopped if the stream completes
//	normally first.
//
// Landmine 1 (Checksum offload) was overcautious — gopacket's default
// decode does NOT validate TCP checksums (see sniffer.go feedAssembler).
//
// Landmine 2 (Mid-stream ghost) is mostly self-healing for HTTP. tcpassembly
// creates streams on first packet seen. For HTTP keep-alive, even if we
// attach mid-body, the next request on the connection starts at a fresh
// status line and parses cleanly.
//
// =============================================================================
// Direction detection
// =============================================================================
//
// CAREFUL: do not use transFlow.Src().String() to extract the port number.
// gopacket's layers.TCPPort.String() returns "80(http)" for IANA well-known
// ports, "8080(http-alt)" for 8080, etc. Only ephemeral ports return a
// plain decimal. Parsing that with strconv.Atoi silently fails and
// classifies every response stream as a request — http.ReadRequest is
// then called on response data and either parse-errors or times out
// without ever returning.
//
// Endpoint.Raw() returns the actual 2-byte port in network byte order.
// That's the source of truth.

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

type httpStreamFactory struct {
	sniffer   *sniffer
	maxBody   int
	streamTTL time.Duration
}

// New is called by tcpassembly when it sees a new TCP flow.
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

	// Return pointer to the embedded ReaderStream — satisfies tcpassembly.Stream.
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

	// parseCount tracks how many requests OR responses parsed successfully on
	// this stream. The AfterFunc deadline only counts toward streams_timeout
	// if parseCount == 0 — a stream that parsed at least once and then idled
	// out waiting for more on a keep-alive connection is success, not timeout.
	parseCount int64
}

// streamKey constructs a sniffer.streamKey from the gopacket Flow data.
// Used by runRequest/runResponse to interoperate with the sniffer's pending
// request map (which is keyed by the same struct that single-segment uses).
func (s *httpStream) streamKey() streamKey {
	var sk streamKey
	srcIP := s.netFlow.Src().Raw()
	dstIP := s.netFlow.Dst().Raw()
	srcPort := s.transFlow.Src().Raw()
	dstPort := s.transFlow.Dst().Raw()
	if len(srcIP) == 4 {
		copy(sk.srcIP[:], srcIP)
	}
	if len(dstIP) == 4 {
		copy(sk.dstIP[:], dstIP)
	}
	if len(srcPort) == 2 {
		sk.srcPort = binary.BigEndian.Uint16(srcPort)
	}
	if len(dstPort) == 2 {
		sk.dstPort = binary.BigEndian.Uint16(dstPort)
	}
	return sk
}

// run consumes the reassembled byte stream. Lives in its own goroutine.
// MUST exit cleanly even if the stream never completes (Landmine 3).
func (s *httpStream) run() {
	defer atomic.AddInt64(&s.sniffer.reassemblyStreamsActive, -1)

	// Landmine 3: deadline-triggered EOF.
	deadline := time.AfterFunc(s.streamTTL, func() {
		// Only count as "timeout" if no successful parses happened on this
		// stream. A keep-alive connection that parsed one request/response
		// and then idled is not a failure.
		if atomic.LoadInt64(&s.parseCount) == 0 {
			atomic.AddInt64(&s.sniffer.reassemblyStreamsTimedOut, 1)
		}
		s.reader.ReassemblyComplete()
	})
	defer deadline.Stop()

	// Direction detection — see file header for the gopacket gotcha.
	srcPortBytes := s.transFlow.Src().Raw()
	if len(srcPortBytes) != 2 {
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

// =============================================================================
// runRequest — canonical request side
// =============================================================================
//
// Parses requests out of the reassembled client→server stream and appends
// to s.sniffer.pending so runResponse on the reverse direction can pair
// against them.

func (s *httpStream) runRequest(r *bufio.Reader) {
	key := s.streamKey()

	for {
		req, err := http.ReadRequest(r)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				atomic.AddInt64(&s.sniffer.reassemblyParseErrors, 1)
				// Drain the rest of this stream until tcpassembly signals EOF,
				// otherwise FlushOlderThan() will block trying to deliver more
				// bytes into our abandoned reader, holding assemblerMu and
				// freezing readLoop. See v0.42.3 deadlock postmortem.
				io.Copy(io.Discard, r)
			}
			return
		}

		// CRITICAL: register pending request BEFORE draining body.
		// The response-side goroutine runs concurrently and may already
		// be parsing the matching response. If we drain the body first,
		// the response goroutine wins the race ~50% of the time, looks
		// up pending[reverseKey], finds nothing, and increments pairMiss.
		// (v0.42.4 pair-rate regression: 99.6% → 52.7%.)
		s.sniffer.mu.Lock()
		s.sniffer.pending[key] = append(s.sniffer.pending[key], &pendingRequest{
			method:    req.Method,
			path:      req.RequestURI,
			host:      req.Host,
			userAgent: req.UserAgent(),
			timestamp: time.Now(),
		})
		s.sniffer.mu.Unlock()

		atomic.AddInt64(&s.sniffer.reassemblyRequests, 1)
		atomic.AddInt64(&s.parseCount, 1)

		// Drain the request body FULLY (not capped at maxBody). The bufio
		// reader is shared across all requests on this keep-alive stream;
		// leftover body bytes from request N corrupt parsing of request N+1,
		// which causes a parse error, which causes us to drain the whole
		// rest of the stream and exit — losing all subsequent requests.
		// We don't keep request bodies as evidence, so just discard.
		// Safe to do AFTER pending insert — body bytes don't affect the
		// pending entry, and the next http.ReadRequest won't start until
		// this drain completes.
		io.Copy(io.Discard, req.Body)
		req.Body.Close()
	}
}

// =============================================================================
// runResponse — canonical response side
// =============================================================================
//
// Parses responses out of the reassembled server→client stream, pops the
// matching pending request, builds a CapturedResponse, and inserts it
// into the REC evidence buffer. Also fires onCapture for the VIP lane.
//
// This is the cutover from v0.40's shadow mode — the buffer.Insert and
// onCapture call here are what makes the coordinator's evidence check
// see real bodies on bare-IP / segmented traffic. Without these calls,
// reassembly is just a science experiment.

func (s *httpStream) runResponse(r *bufio.Reader) {
	key := s.streamKey()
	reverseKey := key.reverse()

	for {
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				atomic.AddInt64(&s.sniffer.reassemblyParseErrors, 1)
				// Drain the rest of this stream until tcpassembly signals EOF.
				// Same reason as runRequest: an abandoned reader wedges
				// FlushOlderThan() and freezes the entire pipeline.
				io.Copy(io.Discard, r)
			}
			return
		}

		// Capture up to maxBody bytes as evidence preview.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.maxBody)))

		// CRITICAL: drain the REMAINDER of the response body. maxBody is just
		// the evidence cap (e.g. 2048 bytes); the actual body might be longer
		// (e.g. 2401 bytes for the CapRover landing page). The leftover bytes
		// sit in our bufio reader and corrupt parsing of the next response on
		// keep-alive connections — http.ReadResponse tries to parse mid-body
		// HTML as a status line, errors out, and we exit losing everything.
		// Worse: those abandoned bytes wedge FlushOlderThan() inside
		// tcpreader.Reassembled(), which holds assemblerMu, which freezes
		// readLoop. (v0.42.3 postmortem.)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		bodyHash := HashBody(body)

		contentLength := resp.ContentLength
		if contentLength < 0 && len(body) > 0 {
			contentLength = int64(len(body))
		}

		// Pop the matching pending request from the request-direction stream.
		s.sniffer.mu.Lock()
		var pending *pendingRequest
		queue := s.sniffer.pending[reverseKey]
		if len(queue) > 0 {
			pending = queue[0]
			s.sniffer.pending[reverseKey] = queue[1:]
			if len(s.sniffer.pending[reverseKey]) == 0 {
				delete(s.sniffer.pending, reverseKey)
			}
		}
		s.sniffer.mu.Unlock()

		captured := CapturedResponse{
			Timestamp:       time.Now(),
			StatusCode:      resp.StatusCode,
			ContentType:     resp.Header.Get("Content-Type"),
			ContentLength:   contentLength,
			BodyPreview:     body,
			BodyPreviewHash: bodyHash,
		}
		if pending != nil {
			captured.Method = pending.method
			captured.Path = pending.path
			captured.Host = pending.host
			captured.UserAgent = pending.userAgent
		} else {
			// No pending found. Could be: response arrived before request was
			// parsed (race), or request stream wasn't observed (mid-connection
			// startup). Insert anyway so segmentation-broken traffic still
			// produces evidence; coordinator's L7 heuristic correlation
			// (method/path matching) will weed out unmatched fragments.
			atomic.AddInt64(&s.sniffer.pairMissCount, 1)
		}

		// Canonical writes — this is the cutover.
		s.sniffer.buffer.Insert(captured)
		if s.sniffer.onCapture != nil {
			s.sniffer.onCapture(captured)
		}

		atomic.AddInt64(&s.sniffer.reassemblyResponses, 1)
		atomic.AddInt64(&s.parseCount, 1)

		log.Printf("[rec:reassembly] RESP status=%d ct=%q cl=%d te=%v ce=%q bodyLen=%d hash=%.16s flow=%s→%s method=%s path=%s",
			resp.StatusCode,
			resp.Header.Get("Content-Type"),
			resp.ContentLength,
			resp.TransferEncoding,
			resp.Header.Get("Content-Encoding"),
			len(body),
			bodyHash,
			s.netFlow.Src().String(),
			s.netFlow.Dst().String(),
			captured.Method,
			captured.Path)
	}
}