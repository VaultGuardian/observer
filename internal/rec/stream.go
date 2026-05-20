// internal/rec/stream.go
//
// v0.42.7: Response-only TCP reassembly.
//
// =============================================================================
// Why response-only
// =============================================================================
//
// Request metadata (method, path, host, user-agent) is parsed synchronously
// in processFrame's inline parser and registered in the flow state before the
// response packet is even read from the socket. No request goroutine needed.
//
// Response bodies are parsed via TCP reassembly because nginx splits headers
// and body across TCP segments for bare-IP / sendfile / tcp_nopush traffic.
// http.ReadResponse over the reassembled stream gets full headers + body
// regardless of segmentation. This is the v1.0 evidence capture fix.
//
// =============================================================================
// Goroutine safety
// =============================================================================
//
// Landmine 3 (goroutine leak): Each stream has a time.AfterFunc deadline
// that force-closes the ReaderStream after StreamTTL. Blocked
// http.ReadResponse returns EOF and the goroutine exits cleanly.
//
// Deadlock prevention: On parse error or after body capture, the stream
// MUST drain all remaining bytes via io.Copy(io.Discard, ...) before exiting.
// An abandoned reader wedges FlushOlderThan() inside tcpreader.Reassembled()
// while holding assemblerMu, freezing readLoop. (v0.42.3 postmortem.)
//
// Lock discipline: pairResponse() returns the paired request metadata.
// buffer.Insert() and onCapture() are called AFTER the flow lock is released.
// No lock held during callbacks.

package rec

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// safeReaderStream wraps tcpreader.ReaderStream to make ReassemblyComplete
// idempotent. gopacket's ReaderStream panics on double-close of its internal
// channel. Both the streamTTL AfterFunc and FlushOlderThan can trigger
// ReassemblyComplete on the same stream — whichever fires first wins,
// the other is a no-op. (v0.43 crash-loop fix.)
type safeReaderStream struct {
	reader *tcpreader.ReaderStream
	once   sync.Once
	closed atomic.Bool // set after ReassemblyComplete — Reassembled becomes no-op
}

func (s *safeReaderStream) Reassembled(rs []tcpassembly.Reassembly) {
	if s.closed.Load() {
		return // stream already closed, discard late packets
	}
	// Belt and suspenders: recover from the tiny race window where
	// closed.Load() returns false but ReassemblyComplete closes the
	// channel before reader.Reassembled sends. (v0.43.1 crash fix.)
	defer func() {
		if r := recover(); r != nil {
			s.closed.Store(true) // ensure future calls skip fast
		}
	}()
	s.reader.Reassembled(rs)
}

func (s *safeReaderStream) ReassemblyComplete() {
	s.once.Do(func() {
		s.closed.Store(true)
		s.reader.ReassemblyComplete()
	})
}

// =============================================================================
// httpStreamFactory — response streams only
// =============================================================================

type httpStreamFactory struct {
	sniffer   *sniffer
	maxBody   int
	streamTTL time.Duration
}

// discardStream silently drops all data. Used when MaxActiveStreams is hit.
// gopacket/tcpassembly requires a Stream to be returned from New() — we
// can't return nil. This eats the data without allocating goroutines.
type discardStream struct{}

func (discardStream) Reassembled([]tcpassembly.Reassembly) {}
func (discardStream) ReassemblyComplete()                  {}

// New is called by tcpassembly when it sees a new TCP flow. Since we only
// feed response-direction packets to the assembler, every stream here is
// a response stream — no direction detection needed.
//
// MaxActiveStreams enforcement: CAS loop on reassemblyStreamsActive. If
// the cap is hit, return a discardStream instead of spawning a goroutine.
// Under overload, this prevents goroutine explosion.
func (f *httpStreamFactory) New(netFlow, transFlow gopacket.Flow) tcpassembly.Stream {
	max := int64(f.sniffer.reassemblyConfig.MaxActiveStreams)
	if max > 0 {
		for {
			active := atomic.LoadInt64(&f.sniffer.reassemblyStreamsActive)
			if active >= max {
				atomic.AddInt64(&f.sniffer.reassemblyStreamDrops, 1)
				return discardStream{}
			}
			if atomic.CompareAndSwapInt64(&f.sniffer.reassemblyStreamsActive, active, active+1) {
				break
			}
		}
	} else {
		atomic.AddInt64(&f.sniffer.reassemblyStreamsActive, 1)
	}

	atomic.AddInt64(&f.sniffer.reassemblyStreamsTotal, 1)

	s := &httpStream{
		netFlow:   netFlow,
		transFlow: transFlow,
		sniffer:   f.sniffer,
		maxBody:   f.maxBody,
		streamTTL: f.streamTTL,
		createdAt: time.Now(),
		reader:    tcpreader.NewReaderStream(),
	}

	safe := &safeReaderStream{reader: &s.reader}
	s.safeReader = safe

	go s.run()

	return safe
}

// =============================================================================
// httpStream — one per response direction per TCP flow
// =============================================================================

type httpStream struct {
	netFlow, transFlow gopacket.Flow
	sniffer            *sniffer
	maxBody            int
	streamTTL          time.Duration
	createdAt          time.Time
	reader             tcpreader.ReaderStream
	safeReader         *safeReaderStream // returned to assembler, guards double-close

	parseCount int64
}

// flowKey returns the canonical flow key (client→server direction) for
// looking up the bidirectional flow state. Since this is a response stream
// (server→client), we reverse the key.
//
// CAREFUL: do not use transFlow.Src().String() for port extraction.
// gopacket's layers.TCPPort.String() returns "80(http)" for well-known
// ports. Endpoint.Raw() returns the actual 2-byte port. (v0.42.0 gotcha.)
func (s *httpStream) flowKey() streamKey {
	// This stream is server→client. Build the key as-is, then reverse
	// to get the canonical client→server key.
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
	return sk.reverse() // canonical = client→server
}

// run consumes the reassembled response byte stream. Lives in its own goroutine.
//
// =============================================================================
// v0.47.2 hotfix — symmetric read-side close-race recover
// =============================================================================
// gopacket's tcpreader.ReaderStream.Read sends on its internal `next` channel
// as part of its read protocol (signaling "ready for more data"). If
// ReassemblyComplete fires while Read is mid-iteration — either via the
// streamTTL deadline below OR via FlushOlderThan from the assembler — the
// `next` channel is closed and the next send panics:
//
//	panic: send on closed channel
//	gopacket/tcpassembly/tcpreader.(*ReaderStream).Read
//	  reader.go:178
//	bufio.(*Reader).fill
//	net/http.ReadResponse
//	internal/rec.(*httpStream).runResponse  stream.go:228
//	internal/rec.(*httpStream).run          stream.go:212
//
// safeReaderStream.Reassembled already has a `defer recover()` for the
// assembler-side version of this race (v0.43.1 fix). This is the symmetric
// READ-side version — same shape, opposite goroutine, same recovery pattern.
// The v0.43.1 fix only guarded one side; production showed twice in 12h
// that the read side needed it too.
// =============================================================================
func (s *httpStream) run() {
	defer atomic.AddInt64(&s.sniffer.reassemblyStreamsActive, -1)

	// Read-side close-race recover. Counter reuses reassemblyParseErrors;
	// distinguishable in logs by the "Read close-race panic" tag.
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&s.sniffer.reassemblyParseErrors, 1)
			log.Printf("[rec:reassembly] recovered from Read close-race panic: %v", r)
		}
	}()

	// Landmine 3: deadline-triggered EOF.
	// CRITICAL: ReassemblyComplete can also be called by FlushOlderThan
	// (via assembler.closeConnection). Both paths go through safeReaderStream
	// which uses sync.Once to prevent double-close panic.
	// (v0.43 crash-loop: 20 restarts in 5 minutes.)
	deadline := time.AfterFunc(s.streamTTL, func() {
		if atomic.LoadInt64(&s.parseCount) == 0 {
			atomic.AddInt64(&s.sniffer.reassemblyStreamsTimedOut, 1)
		}
		s.safeReader.ReassemblyComplete()
	})
	defer deadline.Stop()

	// All streams are response streams — go straight to parsing.
	bufReader := bufio.NewReader(&s.reader)
	s.runResponse(bufReader)
}

// =============================================================================
// runResponse — the only parsing path
// =============================================================================
//
// Parses responses from the reassembled server→client stream. For each
// response: captures body, calls sniffer.pairResponse to match with a
// waiting request (or queue as orphan), then inserts into the ring buffer
// and fires onCapture — all OUTSIDE any flow lock.

func (s *httpStream) runResponse(r *bufio.Reader) {
	fk := s.flowKey()

	for {
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				atomic.AddInt64(&s.sniffer.reassemblyParseErrors, 1)
				// Drain remaining stream so tcpassembly does not wedge.
				io.Copy(io.Discard, r)
			}
			return
		}

		// Capture up to maxBody bytes as evidence preview.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.maxBody)))

		// CRITICAL: drain the REMAINDER of the response body. (v0.42.3 fix.)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		bodyHash := HashBody(body)

		contentLength := resp.ContentLength
		if contentLength < 0 && len(body) > 0 {
			contentLength = int64(len(body))
		}

		captured := CapturedResponse{
			Timestamp:       time.Now(),
			StatusCode:      resp.StatusCode,
			ContentType:     resp.Header.Get("Content-Type"),
			ContentLength:   contentLength,
			BodyPreview:     body,
			BodyPreviewHash: bodyHash,
		}

		// Pair with waiting request via the flow state.
		// pairResponse returns nil if no request was waiting (response queued).
		pendingReq := s.sniffer.pairResponse(fk, captured)

		if pendingReq != nil {
			// Paired — stamp request metadata onto the response.
			captured.Method = pendingReq.method
			captured.Path = pendingReq.path
			captured.Host = pendingReq.host
			captured.UserAgent = pendingReq.userAgent

			// Insert into ring buffer and fire VIP callback OUTSIDE flow lock.
			s.sniffer.buffer.Insert(captured)
			if s.sniffer.onCapture != nil {
				s.sniffer.onCapture(captured)
			}
		}
		// If pendingReq == nil, the response was queued in flow.responses.
		// The cleanup loop will expire it as an orphan after 2s, insert it
		// into the buffer, and fire onCapture then. No action needed here.

		atomic.AddInt64(&s.sniffer.reassemblyResponses, 1)
		atomic.AddInt64(&s.parseCount, 1)

		if s.sniffer.verbose || pendingReq != nil {
			method := ""
			path := ""
			if pendingReq != nil {
				method = pendingReq.method
				path = pendingReq.path
			}
			log.Printf("[rec:reassembly] RESP status=%d ct=%q cl=%d bodyLen=%d hash=%.16s paired=%t method=%s path=%s",
				resp.StatusCode,
				resp.Header.Get("Content-Type"),
				resp.ContentLength,
				len(body),
				bodyHash,
				pendingReq != nil,
				method,
				path)
		}
	}
}
