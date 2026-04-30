// internal/rec/sniffer.go
//
// v0.42.7: Deterministic request-response pairing.
//
// =============================================================================
// Architecture (design consensus)
// =============================================================================
//
// The fundamental problem with v0.42.0–v0.42.6 was that TCP reassembly created
// separate goroutines for request and response directions. The Go scheduler
// determined which goroutine ran first — a coin flip when the kernel buffered
// both packets. Pair rate dropped from 99.6% to ~50%.
//
// The fix separates responsibilities:
//
//   Request metadata: parsed SYNCHRONOUSLY in processFrame from the first
//   packet's payload. No assembler, no goroutine. Registered in the flow
//   state before the response packet is even read from the socket.
//
//   Response body: parsed via TCP reassembly (gopacket/tcpassembly) in a
//   goroutine. This is the thing reassembly was needed for — nginx splits
//   response headers/body across segments for bare-IP / sendfile traffic.
//
//   Pairing: event-driven. Response side checks for a waiting request and
//   pairs immediately. If no request exists (split headers, mid-stream
//   capture), the response queues and expires after 2s as an orphan. Request
//   side ONLY appends — it never consumes queued responses, because doing so
//   on a keep-alive connection could pair Request B with Response A if
//   Request A's headers were split (code review's catch).
//
// =============================================================================
// Inline parser safety (code review + the design review guardrails)
// =============================================================================
//
// - Payload must START with a known HTTP method token (GET, POST, etc.).
//   Never scan for "HTTP/" arbitrarily — a POST body could contain it.
//
// - TCP sequence dedupe: a ring buffer of the last 32 sequence numbers
//   per flow prevents retransmits and duplicate captures from creating
//   duplicate pending requests that poison the FIFO.
//
// - Content-Length tracking: after parsing a request with Content-Length > 0,
//   subsequent segments are skipped until the body bytes are consumed. Prevents
//   a crafted POST body starting with "GET /fake HTTP/1.1" from creating a
//   ghost pending request.
//
// - Safe byte scanning: never slice payload[:N] without bounds checking.
//   An index-out-of-bounds panic in processFrame kills readLoop permanently.
//
// - Queue bounds: max flow states, max requests per flow, max responses per
//   flow. Attacker-influenced queues must be bounded.

package rec

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// =============================================================================
// Flow Pairing State
// =============================================================================

// streamKey identifies a TCP flow direction. The canonical key for a flow
// is always client→server (ephemeral port as src, HTTP port as dst).
type streamKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

func (sk streamKey) reverse() streamKey {
	return streamKey{
		srcIP: sk.dstIP, srcPort: sk.dstPort,
		dstIP: sk.srcIP, dstPort: sk.srcPort,
	}
}

type pendingRequest struct {
	method    string
	path      string // raw path including query string — SACRED
	host      string
	userAgent string
	timestamp time.Time
}

// pendingResponse holds a fully-built CapturedResponse that arrived before
// its matching request (split headers, mid-stream capture, scheduler edge).
// Expires after ResponseOrphanTimeout and gets inserted as an orphan.
type pendingResponse struct {
	captured  CapturedResponse
	timestamp time.Time
}

// seqRingSize is the number of TCP sequence numbers tracked per flow for
// retransmit/duplicate detection. 32 is enough — a flow rarely has more
// than a handful of requests in-flight simultaneously.
const seqRingSize = 32

// flowPair holds bidirectional pairing state for a single TCP flow.
// Request side appends. Response side consumes requests or queues.
// Cleanup loop expires stale entries.
type flowPair struct {
	requests  []*pendingRequest
	responses []*pendingResponse

	// TCP sequence dedupe ring — prevents retransmit/duplicate packets
	// from creating duplicate pending requests that poison FIFO pairing.
	seenSeqs [seqRingSize]uint32
	seenSeqN int // entries filled (up to seqRingSize)
	seenSeqW int // next write position (wraps)

	// Body tracking — when inline parser finds Content-Length > 0, we
	// track remaining body bytes to skip segments that are request body
	// data. Prevents a crafted POST body starting with "GET /fake" from
	// creating a ghost pending request.
	bodyRemaining int64

	// Chunked/unknown body guard — when the inline parser finds a
	// body-capable request with Transfer-Encoding: chunked or unknown
	// body length, we cannot predict when the body ends from the request
	// side alone. Set this flag to skip all subsequent client payloads
	// until the response side pairs and clears it. Conservative: may
	// miss a rare pipelined request after a chunked body, but missing
	// is safer than false evidence. (code review catch.)
	skipUntilPaired bool

	mu sync.Mutex
}

// hasSeenSeq checks if a TCP sequence number was recently seen on this flow.
func (fp *flowPair) hasSeenSeq(seq uint32) bool {
	n := fp.seenSeqN
	for i := 0; i < n; i++ {
		if fp.seenSeqs[i] == seq {
			return true
		}
	}
	return false
}

// recordSeq adds a TCP sequence number to the dedupe ring.
func (fp *flowPair) recordSeq(seq uint32) {
	fp.seenSeqs[fp.seenSeqW] = seq
	fp.seenSeqW = (fp.seenSeqW + 1) % seqRingSize
	if fp.seenSeqN < seqRingSize {
		fp.seenSeqN++
	}
}

// =============================================================================
// Inline Request Parser
// =============================================================================

// inlineParseResult holds the output of the synchronous request header parser.
type inlineParseResult struct {
	method        string
	path          string
	host          string
	userAgent     string
	contentLength int64 // -1 = absent/unknown, -2 = chunked, >=0 = known
	headerLen     int   // byte offset where headers end (\r\n\r\n)
}

// maxInlineScan caps how many bytes the inline parser inspects. We only
// need the request line + Host/User-Agent/Content-Length headers. Anything
// beyond this is body data or irrelevant headers.
const maxInlineScan = 8192

// httpMethodPrefixes is the exhaustive set of HTTP/1.x method tokens.
// The inline parser requires the payload to START with one of these.
// Parse all methods — let the classifier decide what matters (the design review).
var httpMethodPrefixes = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("PATCH "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
}

// inlineParseRequest extracts HTTP request metadata from a raw TCP payload.
// Returns nil if the payload is not a valid HTTP request start.
//
// This is NOT a full HTTP parser. It extracts four fields from the first
// segment: method, path, Host header, User-Agent header. It also reads
// Content-Length for body tracking. It stops at the first \r\n\r\n or
// the maxInlineScan cap, whichever comes first.
//
// the design review guardrail: all byte access is bounds-checked. A panic here
// kills readLoop permanently and Observer goes blind.
func inlineParseRequest(payload []byte) *inlineParseResult {
	if len(payload) < 14 { // minimum: "GET / HTTP/1.0\n"
		return nil
	}

	// Require payload to start with a known HTTP method token.
	methodFound := false
	for _, prefix := range httpMethodPrefixes {
		if bytes.HasPrefix(payload, prefix) {
			methodFound = true
			break
		}
	}
	if !methodFound {
		return nil
	}

	// Cap scan length — never read beyond payload bounds.
	scanLen := len(payload)
	if scanLen > maxInlineScan {
		scanLen = maxInlineScan
	}
	data := payload[:scanLen]

	// Find end of request line.
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 {
		return nil // incomplete request line in this segment
	}
	requestLine := data[:lineEnd]
	if len(requestLine) > 0 && requestLine[len(requestLine)-1] == '\r' {
		requestLine = requestLine[:len(requestLine)-1]
	}

	// Parse "METHOD PATH HTTP/1.x"
	sp1 := bytes.IndexByte(requestLine, ' ')
	if sp1 < 0 {
		return nil
	}
	rest := requestLine[sp1+1:]
	sp2 := bytes.LastIndexByte(rest, ' ')
	if sp2 < 0 {
		return nil
	}
	version := rest[sp2+1:]
	if !bytes.HasPrefix(version, []byte("HTTP/")) {
		return nil
	}

	result := &inlineParseResult{
		method:        string(requestLine[:sp1]),
		path:          string(rest[:sp2]),
		contentLength: -1, // unknown until we see the header
	}

	// Scan headers for Host, User-Agent, Content-Length, Transfer-Encoding.
	pos := lineEnd + 1
	for pos < scanLen {
		nlIdx := bytes.IndexByte(data[pos:], '\n')
		if nlIdx < 0 {
			break // no more complete header lines in this segment
		}
		line := data[pos : pos+nlIdx]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		pos += nlIdx + 1

		// Empty line = end of headers.
		if len(line) == 0 {
			result.headerLen = pos
			return result
		}

		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 0 {
			continue
		}
		name := line[:colonIdx]
		value := bytes.TrimSpace(line[colonIdx+1:])

		// Case-insensitive header matching without allocating lowercase copy.
		if len(name) == 4 && (name[0] == 'H' || name[0] == 'h') &&
			(name[1] == 'O' || name[1] == 'o') &&
			(name[2] == 'S' || name[2] == 's') &&
			(name[3] == 'T' || name[3] == 't') {
			result.host = string(value)
		} else if len(name) == 10 && (name[0] == 'U' || name[0] == 'u') &&
			bytes.EqualFold(name, []byte("User-Agent")) {
			result.userAgent = string(value)
		} else if len(name) == 14 && (name[0] == 'C' || name[0] == 'c') &&
			bytes.EqualFold(name, []byte("Content-Length")) {
			if cl, err := strconv.ParseInt(string(value), 10, 64); err == nil {
				result.contentLength = cl
			}
		} else if len(name) == 17 && (name[0] == 'T' || name[0] == 't') &&
			bytes.EqualFold(name, []byte("Transfer-Encoding")) {
			if bytes.Contains(bytes.ToLower(value), []byte("chunked")) {
				result.contentLength = -2 // chunked marker
			}
		}
	}

	// Headers didn't terminate with \r\n\r\n within our scan window.
	// We still have method/path — return what we have. headerLen stays 0
	// which means body tracking won't activate (safe: we'd rather miss
	// body tracking than skip legitimate requests).
	return result
}

// =============================================================================
// Sniffer
// =============================================================================

type sniffer struct {
	buffer    *RingBuffer
	iface     string
	maxBody   int
	vxlanPort uint16

	// HTTP ports — request direction: dstPort in set. Response direction:
	// srcPort in set.
	knownPorts map[int]bool

	// Bidirectional flow pairing state. Keyed by client→server direction.
	// Request side uses the key as-is. Response side reverses its key.
	flows   map[streamKey]*flowPair
	flowsMu sync.Mutex

	// onCapture fires after each successfully paired/orphaned response so
	// the collector can check VIP pins for push-mode resolution.
	onCapture func(CapturedResponse)

	// Response-only reassembly machinery.
	reassemblyConfig ReassemblyConfig
	flowConfig       FlowConfig
	assembler        *tcpassembly.Assembler
	assemblerMu      sync.Mutex

	// --- Counters (all via atomic) ---
	packetCount int64
	vxlanCount  int64

	// Inline parser
	inlineRequests       int64
	inlineDuplicateDrops int64
	inlineBodySkips      int64
	inlineRejects        int64

	// Pairing
	pairImmediate   int64
	orphanResponses int64
	requestsExpired int64

	// Response reassembly
	reassemblyStreamsActive   int64
	reassemblyStreamsTotal    int64
	reassemblyStreamsTimedOut int64
	reassemblyStreamDrops     int64 // MaxActiveStreams cap hit
	reassemblyResponses       int64
	reassemblyParseErrors     int64

	feedHTTP      int64
	flowEvictions int64 // flow cap hit, blunt eviction

	verbose bool
}

func newSniffer(buffer *RingBuffer, iface string, ports []int, maxBody int, vxlanPort uint16, verbose bool, reasm ReassemblyConfig, flowCfg FlowConfig) *sniffer {
	knownPorts := make(map[int]bool, len(ports))
	for _, p := range ports {
		knownPorts[p] = true
	}
	if vxlanPort == 0 {
		vxlanPort = DefaultVXLANPort
	}
	s := &sniffer{
		buffer:           buffer,
		iface:            iface,
		knownPorts:       knownPorts,
		flows:            make(map[streamKey]*flowPair),
		maxBody:          maxBody,
		vxlanPort:        vxlanPort,
		verbose:          verbose,
		reassemblyConfig: reasm,
		flowConfig:       flowCfg,
	}

	factory := &httpStreamFactory{
		sniffer:   s,
		maxBody:   reasm.MaxBody,
		streamTTL: reasm.StreamTTL,
	}
	pool := tcpassembly.NewStreamPool(factory)
	s.assembler = tcpassembly.NewAssembler(pool)
	s.assembler.MaxBufferedPagesTotal = reasm.MaxBufferedPagesTotal
	s.assembler.MaxBufferedPagesPerConnection = reasm.MaxBufferedPagesPerConn
	log.Printf("[rec:reassembly] response-only — maxBody=%d streamTTL=%s idleTimeout=%s pages_total=%d pages_per_conn=%d max_streams=%d",
		reasm.MaxBody, reasm.StreamTTL, reasm.IdleTimeout,
		reasm.MaxBufferedPagesTotal, reasm.MaxBufferedPagesPerConn, reasm.MaxActiveStreams)
	log.Printf("[rec:flows] maxFlows=%d maxReqPerFlow=%d maxRespPerFlow=%d respOrphanTimeout=%s reqExpireTimeout=%s",
		flowCfg.MaxFlowStates, flowCfg.MaxRequestsPerFlow, flowCfg.MaxResponsesPerFlow,
		flowCfg.ResponseOrphanTimeout, flowCfg.RequestExpireTimeout)

	return s
}

// openSocket opens the AF_PACKET raw socket and binds to the interface.
func (s *sniffer) openSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return -1, fmt.Errorf("opening raw socket: %w (do you have CAP_NET_RAW?)", err)
	}

	if s.iface != "" {
		if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, s.iface); err != nil {
			syscall.Close(fd)
			return -1, fmt.Errorf("binding to interface %s: %w", s.iface, err)
		}
		log.Printf("[rec] Sniffer bound to interface %s", s.iface)
	} else {
		log.Printf("[rec] Sniffer capturing on all interfaces (no REC_INTERFACE set)")
	}

	tv := syscall.Timeval{Sec: 1, Usec: 0}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return -1, fmt.Errorf("setting socket timeout: %w", err)
	}

	return fd, nil
}

// readLoop processes packets until ctx is cancelled.
func (s *sniffer) readLoop(ctx context.Context, fd int) {
	defer syscall.Close(fd)

	buf := make([]byte, 65536)
	debugLogged := false

	for {
		select {
		case <-ctx.Done():
			log.Printf("[rec] Sniffer stopping (packets=%d vxlan=%d inline_req=%d pair_immediate=%d orphan_resp=%d)",
				atomic.LoadInt64(&s.packetCount),
				atomic.LoadInt64(&s.vxlanCount),
				atomic.LoadInt64(&s.inlineRequests),
				atomic.LoadInt64(&s.pairImmediate),
				atomic.LoadInt64(&s.orphanResponses))
			return
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			log.Printf("[rec] Socket read error: %v", err)
			continue
		}

		if n < 14 {
			continue
		}

		atomic.AddInt64(&s.packetCount, 1)
		s.processFrame(buf[:n], 0)

		if !debugLogged && atomic.LoadInt64(&s.packetCount) >= 10 {
			log.Printf("[rec] Sniffer active: %d packets, %d VXLAN unwrapped",
				atomic.LoadInt64(&s.packetCount), atomic.LoadInt64(&s.vxlanCount))
			debugLogged = true
		}
	}
}

// =============================================================================
// processFrame — the packet dispatch hub
// =============================================================================
//
// Request-direction packets (dstPort is HTTP): inline-parsed for metadata,
// registered in flow state synchronously. NOT fed to the assembler.
//
// Response-direction packets (srcPort is HTTP): fed to tcpassembly for
// full body reassembly. Goroutine parses response, pairs with waiting
// request, or queues as orphan candidate.

func (s *sniffer) processFrame(frame []byte, depth int) {
	if depth > maxDecapDepth {
		return
	}

	// Try VXLAN decapsulation first — Swarm overlay traffic is wrapped.
	if result, err := decapVXLAN(frame, s.vxlanPort); err == nil {
		atomic.AddInt64(&s.vxlanCount, 1)
		s.processFrame(result.InnerFrame, depth+1)
		return
	}

	// Ethernet → IPv4 → TCP
	if len(frame) < 14 {
		return
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != 0x0800 {
		return
	}
	ipData := frame[14:]

	if len(ipData) < 20 {
		return
	}
	if ipData[0]>>4 != 4 {
		return
	}
	ihl := int(ipData[0]&0x0f) * 4
	if len(ipData) < ihl {
		return
	}
	if ipData[9] != 6 { // TCP only
		return
	}

	var srcIP, dstIP [4]byte
	copy(srcIP[:], ipData[12:16])
	copy(dstIP[:], ipData[16:20])
	tcpData := ipData[ihl:]

	if len(tcpData) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(tcpData[0:2])
	dstPort := binary.BigEndian.Uint16(tcpData[2:4])
	tcpSeq := binary.BigEndian.Uint32(tcpData[4:8])
	dataOffset := int(tcpData[12]>>4) * 4
	if len(tcpData) < dataOffset {
		return
	}
	payload := tcpData[dataOffset:]

	if len(payload) == 0 {
		return
	}

	isRequest := s.knownPorts[int(dstPort)]
	isResponse := s.knownPorts[int(srcPort)]

	if isRequest {
		// Request direction: inline parse, synchronous registration.
		// Canonical flow key is client→server (this direction as-is).
		flowKey := streamKey{
			srcIP: srcIP, srcPort: srcPort,
			dstIP: dstIP, dstPort: dstPort,
		}
		s.handleInlineRequest(flowKey, tcpSeq, payload)
	}

	if isResponse {
		// Response direction: feed to tcpassembly for body reassembly.
		atomic.AddInt64(&s.feedHTTP, 1)
		s.feedAssembler(srcIP, dstIP, srcPort, dstPort, tcpData)
	}
}

// =============================================================================
// handleInlineRequest — synchronous request metadata capture
// =============================================================================

func (s *sniffer) handleInlineRequest(flowKey streamKey, tcpSeq uint32, payload []byte) {
	s.flowsMu.Lock()
	fp := s.flows[flowKey]
	if fp == nil {
		// Enforce max flow states (the design review: delete from map, not just clear slices).
		if len(s.flows) >= s.flowConfig.MaxFlowStates {
			s.evictOneFlow()
		}
		fp = &flowPair{}
		s.flows[flowKey] = fp
	}
	s.flowsMu.Unlock()

	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Chunked/unknown body guard: skip all client payloads until the
	// response side pairs the outstanding request and clears this flag.
	if fp.skipUntilPaired {
		atomic.AddInt64(&s.inlineBodySkips, 1)
		return
	}

	// Body tracking: skip segments that are request body data.
	if fp.bodyRemaining > 0 {
		consumed := int64(len(payload))
		if consumed > fp.bodyRemaining {
			consumed = fp.bodyRemaining
		}
		fp.bodyRemaining -= consumed
		atomic.AddInt64(&s.inlineBodySkips, 1)
		return
	}

	// TCP sequence dedupe: reject retransmits and duplicate captures.
	if fp.hasSeenSeq(tcpSeq) {
		atomic.AddInt64(&s.inlineDuplicateDrops, 1)
		return
	}
	fp.recordSeq(tcpSeq)

	// Inline parse.
	parsed := inlineParseRequest(payload)
	if parsed == nil {
		atomic.AddInt64(&s.inlineRejects, 1)
		return
	}

	// Enforce max requests per flow.
	if len(fp.requests) >= s.flowConfig.MaxRequestsPerFlow {
		// Drop oldest — it was probably never going to get a response.
		fp.requests = fp.requests[1:]
		atomic.AddInt64(&s.requestsExpired, 1)
	}

	fp.requests = append(fp.requests, &pendingRequest{
		method:    parsed.method,
		path:      parsed.path,
		host:      parsed.host,
		userAgent: parsed.userAgent,
		timestamp: time.Now(),
	})

	// Body tracking: if request has Content-Length > 0, compute how many
	// body bytes remain after this segment.
	if parsed.contentLength > 0 && parsed.headerLen > 0 {
		bodyInSegment := int64(len(payload)) - int64(parsed.headerLen)
		if bodyInSegment < 0 {
			bodyInSegment = 0
		}
		fp.bodyRemaining = parsed.contentLength - bodyInSegment
		if fp.bodyRemaining < 0 {
			fp.bodyRemaining = 0
		}
	} else if parsed.contentLength == -2 {
		// Chunked transfer encoding — we cannot predict body end from
		// the request side without parsing chunk framing. Set the guard
		// flag and let the response side clear it when it pairs.
		fp.skipUntilPaired = true
	}

	atomic.AddInt64(&s.inlineRequests, 1)
}

// evictOneFlow removes one flow from the map. O(1) — picks the first key
// Go's map iterator returns (effectively random). Under overload, we need
// speed more than precision. An O(N) oldest-flow scan would freeze readLoop
// when we're already at capacity. (code review catch.)
// MUST be called with s.flowsMu held.
func (s *sniffer) evictOneFlow() {
	for key := range s.flows {
		delete(s.flows, key)
		atomic.AddInt64(&s.flowEvictions, 1)
		return
	}
}

// getOrCreateFlow returns the flowPair for a key, creating it if needed.
// Caller must hold s.flowsMu.
func (s *sniffer) getOrCreateFlow(key streamKey) *flowPair {
	fp := s.flows[key]
	if fp == nil {
		if len(s.flows) >= s.flowConfig.MaxFlowStates {
			s.evictOneFlow()
		}
		fp = &flowPair{}
		s.flows[key] = fp
	}
	return fp
}

// pairResponse is called by the response goroutine (stream.go) after parsing
// a response. It tries to pair with a waiting request. If no request exists,
// it queues the response for later orphan expiry.
//
// Returns the paired pendingRequest (nil if queued as orphan candidate).
// Does NOT hold the flow lock during buffer.Insert or onCapture — builds
// the action, unlocks, then the caller executes (the design review: avoid lock chains).
func (s *sniffer) pairResponse(flowKey streamKey, captured CapturedResponse) *pendingRequest {
	s.flowsMu.Lock()
	fp := s.getOrCreateFlow(flowKey)
	s.flowsMu.Unlock()

	fp.mu.Lock()
	defer fp.mu.Unlock()

	// Response side: check if a request is waiting.
	if len(fp.requests) > 0 {
		req := fp.requests[0]
		fp.requests = fp.requests[1:]
		// Clear chunked body guard — the response arrived, so the
		// request body (chunked or otherwise) has been fully sent.
		// Next client payload is a new request.
		fp.skipUntilPaired = false
		fp.bodyRemaining = 0
		atomic.AddInt64(&s.pairImmediate, 1)
		return req
	}

	// No request waiting — log diagnostics before queuing as orphan.
	if s.verbose {
		log.Printf("[rec] PAIR MISS: status=%d body_bytes=%d src=%d.%d.%d.%d:%d dst=%d.%d.%d.%d:%d",
			captured.StatusCode, len(captured.BodyPreview),
			flowKey.dstIP[0], flowKey.dstIP[1], flowKey.dstIP[2], flowKey.dstIP[3], flowKey.dstPort,
			flowKey.srcIP[0], flowKey.srcIP[1], flowKey.srcIP[2], flowKey.srcIP[3], flowKey.srcPort)
		for i, req := range fp.requests {
			log.Printf("[rec] PAIR MISS:   pending[%d] %s %s (age=%.1fs)",
				i, req.method, req.path, time.Since(req.timestamp).Seconds())
		}
		log.Printf("[rec] PAIR MISS:   stats: inline_req=%d pair_immediate=%d total_misses=%d expired=%d",
			atomic.LoadInt64(&s.inlineRequests),
			atomic.LoadInt64(&s.pairImmediate),
			atomic.LoadInt64(&s.orphanResponses),
			atomic.LoadInt64(&s.requestsExpired))

		// Scan for requests to the same server on different ephemeral ports.
		// If we find any, it's a NAT/port rewrite problem — the request
		// exists but under a different flow key.
		serverIP := flowKey.dstIP
		serverPort := flowKey.dstPort
		s.flowsMu.Lock()
		for otherKey, otherFP := range s.flows {
			if otherKey == flowKey {
				continue
			}
			if otherFP == nil {
				continue
			}
			if otherKey.dstIP == serverIP && otherKey.dstPort == serverPort {
				otherFP.mu.Lock()
				if len(otherFP.requests) > 0 {
					log.Printf("[rec] PAIR MISS:   !! FOUND on different ephemeral: %d.%d.%d.%d:%d has %d pending req",
						otherKey.srcIP[0], otherKey.srcIP[1], otherKey.srcIP[2], otherKey.srcIP[3], otherKey.srcPort,
						len(otherFP.requests))
				}
				otherFP.mu.Unlock()
			}
		}
		s.flowsMu.Unlock()
	}

	// Queue the response as an orphan candidate.
	// It will expire after ResponseOrphanTimeout and be inserted as orphan.
	if len(fp.responses) >= s.flowConfig.MaxResponsesPerFlow {
		fp.responses = fp.responses[1:] // drop oldest
		atomic.AddInt64(&s.orphanResponses, 1)
	}
	fp.responses = append(fp.responses, &pendingResponse{
		captured:  captured,
		timestamp: time.Now(),
	})
	return nil
}

// =============================================================================
// feedAssembler — response direction only
// =============================================================================
//
// Only called for packets where srcPort is a known HTTP port. Feeds to
// gopacket's tcpassembly for full response body reconstruction.

func (s *sniffer) feedAssembler(srcIP, dstIP [4]byte, srcPort, dstPort uint16, tcpData []byte) {
	packet := gopacket.NewPacket(tcpData, layers.LayerTypeTCP, gopacket.NoCopy)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	netFlow := gopacket.NewFlow(layers.EndpointIPv4, srcIP[:], dstIP[:])

	s.assemblerMu.Lock()
	s.assembler.AssembleWithTimestamp(netFlow, tcp, time.Now())
	s.assemblerMu.Unlock()
}

// =============================================================================
// flushLoop — idle-timeout flush for response assembler
// =============================================================================

func (s *sniffer) flushLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.assemblerMu.Lock()
			s.assembler.FlushAll()
			s.assemblerMu.Unlock()
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-s.reassemblyConfig.IdleTimeout)
			s.assemblerMu.Lock()
			s.assembler.FlushOlderThan(cutoff)
			s.assemblerMu.Unlock()
		}
	}
}

// =============================================================================
// cleanupLoop — bidirectional flow expiry (1s interval)
// =============================================================================
//
// Response orphan timeout: 2s. If a response has been queued without a
// matching request for 2s, insert it as an orphan into the ring buffer.
//
// Request expire timeout: 30s. If a request has been waiting without a
// matching response for 30s, discard it (edge-generated response, dropped
// connection, etc.).
//
// Empty flows: deleted from the map (the design review: don't leak empty structs).

func (s *sniffer) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runCleanup()
		}
	}
}

func (s *sniffer) runCleanup() {
	now := time.Now()
	respCutoff := now.Add(-s.flowConfig.ResponseOrphanTimeout)
	reqCutoff := now.Add(-s.flowConfig.RequestExpireTimeout)

	// Step 1: Snapshot flow pointers under the global lock.
	// This keeps flowsMu held for O(N) pointer copies — no per-flow
	// locking, no buffer.Insert, no callbacks. On a busy server with
	// 50K flows, this is ~50K pointer copies (~400KB), sub-millisecond.
	type flowEntry struct {
		key streamKey
		fp  *flowPair
	}

	s.flowsMu.Lock()
	snapshot := make([]flowEntry, 0, len(s.flows))
	for key, fp := range s.flows {
		snapshot = append(snapshot, flowEntry{key: key, fp: fp})
	}
	s.flowsMu.Unlock()

	// Step 2: Process each flow under its own lock. No global lock held.
	type orphanAction struct {
		captured CapturedResponse
	}
	var orphans []orphanAction
	var expiredReqs int64
	var emptyKeys []streamKey

	for _, entry := range snapshot {
		fp := entry.fp
		fp.mu.Lock()

		// Expire old responses → orphans.
		i := 0
		for i < len(fp.responses) && fp.responses[i].timestamp.Before(respCutoff) {
			orphans = append(orphans, orphanAction{captured: fp.responses[i].captured})
			i++
		}
		if i > 0 {
			fp.responses = fp.responses[i:]
		}

		// Expire old requests — log each one when verbose.
		j := 0
		for j < len(fp.requests) && fp.requests[j].timestamp.Before(reqCutoff) {
			if s.verbose {
				log.Printf("[rec] CLEANUP: expired request %s %s (age=%.1fs)",
					fp.requests[j].method, fp.requests[j].path,
					time.Since(fp.requests[j].timestamp).Seconds())
			}
			j++
		}
		if j > 0 {
			expiredReqs += int64(j)
			fp.requests = fp.requests[j:]
		}

		empty := len(fp.requests) == 0 && len(fp.responses) == 0
		fp.mu.Unlock()

		if empty {
			emptyKeys = append(emptyKeys, entry.key)
		}
	}

	// Step 3: Delete empty flows under the global lock. Brief hold.
	if len(emptyKeys) > 0 {
		s.flowsMu.Lock()
		for _, key := range emptyKeys {
			// Re-check: another goroutine may have inserted into this flow
			// between our snapshot and now. Only delete if still empty.
			if fp, ok := s.flows[key]; ok {
				fp.mu.Lock()
				stillEmpty := len(fp.requests) == 0 && len(fp.responses) == 0
				fp.mu.Unlock()
				if stillEmpty {
					delete(s.flows, key)
				}
			}
		}
		s.flowsMu.Unlock()
	}

	// Step 4: Execute orphan insertions OUTSIDE all locks.
	for _, o := range orphans {
		s.buffer.Insert(o.captured)
		if s.onCapture != nil {
			s.onCapture(o.captured)
		}
		atomic.AddInt64(&s.orphanResponses, 1)
	}

	if expiredReqs > 0 {
		atomic.AddInt64(&s.requestsExpired, expiredReqs)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func htons(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}