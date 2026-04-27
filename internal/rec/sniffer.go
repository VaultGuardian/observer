// internal/rec/sniffer.go
package rec

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// =============================================================================
// Stream Tracking — Pair HTTP requests with responses
// =============================================================================

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

// =============================================================================
// Sniffer — Raw socket packet capture + HTTP parsing
// =============================================================================
//
// WHAT THIS IS:
//   Best-effort, single-segment HTTP sniffing on plaintext traffic behind
//   a reverse proxy. Pure Go stdlib, zero external dependencies, no CGO.
//
// HOW IT WORKS (v0.22 — SPECULATIVE PARSE):
//   1. Opens an AF_PACKET raw socket (requires CAP_NET_RAW)
//   2. Reads ethernet frames, parses IPv4 headers manually
//   3. For TCP: checks payload prefix speculatively
//   4. For UDP: detects VXLAN, unwraps inner frame, recurses
//   5. Uses stdlib net/http to parse HTTP request/response from TCP payload
//   6. Tracks request→response pairing via FIFO queue per TCP stream
//   7. Inserts completed transactions into the ring buffer
//   8. Fix 1: Fires onCapture callback for VIP lane push matching

type sniffer struct {
	buffer    *RingBuffer
	iface     string
	maxBody   int
	vxlanPort uint16

	knownPorts map[int]bool

	pending map[streamKey][]*pendingRequest
	mu      sync.Mutex

	// Fix 1: Called after each successful response capture.
	// The collector uses this to check VIP pins for push matching.
	// Set by the liveCollector before readLoop starts.
	onCapture func(CapturedResponse)

	// --- Core counters ---
	packetCount   int64
	httpReqCount  int64
	httpRespCount int64
	pairMissCount int64
	vxlanCount    int64
	vxlanHTTPReq  int64
	vxlanHTTPResp int64

	// --- Speculative parse telemetry ---
	reqPrefixHits  int64
	reqParseFails  int64
	respPrefixHits int64
	respParseFails int64

	// --- Phase 1 segmentation diagnostics (v0.40) ---
	// bodyEmptyInSegment: bodyInSegment == 0 for any reason (incl. HEAD, 204, 304)
	// bodyExpectedButMissing: bodyInSegment == 0 AND a body was expected — the smoking gun
	// chunkedRespCount: responses with Transfer-Encoding: chunked
	// compressedRespCount: responses with Content-Encoding present (gzip/br/etc.)
	bodyEmptyInSegment     int64
	bodyExpectedButMissing int64
	chunkedRespCount       int64
	compressedRespCount    int64

	portReqHits  map[int]int64
	portRespHits map[int]int64

	verbose bool
}

func newSniffer(buffer *RingBuffer, iface string, ports []int, maxBody int, vxlanPort uint16, verbose bool) *sniffer {
	knownPorts := make(map[int]bool, len(ports))
	for _, p := range ports {
		knownPorts[p] = true
	}
	if vxlanPort == 0 {
		vxlanPort = DefaultVXLANPort
	}
	return &sniffer{
		buffer:       buffer,
		iface:        iface,
		knownPorts:   knownPorts,
		pending:      make(map[streamKey][]*pendingRequest),
		maxBody:      maxBody,
		vxlanPort:    vxlanPort,
		portReqHits:  make(map[int]int64),
		portRespHits: make(map[int]int64),
		verbose:      verbose,
	}
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
			log.Printf("[rec] Sniffer stopping (packets=%d httpReq=%d httpResp=%d pairMisses=%d vxlan=%d vxlanReq=%d vxlanResp=%d)",
				s.packetCount, s.httpReqCount, s.httpRespCount, s.pairMissCount,
				s.vxlanCount, s.vxlanHTTPReq, s.vxlanHTTPResp)
			log.Printf("[rec] Speculative parse stats: reqPrefixHits=%d reqParseFails=%d respPrefixHits=%d respParseFails=%d",
				s.reqPrefixHits, s.reqParseFails, s.respPrefixHits, s.respParseFails)
			log.Printf("[rec:diag] Segmentation stats: bodyEmptyInSegment=%d bodyExpectedButMissing=%d chunkedResp=%d compressedResp=%d",
				s.bodyEmptyInSegment, s.bodyExpectedButMissing, s.chunkedRespCount, s.compressedRespCount)
			s.logPortStats()
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

		s.packetCount++
		s.processFrame(buf[:n], 0)

		if !debugLogged && s.packetCount >= 10 {
			log.Printf("[rec] Sniffer active: %d packets, %d HTTP req, %d HTTP resp, %d pair misses, %d VXLAN unwrapped",
				s.packetCount, s.httpReqCount, s.httpRespCount, s.pairMissCount, s.vxlanCount)
			debugLogged = true
		}
	}
}

// processFrame parses an ethernet frame and routes HTTP traffic to handlers.
func (s *sniffer) processFrame(frame []byte, depth int) {
	if depth > maxDecapDepth {
		return
	}

	// --- Try VXLAN decapsulation first ---
	if result, err := decapVXLAN(frame, s.vxlanPort); err == nil {
		s.vxlanCount++
		s.processFrame(result.InnerFrame, depth+1)
		return
	}

	// --- Normal Ethernet → IPv4 → TCP → Speculative HTTP ---
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
	dataOffset := int(tcpData[12]>>4) * 4
	if len(tcpData) < dataOffset {
		return
	}
	payload := tcpData[dataOffset:]

	if len(payload) == 0 {
		return
	}

	key := streamKey{srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort}

	// --- Speculative parse ---
	if looksLikeHTTPRequest(payload) {
		s.reqPrefixHits++
		if s.handleRequest(key, payload, int(dstPort)) {
			if depth > 0 {
				s.vxlanHTTPReq++
			}
		}
		return
	}

	if looksLikeHTTPResponse(payload) {
		s.respPrefixHits++
		if s.handleResponse(key, payload, int(srcPort)) {
			if depth > 0 {
				s.vxlanHTTPResp++
			}
		}
		return
	}
}

// handleRequest tries to parse an HTTP request from a single TCP segment.
func (s *sniffer) handleRequest(key streamKey, payload []byte, dstPort int) bool {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		s.reqParseFails++
		return false
	}
	defer req.Body.Close()

	s.mu.Lock()
	s.pending[key] = append(s.pending[key], &pendingRequest{
		method:    req.Method,
		path:      req.RequestURI,
		host:      req.Host,
		userAgent: req.UserAgent(),
		timestamp: time.Now(),
	})
	s.portReqHits[dstPort]++
	s.mu.Unlock()

	if s.verbose {
		log.Printf("[rec] REQ: %d.%d.%d.%d:%d→%d.%d.%d.%d:%d %s %s",
			key.srcIP[0], key.srcIP[1], key.srcIP[2], key.srcIP[3], key.srcPort,
			key.dstIP[0], key.dstIP[1], key.dstIP[2], key.dstIP[3], key.dstPort,
			req.Method, req.RequestURI)
	}

	s.httpReqCount++
	return true
}

// handleResponse tries to parse an HTTP response from a single TCP segment.
// Fix 1: After inserting into the ring buffer, fires the onCapture callback
// so the VIP lane can check for push matches.
//
// v0.40: Phase 1 diagnostics — detect header/body segmentation patterns.
// We're looking for cases where nginx splits headers and body across
// separate TCP packets. The single-segment parser sees headers, parses
// HTTP 200, but reads zero body bytes because the body is in the next
// packet. Phase 3 will fix this with full TCP reassembly. Phase 1 just
// gives us the data to confirm and quantify the problem.
func (s *sniffer) handleResponse(key streamKey, payload []byte, srcPort int) bool {
	// Phase 1: locate the header/body boundary BEFORE parsing. This tells
	// us how many body bytes (if any) are in this single segment.
	hdrEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	bodyInSegment := 0
	if hdrEnd >= 0 {
		bodyInSegment = len(payload) - hdrEnd - 4
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
	if err != nil {
		s.respParseFails++
		return false
	}
	defer resp.Body.Close()

	// Pop the oldest pending request on the reverse stream (FIFO).
	reverseKey := key.reverse()

	s.mu.Lock()
	var pending *pendingRequest
	queue := s.pending[reverseKey]
	if len(queue) > 0 {
		pending = queue[0]
		s.pending[reverseKey] = queue[1:]
		if len(s.pending[reverseKey]) == 0 {
			delete(s.pending, reverseKey)
		}
	}
	s.portRespHits[srcPort]++
	s.mu.Unlock()

	// Read body preview
	bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.maxBody)))
	bodyPreviewHash := HashBody(bodyPreview)

	contentLength := resp.ContentLength
	if contentLength < 0 && len(bodyPreview) > 0 {
		contentLength = int64(len(bodyPreview))
	}

	// =========================================================================
	// Phase 1 diagnostics
	// =========================================================================
	// Decide whether a body was *expected* in this response. Empty bodies are
	// legitimate for: HEAD requests, 1xx informational, 204 No Content,
	// 304 Not Modified. Anything else with Content-Length > 0 or chunked
	// transfer encoding implies a body should exist.
	isHEAD := pending != nil && pending.method == "HEAD"
	bodylessStatus := resp.StatusCode == 204 || resp.StatusCode == 304 ||
		(resp.StatusCode >= 100 && resp.StatusCode < 200)
	hasChunked := len(resp.TransferEncoding) > 0
	hasCompression := resp.Header.Get("Content-Encoding") != ""

	bodyExpected := !isHEAD && !bodylessStatus &&
		(resp.ContentLength > 0 || hasChunked)

	if bodyInSegment == 0 {
		s.bodyEmptyInSegment++
		if bodyExpected {
			s.bodyExpectedButMissing++
		}
	}
	if hasChunked {
		s.chunkedRespCount++
	}
	if hasCompression {
		s.compressedRespCount++
	}

	// Per-response diagnostic log:
	//   - verbose mode: every response
	//   - default: only suspected-broken cases (the smoking gun for Phase 3)
	// Without this filter, scanner traffic on bare-IP hosts would flood logs;
	// with it, we see exactly the cases REC is failing on.
	if s.verbose || (bodyInSegment == 0 && bodyExpected) {
		method := "?"
		path := "?"
		if pending != nil {
			method = pending.method
			path = pending.path
		}
		log.Printf("[rec:diag] RESP status=%d cl=%d te=%v ce=%q ct=%q method=%s path=%s payloadLen=%d hdrEnd=%d bodyInSegment=%d rawPreviewLen=%d hash=%.16s",
			resp.StatusCode, resp.ContentLength, resp.TransferEncoding,
			resp.Header.Get("Content-Encoding"), resp.Header.Get("Content-Type"),
			method, path,
			len(payload), hdrEnd, bodyInSegment, len(bodyPreview), bodyPreviewHash)
	}

	captured := CapturedResponse{
		Timestamp:       time.Now(),
		StatusCode:      resp.StatusCode,
		ContentType:     resp.Header.Get("Content-Type"),
		ContentLength:   contentLength,
		BodyPreview:     bodyPreview,
		BodyPreviewHash: bodyPreviewHash,
	}

	// Attach request fields if we saw the matching request.
	if pending != nil {
		captured.Method = pending.method
		captured.Path = pending.path
		captured.Host = pending.host
		captured.UserAgent = pending.userAgent
		if s.verbose {
			log.Printf("[rec] RESP paired: %d.%d.%d.%d:%d→%d.%d.%d.%d:%d status=%d method=%s path=%s",
				key.srcIP[0], key.srcIP[1], key.srcIP[2], key.srcIP[3], key.srcPort,
				key.dstIP[0], key.dstIP[1], key.dstIP[2], key.dstIP[3], key.dstPort,
				resp.StatusCode, pending.method, pending.path)
		}
	} else {
		s.pairMissCount++
		log.Printf("[rec] RESP pair miss: %d.%d.%d.%d:%d→%d.%d.%d.%d:%d status=%d reverseKey=%d.%d.%d.%d:%d→%d.%d.%d.%d:%d pendingStreams=%d",
			key.srcIP[0], key.srcIP[1], key.srcIP[2], key.srcIP[3], key.srcPort,
			key.dstIP[0], key.dstIP[1], key.dstIP[2], key.dstIP[3], key.dstPort,
			resp.StatusCode,
			reverseKey.srcIP[0], reverseKey.srcIP[1], reverseKey.srcIP[2], reverseKey.srcIP[3], reverseKey.srcPort,
			reverseKey.dstIP[0], reverseKey.dstIP[1], reverseKey.dstIP[2], reverseKey.dstIP[3], reverseKey.dstPort,
			len(s.pending))
	}

	s.buffer.Insert(captured)
	s.httpRespCount++

	// Fix 1: Fire VIP lane callback.
	// The collector checks VIP pins for immediate push resolution.
	// Non-blocking — this must not slow down the packet capture loop.
	if s.onCapture != nil {
		s.onCapture(captured)
	}

	return true
}

// cleanupLoop removes stale pending requests every 30 seconds.
func (s *sniffer) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			cutoff := time.Now().Add(-30 * time.Second)
			for key, queue := range s.pending {
				i := 0
				for i < len(queue) && queue[i].timestamp.Before(cutoff) {
					i++
				}
				if i == len(queue) {
					delete(s.pending, key)
				} else if i > 0 {
					s.pending[key] = queue[i:]
				}
			}
			s.mu.Unlock()
		}
	}
}

// logPortStats logs which ports had successful HTTP parses.
func (s *sniffer) logPortStats() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.portReqHits) == 0 && len(s.portRespHits) == 0 {
		return
	}

	log.Printf("[rec] Port stats (requests):")
	for port, count := range s.portReqHits {
		known := ""
		if s.knownPorts[port] {
			known = " (configured)"
		}
		log.Printf("[rec]   port %d: %d parsed%s", port, count, known)
	}
	log.Printf("[rec] Port stats (responses):")
	for port, count := range s.portRespHits {
		known := ""
		if s.knownPorts[port] {
			known = " (configured)"
		}
		log.Printf("[rec]   port %d: %d parsed%s", port, count, known)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func htons(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}

func looksLikeHTTPRequest(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	switch {
	case bytes.HasPrefix(payload, []byte("GET ")),
		bytes.HasPrefix(payload, []byte("POST ")),
		bytes.HasPrefix(payload, []byte("PUT ")),
		bytes.HasPrefix(payload, []byte("DELETE ")),
		bytes.HasPrefix(payload, []byte("PATCH ")),
		bytes.HasPrefix(payload, []byte("HEAD ")),
		bytes.HasPrefix(payload, []byte("OPTIONS ")),
		bytes.HasPrefix(payload, []byte("CONNECT ")):
		return true
	}
	return false
}

func looksLikeHTTPResponse(payload []byte) bool {
	return len(payload) >= 5 && bytes.HasPrefix(payload, []byte("HTTP/"))
}