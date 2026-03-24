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

// streamKey identifies one direction of a TCP connection.
type streamKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

// reverse returns the opposite direction of this stream.
func (sk streamKey) reverse() streamKey {
	return streamKey{
		srcIP: sk.dstIP, srcPort: sk.dstPort,
		dstIP: sk.srcIP, dstPort: sk.srcPort,
	}
}

// pendingRequest is a request we saw on the wire, waiting for its response.
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
//   Suitable for low-traffic servers (e.g. CapRover boxes) where most HTTP
//   transactions fit in a single TCP segment.
//
//   Supports VXLAN-encapsulated traffic (Docker Swarm, Kubernetes Flannel,
//   etc.) — automatically detects and unwraps VXLAN tunnels to reach the
//   inner plaintext HTTP. No configuration needed on standard setups.
//
// WHAT THIS IS NOT:
//   Reliable transaction reconstruction. Not forensic-grade. Not suitable
//   for high-throughput environments or compliance evidence without caveats.
//
// HOW IT WORKS:
//   1. Opens an AF_PACKET raw socket (requires CAP_NET_RAW)
//   2. Reads ethernet frames, parses IPv4 headers manually
//   3. For TCP: filters by configured ports, parses HTTP request/response
//   4. For UDP: detects VXLAN (dst port 4789), unwraps inner Ethernet frame,
//      and recurses back to step 2 with a depth guard (max 2 levels)
//   5. Uses stdlib net/http to parse HTTP request/response from TCP payload
//   6. Tracks request→response pairing via FIFO queue per TCP stream
//   7. Inserts completed transactions into the ring buffer
//
// KNOWN LIMITATIONS (be honest about these):
//
//   1. SINGLE-SEGMENT PARSING: If HTTP headers span multiple TCP segments,
//      the request or response is silently skipped. In practice, headers
//      almost always fit in one segment (MSS ~1460, headers usually <500).
//
//   2. BODY PREVIEW ONLY: Body capture is limited to what fits in the TCP
//      segment after headers. BodyPreviewHash covers only this partial
//      content, NOT the full response body. Don't treat it as forensic.
//
//   3. REQUEST CAPTURE FAILURES: If the request packet is missed (dropped,
//      partial, or arrived before sniffer started), the response is inserted
//      WITHOUT method/path/host/user-agent. This makes it unmatchable by
//      the correlator. EXPECT A SIGNIFICANT MISS RATE in real traffic,
//      especially right after startup or during traffic bursts.
//
//   4. IPv4 ONLY: No IPv6 support (EtherType 0x0800 filter). Fine for
//      Docker bridge networks which are typically IPv4.
//
//   5. NO SOURCE CONTAINER RESOLUTION: We see IP addresses on the wire,
//      not container names. IP→container mapping is not implemented in
//      Phase 1. The SourceContainer field on CapturedResponse is left
//      empty by the sniffer.
//
//   6. CPU COST: Every IPv4 packet hits userspace parsing. No BPF
//      filter yet. Acceptable on low-traffic boxes, problematic at scale.
//      BPF port filtering is a Phase 2 optimization.
//
//   7. ENCRYPTED OVERLAYS: If Docker Swarm overlay networks are created
//      with --opt encrypted, IPsec encrypts the VXLAN payload. VXLAN
//      unwrapping still works mechanically, but the inner frame is
//      ciphertext — no HTTP will be parsed. REC honestly reports zero
//      HTTP in this case.

type sniffer struct {
	buffer    *RingBuffer
	iface     string // empty = capture on all interfaces
	ports     map[int]bool
	maxBody   int
	vxlanPort uint16 // VXLAN destination port (default 4789, from Docker API or config)

	// FIFO queue of pending requests per TCP stream direction.
	// Nginx uses HTTP keep-alive on upstream connections, so multiple
	// requests can be in-flight on the same TCP connection simultaneously.
	// A single-pointer map would cause Request B to overwrite Request A
	// when both are on the same connection. FIFO ordering is correct
	// for HTTP/1.1 without multiplexing (strictly sequential).
	// ('s keep-alive bug catch.)
	pending map[streamKey][]*pendingRequest
	mu      sync.Mutex

	// Debug counters for startup logging
	packetCount   int64
	httpReqCount  int64
	httpRespCount int64
	pairMissCount int64 // responses where request was never seen
	vxlanCount    int64 // VXLAN packets successfully unwrapped
	vxlanHTTPReq  int64 // HTTP requests found inside VXLAN tunnels
	vxlanHTTPResp int64 // HTTP responses found inside VXLAN tunnels
}

func newSniffer(buffer *RingBuffer, iface string, ports []int, maxBody int, vxlanPort uint16) *sniffer {
	portSet := make(map[int]bool, len(ports))
	for _, p := range ports {
		portSet[p] = true
	}
	if vxlanPort == 0 {
		vxlanPort = DefaultVXLANPort
	}
	return &sniffer{
		buffer:    buffer,
		iface:     iface,
		ports:     portSet,
		pending:   make(map[streamKey][]*pendingRequest),
		maxBody:   maxBody,
		vxlanPort: vxlanPort,
	}
}

// openSocket opens the AF_PACKET raw socket and binds to the interface.
// Runs SYNCHRONOUSLY in Start() — if it fails, Start() returns the error
// and running stays false.
func (s *sniffer) openSocket() (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
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
// Runs in a goroutine — the socket is already open and verified.
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
// The depth parameter guards against VXLAN-in-VXLAN recursion (max 2 levels).
//
// VXLAN detection is always-on, no-op when absent:
//   1. Try VXLAN decap first. If it succeeds, recurse with inner frame.
//   2. If not VXLAN, proceed with normal Ethernet → IPv4 → TCP → HTTP.
//
// This handles both Swarm (VXLAN-encapsulated HTTP) and plain docker-compose
// (direct TCP HTTP) transparently, with zero configuration.
func (s *sniffer) processFrame(frame []byte, depth int) {
	if depth > maxDecapDepth {
		return // guard against pathological tunnel-in-tunnel
	}

	// --- Try VXLAN decapsulation first (always-on, no-op when absent) ---
	// decapVXLAN returns errNotVXLAN in constant time for non-VXLAN packets.
	// On Swarm: unwraps the inner Ethernet frame and recurses.
	// On docker-compose: fails fast, falls through to normal TCP parsing.
	if result, err := decapVXLAN(frame, s.vxlanPort); err == nil {
		s.vxlanCount++
		s.processFrame(result.InnerFrame, depth+1)
		return
	}

	// --- Normal Ethernet → IPv4 → TCP → HTTP ---
	if len(frame) < 14 {
		return
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != 0x0800 { // IPv4 only (no IPv6 in Phase 1)
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
	if ipData[9] != 6 { // TCP only (UDP is handled by VXLAN path above)
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

	if s.ports[int(dstPort)] {
		s.handleRequest(key, payload)
		if depth > 0 {
			s.vxlanHTTPReq++
		}
		return
	}
	if s.ports[int(srcPort)] {
		s.handleResponse(key, payload)
		if depth > 0 {
			s.vxlanHTTPResp++
		}
		return
	}
}

// handleRequest tries to parse an HTTP request from a single TCP segment.
func (s *sniffer) handleRequest(key streamKey, payload []byte) {
	if !looksLikeHTTPRequest(payload) {
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return // partial headers, TLS, or garbage — skip
	}
	defer req.Body.Close()

	s.mu.Lock()
	// FIFO append — HTTP/1.1 keep-alive means multiple requests on same
	// TCP connection. We queue them in order and pop from front when the
	// response arrives. ('s keep-alive bug catch.)
	s.pending[key] = append(s.pending[key], &pendingRequest{
		method:    req.Method,
		path:      req.RequestURI, // raw path with query string — SACRED
		host:      req.Host,
		userAgent: req.UserAgent(),
		timestamp: time.Now(),
	})
	s.mu.Unlock()

	log.Printf("[rec] REQ: %d.%d.%d.%d:%d→%d.%d.%d.%d:%d %s %s",
		key.srcIP[0], key.srcIP[1], key.srcIP[2], key.srcIP[3], key.srcPort,
		key.dstIP[0], key.dstIP[1], key.dstIP[2], key.dstIP[3], key.dstPort,
		req.Method, req.RequestURI)

	s.httpReqCount++
}

// handleResponse tries to parse an HTTP response from a single TCP segment.
func (s *sniffer) handleResponse(key streamKey, payload []byte) {
	if !bytes.HasPrefix(payload, []byte("HTTP/")) {
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(payload)), nil)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Pop the oldest pending request on the reverse stream (FIFO).
	// HTTP/1.1 without multiplexing is strictly sequential, so the first
	// queued request matches the first response. ('s fix.)
	reverseKey := key.reverse()

	s.mu.Lock()
	var pending *pendingRequest
	queue := s.pending[reverseKey]
	if len(queue) > 0 {
		pending = queue[0]
		s.pending[reverseKey] = queue[1:]
		if len(s.pending[reverseKey]) == 0 {
			delete(s.pending, reverseKey) // clean up empty slices
		}
	}
	s.mu.Unlock()

	// Read body preview — whatever fits in this single TCP segment after headers.
	// This is PARTIAL content, not the full body.
	bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.maxBody)))

	// Hash the PREVIEW, not the full body.
	// This is explicitly a preview hash — see BodyPreviewHash on TransportEvidence.
	bodyPreviewHash := HashBody(bodyPreview)

	contentLength := resp.ContentLength
	if contentLength < 0 && len(bodyPreview) > 0 {
		contentLength = int64(len(bodyPreview))
	}

	captured := CapturedResponse{
		Timestamp:     time.Now(),
		StatusCode:    resp.StatusCode,
		ContentType:   resp.Header.Get("Content-Type"),
		ContentLength: contentLength,
		BodyPreview:   bodyPreview,
		BodyPreviewHash: bodyPreviewHash,
		// NOTE: SourceContainer is NOT populated by the sniffer.
		// We see IP addresses on the wire, not container names.
		// IP→container resolution is not implemented in Phase 1.
		// SourceContainer is left empty — the ring buffer's Lookup()
		// skips the container filter when empty on either side.
	}

	// Attach request fields if we saw the matching request.
	// If request capture failed (missed packet, partial headers, sniffer
	// started after request was sent), these stay empty and the response
	// becomes unmatchable by the correlator. This is expected — see
	// "REQUEST CAPTURE FAILURES" in the sniffer doc comment.
	if pending != nil {
		captured.Method = pending.method
		captured.Path = pending.path
		captured.Host = pending.host
		captured.UserAgent = pending.userAgent
		log.Printf("[rec] RESP paired: %d.%d.%d.%d:%d→%d.%d.%d.%d:%d status=%d method=%s path=%s",
			key.srcIP[0], key.srcIP[1], key.srcIP[2], key.srcIP[3], key.srcPort,
			key.dstIP[0], key.dstIP[1], key.dstIP[2], key.dstIP[3], key.dstPort,
			resp.StatusCode, pending.method, pending.path)
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
}

// cleanupLoop removes stale pending requests every 30 seconds.
// Iterates through FIFO queues and removes entries older than 30s.
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
				// Remove stale entries from front of queue (oldest first)
				i := 0
				for i < len(queue) && queue[i].timestamp.Before(cutoff) {
					i++
				}
				if i == len(queue) {
					delete(s.pending, key) // entire queue is stale
				} else if i > 0 {
					s.pending[key] = queue[i:] // trim stale prefix
				}
			}
			s.mu.Unlock()
		}
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