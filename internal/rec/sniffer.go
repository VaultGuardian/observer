// internal/rec/sniffer.go
package rec

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// =============================================================================
// Stream Tracking — Pair HTTP requests with responses
// =============================================================================
//
// The sniffer's `pending` map is shared with stream.go. runRequest appends
// to it, runResponse pops from it. The cleanupLoop ages out stale entries
// for connections where the response was never observed.

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
// Sniffer — Raw socket packet capture, feeds tcpassembly
// =============================================================================
//
// HOW IT WORKS:
//   1. Opens an AF_PACKET raw socket (requires CAP_NET_RAW)
//   2. Reads ethernet frames, parses IPv4/TCP headers manually (cheap)
//   3. For UDP/VXLAN: decapsulates and recurses on the inner frame
//   4. Hands every TCP segment with payload to gopacket's tcpassembly
//   5. tcpassembly reconstructs streams, our httpStreamFactory creates
//      per-direction goroutines that run http.ReadRequest / http.ReadResponse
//      against the reassembled byte stream (see stream.go)
//   6. runResponse builds CapturedResponse, inserts into the ring buffer,
//      fires the onCapture callback for VIP lane push matching

type sniffer struct {
	buffer    *RingBuffer
	iface     string
	maxBody   int
	vxlanPort uint16

	// HTTP ports — used by stream.go for direction detection (response
	// streams have src port in this set).
	knownPorts map[int]bool

	// pending is the request→response correlation map. runRequest appends
	// here, runResponse pops the reverse-keyed entry.
	pending map[streamKey][]*pendingRequest
	mu      sync.Mutex

	// onCapture is called after each successful response capture so the
	// collector can check VIP pins for push-mode resolution.
	onCapture func(CapturedResponse)

	// --- Reassembly machinery (always-on as of v0.42) ---
	reassemblyConfig ReassemblyConfig
	assembler        *tcpassembly.Assembler
	assemblerMu      sync.Mutex // assembler is not goroutine-safe

	// --- Counters ---
	packetCount   int64
	pairMissCount int64
	vxlanCount    int64

	reassemblyStreamsActive   int64
	reassemblyStreamsTotal    int64
	reassemblyStreamsTimedOut int64
	reassemblyResponses       int64
	reassemblyRequests        int64
	reassemblyParseErrors     int64

	verbose bool
}

func newSniffer(buffer *RingBuffer, iface string, ports []int, maxBody int, vxlanPort uint16, verbose bool, reasm ReassemblyConfig) *sniffer {
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
		pending:          make(map[streamKey][]*pendingRequest),
		maxBody:          maxBody,
		vxlanPort:        vxlanPort,
		verbose:          verbose,
		reassemblyConfig: reasm,
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
	log.Printf("[rec:reassembly] enabled — maxBody=%d streamTTL=%s idleTimeout=%s pages_total=%d pages_per_conn=%d max_streams=%d",
		reasm.MaxBody, reasm.StreamTTL, reasm.IdleTimeout,
		reasm.MaxBufferedPagesTotal, reasm.MaxBufferedPagesPerConn, reasm.MaxActiveStreams)

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
			log.Printf("[rec] Sniffer stopping (packets=%d pairMisses=%d vxlan=%d)",
				s.packetCount, s.pairMissCount, s.vxlanCount)
			log.Printf("[rec:reassembly] final — streams_total=%d responses=%d requests=%d timeout=%d parse_errors=%d",
				s.reassemblyStreamsTotal, s.reassemblyResponses, s.reassemblyRequests,
				s.reassemblyStreamsTimedOut, s.reassemblyParseErrors)
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
			log.Printf("[rec] Sniffer active: %d packets, %d VXLAN unwrapped",
				s.packetCount, s.vxlanCount)
			debugLogged = true
		}
	}
}

// processFrame parses an Ethernet frame, decapsulates VXLAN if present,
// and feeds the contained TCP segment to the assembler.
func (s *sniffer) processFrame(frame []byte, depth int) {
	if depth > maxDecapDepth {
		return
	}

	// Try VXLAN decapsulation first — Swarm overlay traffic is wrapped.
	if result, err := decapVXLAN(frame, s.vxlanPort); err == nil {
		s.vxlanCount++
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
	dataOffset := int(tcpData[12]>>4) * 4
	if len(tcpData) < dataOffset {
		return
	}
	payload := tcpData[dataOffset:]

	if len(payload) == 0 {
		return
	}

	// Hand the TCP segment to gopacket's tcpassembly. Per-direction stream
	// goroutines (see stream.go) consume the reassembled byte stream and
	// run http.ReadRequest / http.ReadResponse against it.
	s.feedAssembler(srcIP, dstIP, srcPort, dstPort, tcpData, payload)
}

// feedAssembler hands a single TCP segment to gopacket's tcpassembly.
//
// We let gopacket decode the TCP layer (gopacket.NewPacket) rather than
// hand-constructing a layers.TCP. The hand-construction path leaves the
// private byte-slice representations of SrcPort/DstPort empty, which
// causes tcp.TransportFlow() to return a Flow with zero-length endpoints.
// The first call to .String() on those endpoints panics.
//
// gopacket's default decode does NOT validate TCP checksums (we initially
// avoided NewPacket out of fear of veth-namespace checksum offload — that
// fear was misplaced).
//
// Lifetime invariant: gopacket.NoCopy is safe because AssembleWithTimestamp
// is synchronous. Inside that call, tcpassembly's Reassembled hands the
// bytes to tcpreader.ReaderStream, which COPIES them into its internal
// page buffer. By the time AssembleWithTimestamp returns, the original
// slice (the kernel recvfrom buffer) can be reused with no risk to the
// stream goroutines — they only ever read the ReaderStream's owned copies.
//
// If you ever change AssembleWithTimestamp to be called asynchronously
// (e.g. via a channel), this invariant breaks and NoCopy must change to
// gopacket.Default. Don't.
func (s *sniffer) feedAssembler(srcIP, dstIP [4]byte, srcPort, dstPort uint16, tcpData, payload []byte) {
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

// flushLoop runs the assembler's idle-timeout flush every second. Streams
// that haven't seen data within IdleTimeout get force-completed, which
// causes their stream goroutines to exit cleanly via EOF on the underlying
// ReaderStream.
//
// Belt-and-suspenders for Landmine 3: each httpStream also has its own
// time.AfterFunc deadline at StreamTTL that force-closes the reader. Both
// mechanisms work together — IdleTimeout for typical idle keep-alive
// connections, StreamTTL for adversarial slowloris-style cases.
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

// cleanupLoop removes stale pending requests every 30 seconds. runRequest
// may append entries that runResponse never matches (e.g., when a response
// stream errors before parsing). Without this, the pending map grows
// without bound on long-lived processes.
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

// =============================================================================
// Helpers
// =============================================================================

func htons(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}