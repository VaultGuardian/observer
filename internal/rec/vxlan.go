package rec

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"time"
)

// =============================================================================
// VXLAN Decapsulation — RFC 7348
// =============================================================================
//
// WHY THIS EXISTS:
//   Docker Swarm (and Kubernetes Flannel, Calico, etc.) wraps container-to-container
//   traffic in VXLAN tunnels. The plaintext HTTP between nginx and backend containers
//   is invisible to a host-level AF_PACKET sniffer unless we strip the outer headers.
//
// HOW IT WORKS:
//   VXLAN adds ~50 bytes of outer headers before the inner Ethernet frame:
//     [Outer Ethernet 14B] [Outer IPv4 20B*] [Outer UDP 8B] [VXLAN 8B] [Inner Ethernet...]
//   We detect the outer UDP dst port (default 4789), validate the VXLAN I-flag,
//   strip the outer headers, and return the inner Ethernet frame for normal parsing.
//
// DESIGN PRINCIPLE:
//   Always-on, no-op when absent. decapVXLAN() returns errNotVXLAN in constant time
//   for non-VXLAN packets. No toggle needed — works transparently on both Swarm and
//   plain docker-compose hosts.
//
// CROSS-VALIDATED:
//   gopacket's own layers/vxlan.go uses the same approach: I-flag check (data[0]&0x08),
//   VNI extraction (Uint32(data[4:8]) >> 8), NextLayerType() = LayerTypeEthernet.
//   Recursive Ethernet parsing is the canonical method.

const (
	ethHdrLen        = 14
	ipv4MinLen       = 20
	udpHdrLen        = 8
	vxlanHdrLen      = 8
	etherTypeIPv4    = 0x0800
	etherTypeVLAN    = 0x8100
	protoUDP         = 17
	vxlanFlagI       = 0x08
	DefaultVXLANPort = 4789

	// Maximum VXLAN decapsulation depth. Prevents infinite recursion from
	// pathological VXLAN-in-VXLAN tunneling. In practice, depth > 1 never
	// happens in Docker/Kubernetes overlays.
	maxDecapDepth = 2
)

// vxlanResult holds the unwrapped inner frame and tunnel metadata.
type vxlanResult struct {
	VNI        uint32 // VXLAN Network Identifier (identifies the overlay network)
	InnerFrame []byte // Inner Ethernet frame — feed this back to parseFrame()
}

var (
	errNotVXLAN = errors.New("not a VXLAN packet")
	errTooShort = errors.New("packet too short for VXLAN decapsulation")
)

// decapVXLAN detects and unwraps a VXLAN-encapsulated packet.
//
// Returns errNotVXLAN for non-VXLAN traffic — this is the common case and
// NOT worth logging. The sniffer calls this on every packet; only VXLAN
// packets on the configured port with a valid I-flag get unwrapped.
//
// Handles:
//   - Variable IPv4 header length (reads IHL, never hardcodes 20)
//   - Optional 802.1Q VLAN tag on outer Ethernet (+4 bytes)
//   - Configurable VXLAN port (Docker --data-path-port)
//   - I-flag validation per RFC 7348
func decapVXLAN(pkt []byte, vxlanPort uint16) (*vxlanResult, error) {
	// Minimum: Ethernet(14) + IPv4(20) + UDP(8) + VXLAN(8) + at least 1 inner byte
	if len(pkt) < ethHdrLen+ipv4MinLen+udpHdrLen+vxlanHdrLen+1 {
		return nil, errTooShort
	}

	// --- Outer Ethernet --- handle optional 802.1Q VLAN tag
	off := ethHdrLen
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType == etherTypeVLAN {
		if len(pkt) < 18 {
			return nil, errTooShort
		}
		etherType = binary.BigEndian.Uint16(pkt[16:18])
		off = 18 // skip the 4-byte VLAN tag
	}
	if etherType != etherTypeIPv4 {
		return nil, errNotVXLAN
	}

	// --- Outer IPv4 --- read IHL for variable header length (never hardcode 20)
	if len(pkt) < off+ipv4MinLen {
		return nil, errTooShort
	}
	ihl := int(pkt[off]&0x0F) * 4
	if ihl < ipv4MinLen || len(pkt) < off+ihl {
		return nil, errTooShort
	}
	if pkt[off+9] != protoUDP {
		return nil, errNotVXLAN
	}
	off += ihl

	// --- Outer UDP --- check destination port
	if len(pkt) < off+udpHdrLen {
		return nil, errTooShort
	}
	dstPort := binary.BigEndian.Uint16(pkt[off+2 : off+4])
	if dstPort != vxlanPort {
		return nil, errNotVXLAN
	}
	off += udpHdrLen

	// --- VXLAN Header --- validate I-flag, extract VNI
	if len(pkt) < off+vxlanHdrLen {
		return nil, errTooShort
	}
	if pkt[off]&vxlanFlagI == 0 {
		return nil, errNotVXLAN // I-flag not set = not a valid VXLAN frame
	}
	// VNI is 24 bits in bytes 4-6 of the VXLAN header.
	// Read 4 bytes starting at offset 4, shift right 8 to drop the reserved byte.
	// This is the same extraction gopacket uses in layers/vxlan.go.
	vni := binary.BigEndian.Uint32(pkt[off+4:off+8]) >> 8
	off += vxlanHdrLen

	if off >= len(pkt) {
		return nil, errTooShort
	}

	return &vxlanResult{
		VNI:        vni,
		InnerFrame: pkt[off:],
	}, nil
}

// =============================================================================
// Docker Swarm Detection — Startup Probe
// =============================================================================
//
// Queries the Docker daemon at startup to detect:
//   1. Whether Swarm mode is active
//   2. The configured data-path port (default 4789, but configurable via
//      `docker swarm init --data-path-port`)
//
// Uses the Docker Unix socket directly — no external Docker client library.
// This is a best-effort startup probe, not a runtime dependency.

// SwarmInfo holds Docker Swarm detection results from startup probe.
type SwarmInfo struct {
	Active       bool   // true if LocalNodeState == "active"
	DataPathPort uint16 // VXLAN port (default 4789, may differ)
}

// detectSwarm queries the Docker daemon for Swarm state and VXLAN data-path port.
// Returns sane defaults if the Docker socket is unreachable.
func detectSwarm(dockerSocket string) SwarmInfo {
	if dockerSocket == "" {
		dockerSocket = "/var/run/docker.sock"
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", dockerSocket, 5*time.Second)
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://localhost/info")
	if err != nil {
		log.Printf("[rec] Could not query Docker for Swarm info: %v (assuming non-Swarm, port %d)", err, DefaultVXLANPort)
		return SwarmInfo{Active: false, DataPathPort: DefaultVXLANPort}
	}
	defer resp.Body.Close()

	var info struct {
		Swarm struct {
			LocalNodeState string `json:"LocalNodeState"`
			Cluster        *struct {
				DataPathPort uint32 `json:"DataPathPort"`
			} `json:"Cluster"`
		} `json:"Swarm"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		log.Printf("[rec] Could not parse Docker info: %v (assuming non-Swarm, port %d)", err, DefaultVXLANPort)
		return SwarmInfo{Active: false, DataPathPort: DefaultVXLANPort}
	}

	result := SwarmInfo{
		Active:       info.Swarm.LocalNodeState == "active",
		DataPathPort: DefaultVXLANPort,
	}

	if result.Active && info.Swarm.Cluster != nil && info.Swarm.Cluster.DataPathPort != 0 {
		result.DataPathPort = uint16(info.Swarm.Cluster.DataPathPort)
	}

	return result
}
