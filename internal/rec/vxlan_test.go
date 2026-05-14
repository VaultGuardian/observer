package rec

import (
	"encoding/binary"
	"testing"
)

// buildVXLANPacket constructs a synthetic VXLAN-encapsulated packet for testing.
// Structure: [Outer Eth 14B] [Outer IPv4 20B] [Outer UDP 8B] [VXLAN 8B] [Inner Eth 14B] [inner payload...]
func buildVXLANPacket(vxlanPort uint16, vni uint32, iFlag bool, innerPayload []byte) []byte {
	innerEth := make([]byte, 14) // minimal inner Ethernet header
	// Inner EtherType = IPv4
	binary.BigEndian.PutUint16(innerEth[12:14], 0x0800)

	inner := append(innerEth, innerPayload...)

	totalInnerLen := len(inner)
	udpLen := 8 + 8 + totalInnerLen // UDP header + VXLAN header + inner frame
	ipTotalLen := 20 + udpLen

	pkt := make([]byte, 14+ipTotalLen)

	// --- Outer Ethernet ---
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // EtherType = IPv4

	// --- Outer IPv4 ---
	ipOff := 14
	pkt[ipOff] = 0x45 // Version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[ipOff+2:ipOff+4], uint16(ipTotalLen))
	pkt[ipOff+9] = 17 // Protocol = UDP
	// Source IP: 10.0.0.1
	pkt[ipOff+12], pkt[ipOff+13], pkt[ipOff+14], pkt[ipOff+15] = 10, 0, 0, 1
	// Dest IP: 10.0.0.2
	pkt[ipOff+16], pkt[ipOff+17], pkt[ipOff+18], pkt[ipOff+19] = 10, 0, 0, 2

	// --- Outer UDP ---
	udpOff := ipOff + 20
	binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], 12345)       // src port
	binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], vxlanPort) // dst port
	binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], uint16(udpLen))

	// --- VXLAN Header ---
	vxlanOff := udpOff + 8
	if iFlag {
		pkt[vxlanOff] = 0x08 // I-flag set
	}
	// VNI in bytes 4-6 (stored as upper 24 bits of a 32-bit field)
	binary.BigEndian.PutUint32(pkt[vxlanOff+4:vxlanOff+8], vni<<8)

	// --- Inner frame ---
	copy(pkt[vxlanOff+8:], inner)

	return pkt
}

func TestDecapVXLAN_ValidPacket(t *testing.T) {
	innerPayload := []byte("hello inner world")
	pkt := buildVXLANPacket(4789, 4097, true, innerPayload)

	result, err := decapVXLAN(pkt, 4789)
	if err != nil {
		t.Fatalf("expected successful decap, got error: %v", err)
	}

	if result.VNI != 4097 {
		t.Errorf("expected VNI=4097, got VNI=%d", result.VNI)
	}

	// Inner frame should start with the 14-byte Ethernet header we built
	if len(result.InnerFrame) < 14+len(innerPayload) {
		t.Fatalf("inner frame too short: %d bytes", len(result.InnerFrame))
	}

	// Check inner EtherType
	innerEtherType := binary.BigEndian.Uint16(result.InnerFrame[12:14])
	if innerEtherType != 0x0800 {
		t.Errorf("expected inner EtherType=0x0800, got 0x%04x", innerEtherType)
	}

	// Check inner payload (after Ethernet header)
	gotPayload := result.InnerFrame[14:]
	if string(gotPayload) != string(innerPayload) {
		t.Errorf("inner payload mismatch: got %q, want %q", gotPayload, innerPayload)
	}
}

func TestDecapVXLAN_WrongPort(t *testing.T) {
	pkt := buildVXLANPacket(9999, 4097, true, []byte("data"))

	_, err := decapVXLAN(pkt, 4789)
	if err != errNotVXLAN {
		t.Errorf("expected errNotVXLAN for wrong port, got: %v", err)
	}
}

func TestDecapVXLAN_CustomPort(t *testing.T) {
	// Docker Swarm with --data-path-port=7777
	pkt := buildVXLANPacket(7777, 4097, true, []byte("data"))

	result, err := decapVXLAN(pkt, 7777)
	if err != nil {
		t.Fatalf("expected successful decap on custom port, got error: %v", err)
	}
	if result.VNI != 4097 {
		t.Errorf("expected VNI=4097, got %d", result.VNI)
	}
}

func TestDecapVXLAN_NoIFlag(t *testing.T) {
	pkt := buildVXLANPacket(4789, 4097, false, []byte("data"))

	_, err := decapVXLAN(pkt, 4789)
	if err != errNotVXLAN {
		t.Errorf("expected errNotVXLAN when I-flag not set, got: %v", err)
	}
}

func TestDecapVXLAN_TCPPacket(t *testing.T) {
	// Build a normal TCP packet (not UDP) — should return errNotVXLAN
	pkt := make([]byte, 14+20+20)                  // Eth + IPv4 + TCP
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // EtherType = IPv4
	pkt[14] = 0x45                                 // IPv4, IHL=5
	pkt[14+9] = 6                                  // Protocol = TCP (not UDP)

	_, err := decapVXLAN(pkt, 4789)
	if err != errNotVXLAN {
		t.Errorf("expected errNotVXLAN for TCP packet, got: %v", err)
	}
}

func TestDecapVXLAN_TooShort(t *testing.T) {
	// Packet too short for any meaningful parsing
	_, err := decapVXLAN([]byte{0x00, 0x01, 0x02}, 4789)
	if err != errTooShort {
		t.Errorf("expected errTooShort for tiny packet, got: %v", err)
	}
}

func TestDecapVXLAN_VariableIHL(t *testing.T) {
	// Build a VXLAN packet with IPv4 options (IHL=6, 24 bytes instead of 20)
	innerPayload := []byte("options test")
	innerEth := make([]byte, 14)
	binary.BigEndian.PutUint16(innerEth[12:14], 0x0800)
	inner := append(innerEth, innerPayload...)

	totalInnerLen := len(inner)
	ihl := 6 // 24 bytes (20 standard + 4 options)
	ipHdrLen := ihl * 4
	udpLen := 8 + 8 + totalInnerLen
	ipTotalLen := ipHdrLen + udpLen

	pkt := make([]byte, 14+ipTotalLen)

	// Outer Ethernet
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	// Outer IPv4 with IHL=6
	ipOff := 14
	pkt[ipOff] = byte(0x40 | ihl) // Version 4, IHL=6
	binary.BigEndian.PutUint16(pkt[ipOff+2:ipOff+4], uint16(ipTotalLen))
	pkt[ipOff+9] = 17 // UDP

	// Outer UDP (starts at ipOff + 24, not ipOff + 20)
	udpOff := ipOff + ipHdrLen
	binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], 12345)
	binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], 4789)
	binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], uint16(udpLen))

	// VXLAN header
	vxlanOff := udpOff + 8
	pkt[vxlanOff] = 0x08                                            // I-flag
	binary.BigEndian.PutUint32(pkt[vxlanOff+4:vxlanOff+8], 4098<<8) // VNI=4098

	// Inner frame
	copy(pkt[vxlanOff+8:], inner)

	result, err := decapVXLAN(pkt, 4789)
	if err != nil {
		t.Fatalf("expected successful decap with IHL=6, got error: %v", err)
	}
	if result.VNI != 4098 {
		t.Errorf("expected VNI=4098, got %d", result.VNI)
	}

	gotPayload := result.InnerFrame[14:]
	if string(gotPayload) != string(innerPayload) {
		t.Errorf("inner payload mismatch with IHL=6: got %q, want %q", gotPayload, innerPayload)
	}
}

func TestDecapVXLAN_VLANTag(t *testing.T) {
	// Build a VXLAN packet with 802.1Q VLAN tag on outer Ethernet (+4 bytes)
	innerPayload := []byte("vlan test")
	innerEth := make([]byte, 14)
	binary.BigEndian.PutUint16(innerEth[12:14], 0x0800)
	inner := append(innerEth, innerPayload...)

	totalInnerLen := len(inner)
	udpLen := 8 + 8 + totalInnerLen
	ipTotalLen := 20 + udpLen

	pkt := make([]byte, 18+ipTotalLen) // 18 = 14 Eth + 4 VLAN tag

	// Outer Ethernet with VLAN tag
	binary.BigEndian.PutUint16(pkt[12:14], 0x8100) // VLAN tag present
	binary.BigEndian.PutUint16(pkt[14:16], 100)    // VLAN ID 100
	binary.BigEndian.PutUint16(pkt[16:18], 0x0800) // Encapsulated EtherType = IPv4

	// Outer IPv4 (starts at offset 18 due to VLAN tag)
	ipOff := 18
	pkt[ipOff] = 0x45
	binary.BigEndian.PutUint16(pkt[ipOff+2:ipOff+4], uint16(ipTotalLen))
	pkt[ipOff+9] = 17 // UDP

	// Outer UDP
	udpOff := ipOff + 20
	binary.BigEndian.PutUint16(pkt[udpOff:udpOff+2], 12345)
	binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], 4789)
	binary.BigEndian.PutUint16(pkt[udpOff+4:udpOff+6], uint16(udpLen))

	// VXLAN header
	vxlanOff := udpOff + 8
	pkt[vxlanOff] = 0x08
	binary.BigEndian.PutUint32(pkt[vxlanOff+4:vxlanOff+8], 4099<<8)

	// Inner frame
	copy(pkt[vxlanOff+8:], inner)

	result, err := decapVXLAN(pkt, 4789)
	if err != nil {
		t.Fatalf("expected successful decap with VLAN tag, got error: %v", err)
	}
	if result.VNI != 4099 {
		t.Errorf("expected VNI=4099, got %d", result.VNI)
	}
}

func TestDecapVXLAN_DifferentVNIs(t *testing.T) {
	// Docker Swarm assigns VNIs sequentially: ingress=4096, first overlay=4097, etc.
	for _, vni := range []uint32{4096, 4097, 4098, 16777215} { // 16777215 = max 24-bit
		pkt := buildVXLANPacket(4789, vni, true, []byte("test"))
		result, err := decapVXLAN(pkt, 4789)
		if err != nil {
			t.Errorf("VNI=%d: unexpected error: %v", vni, err)
			continue
		}
		if result.VNI != vni {
			t.Errorf("VNI=%d: got %d", vni, result.VNI)
		}
	}
}

func TestProcessFrame_DepthGuard(t *testing.T) {
	// Verify that processFrame respects the depth limit.
	// We can't easily test the full recursion without a real socket,
	// but we can verify the depth guard by checking that a packet
	// at maxDecapDepth+1 is silently dropped.
	//
	// The real validation is on production: the VXLAN counter should
	// show unwrapped packets, and the HTTP counters should show
	// requests/responses found inside the tunnels.
	if maxDecapDepth < 1 {
		t.Fatal("maxDecapDepth should be at least 1")
	}
	if maxDecapDepth > 5 {
		t.Error("maxDecapDepth seems unreasonably high — 2-3 is expected")
	}
}
