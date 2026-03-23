package rec

// =============================================================================
// BPF Kernel Filtering — Phase 2 Optimization
// =============================================================================
//
// STATUS: Not yet implemented. Requires adding external dependencies:
//   go get golang.org/x/net/bpf golang.org/x/sys/unix
//
// The sniffer works correctly without BPF — it just processes more packets
// in userspace. BPF is a CPU optimization for busy hosts, not a correctness fix.
//
// WHAT IT WOULD DO:
//   Attach a classic BPF filter to the AF_PACKET socket that passes ONLY:
//     - TCP packets where src OR dst port is in the HTTP port list (80, 8080)
//     - UDP packets where dst port is the VXLAN port (4789)
//   Everything else gets dropped in kernel space before copying to userspace.
//
// HOW TO IMPLEMENT:
//   1. go get golang.org/x/net/bpf golang.org/x/sys/unix
//   2. Build the BPF instruction array using bpf.LoadAbsolute, bpf.JumpIf, etc.
//   3. Assemble with bpf.Assemble() → []bpf.RawInstruction
//   4. Attach with unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
//   5. Call in openSocket() after the socket is created, before readLoop starts
//   6. If attachment fails, log warning and continue — BPF is best-effort
//
// REFERENCE (from VXLAN research — verified against gopacket's BPF approach):
//
//   filter for "tcp port 80 or tcp port 8080 or udp dst port 4789":
//
//     LoadAbsolute{Off: 12, Size: 2}                          // EtherType
//     JumpIf{Cond: JumpNotEqual, Val: 0x0800, SkipTrue: →REJECT}
//     LoadAbsolute{Off: 23, Size: 1}                          // IP protocol
//     JumpIf{Cond: JumpEqual, Val: 17, SkipTrue: →UDP_CHECK}  // UDP
//     JumpIf{Cond: JumpNotEqual, Val: 6, SkipTrue: →REJECT}   // not TCP
//     LoadMemShift{Off: 14}                                    // X = IHL*4
//     LoadIndirect{Off: 16, Size: 2}                          // TCP dst port
//     JumpIf{Cond: JumpEqual, Val: 80, SkipTrue: →ACCEPT}
//     JumpIf{Cond: JumpEqual, Val: 8080, SkipTrue: →ACCEPT}
//     LoadIndirect{Off: 14, Size: 2}                          // TCP src port
//     JumpIf{Cond: JumpEqual, Val: 80, SkipTrue: →ACCEPT}
//     JumpIf{Cond: JumpEqual, Val: 8080, SkipTrue: →ACCEPT}
//     Jump to →REJECT
//   UDP_CHECK:
//     LoadMemShift{Off: 14}                                    // X = IHL*4
//     LoadIndirect{Off: 16, Size: 2}                          // UDP dst port
//     JumpIf{Cond: JumpEqual, Val: 4789, SkipTrue: →ACCEPT}
//   REJECT: RetConstant{Val: 0}
//   ACCEPT: RetConstant{Val: 0xFFFF}
