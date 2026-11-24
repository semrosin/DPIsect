package generator

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RawFlow is the live TCP sequence space captured after the handshake.
// The raw path cannot use the kernel's socket state, so the runner
// fills this from the client-side trace before building a fake packet
// (D02, D03; docs/ARCHITECTURE.md §4).
type RawFlow struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	SndNxt  uint32
	RcvNxt  uint32
	Window  uint16
}

// OldSequenceOffset places the D02 "old" probe far below the receive
// window while keeping arithmetic in uint32 space.
const OldSequenceOffset = 1 << 20

// BuildRawIPv4TCP serializes one IPv4/TCP packet with a PSH+ACK flag
// and the absolute SEQ/ACK already resolved in p. Checksum is computed
// unless p.Checksum is non-zero; CorruptChecksum wins over both and
// flips the computed value (D04).
func BuildRawIPv4TCP(p PlannedWirePacket, f RawFlow) ([]byte, error) {
	src4 := f.SrcIP.To4()
	dst4 := f.DstIP.To4()
	if src4 == nil || dst4 == nil {
		return nil, fmt.Errorf("raw packet: IPv4 source and destination are required")
	}
	if len(p.Payload) == 0 {
		return nil, fmt.Errorf("raw packet: empty payload")
	}
	if f.SrcPort == 0 || f.DstPort == 0 {
		return nil, fmt.Errorf("raw packet: source and destination ports are required")
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 64
	}
	window := f.Window
	if window == 0 {
		window = 64240
	}

	const ipLen, tcpLen = 20, 20
	total := ipLen + tcpLen + len(p.Payload)
	packet := make([]byte, total)

	ip := packet[:ipLen]
	ip[0] = 0x45
	ip[1] = 0
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	binary.BigEndian.PutUint16(ip[4:6], 0)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
	ip[8] = ttl
	ip[9] = 6 // TCP
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	tcp := packet[ipLen : ipLen+tcpLen]
	binary.BigEndian.PutUint16(tcp[0:2], f.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], f.DstPort)
	binary.BigEndian.PutUint32(tcp[4:8], p.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], p.Ack)
	tcp[12] = 5 << 4
	tcp[13] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(tcp[14:16], window)
	binary.BigEndian.PutUint16(tcp[18:20], 0)
	copy(packet[ipLen+tcpLen:], p.Payload)

	tcpSum := tcpChecksum(src4, dst4, packet[ipLen:])
	switch {
	case p.CorruptChecksum:
		tcpSum ^= 0xffff
		if tcpSum == 0 {
			tcpSum = 0xffff
		}
	case p.Checksum != 0:
		tcpSum = p.Checksum
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpSum)
	return packet, nil
}

// ResolveRawSequence applies the D02 mode to the live SndNxt.
func ResolveRawSequence(mode string, sndNxt uint32, payloadLen int) (uint32, error) {
	switch mode {
	case "correct":
		return sndNxt, nil
	case "out_of_order":
		return sndNxt + uint32(payloadLen), nil
	case "old":
		return sndNxt - OldSequenceOffset, nil
	default:
		return 0, fmt.Errorf("raw seq mode %q", mode)
	}
}

// ResolveRawAck applies the D03 mode to the live RcvNxt.
func ResolveRawAck(mode string, rcvNxt uint32) (uint32, error) {
	switch mode {
	case "correct":
		return rcvNxt, nil
	case "wrong":
		return rcvNxt + 1, nil
	default:
		return 0, fmt.Errorf("raw ack mode %q", mode)
	}
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return checksum(pseudo)
}
