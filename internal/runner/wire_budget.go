package runner

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

// wireBudget belongs to one capture reader; it must not be shared by writers.
// Counts include segments represented by supported kernel offload records.
// They are capture-based estimates, not counts from the physical link.
type wireBudget struct {
	ip                 net.IP
	port               layers.TCPPort
	limits             Budget
	packets            int
	bytes              int
	recent             []time.Time
	lastObserved       time.Time
	lastMatching       bool
	maxFrameLength     int
	synSeen            map[synKey]int
	synRetransmissions int
	flows              map[flowKey]*flowState
}

type synKey struct {
	src  [4]byte
	port layers.TCPPort
	seq  uint32
}

type flowKey struct {
	src  [4]byte
	port layers.TCPPort
}

type sequenceRange struct {
	start  uint32
	length uint32
}

type flowState struct {
	synSeen bool
	synSeq  uint32
	ranges  []sequenceRange
}

type wireGSO struct {
	kind        byte
	payloadSize int
}

func newWireBudget(ip string, port int, limits Budget) (*wireBudget, error) {
	addr := net.ParseIP(ip).To4()
	if addr == nil || port < 1 || port > 65535 || limits.MaxPackets <= 0 || limits.MaxBytes <= 0 || limits.MaxRatePPS <= 0 {
		return nil, fmt.Errorf("invalid wire budget or IPv4 endpoint")
	}
	if limits.MaxSYNRetransmissions != nil && *limits.MaxSYNRetransmissions <= 0 {
		return nil, fmt.Errorf("invalid SYN retransmission limit")
	}
	return &wireBudget{ip: addr, port: layers.TCPPort(port), limits: limits, synSeen: make(map[synKey]int), flows: make(map[flowKey]*flowState)}, nil
}

// observe returns an error once an observed limit is reached or the frame
// cannot be accounted for. An asynchronous capture cannot prevent an already
// transmitted packet or guarantee that every frame was observed.
func (b *wireBudget) observe(frame []byte, originalLength int, now time.Time, gso wireGSO) error {
	b.lastMatching = false
	if originalLength != len(frame) {
		return fmt.Errorf("wire budget: incomplete capture")
	}
	p := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ipLayer := p.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		if p.ErrorLayer() != nil {
			return fmt.Errorf("wire budget: cannot decode frame: %w", p.ErrorLayer().Error())
		}
		return nil
	}
	ip := ipLayer.(*layers.IPv4)
	fromTarget, toTarget := ip.SrcIP.Equal(b.ip), ip.DstIP.Equal(b.ip)
	if (!fromTarget && !toTarget) || ip.Protocol != layers.IPProtocolTCP {
		return nil
	}
	if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
		return fmt.Errorf("wire budget: fragmented TCP frame cannot be attributed safely")
	}
	tcpLayer := p.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fmt.Errorf("wire budget: TCP header missing")
	}
	tcp := tcpLayer.(*layers.TCP)
	if !(fromTarget && tcp.SrcPort == b.port || toTarget && tcp.DstPort == b.port) {
		return nil
	}
	b.lastMatching = true
	segments, octets, err := b.frameCost(p, ip, tcp, originalLength, gso)
	if err != nil {
		return err
	}
	b.packets += segments
	b.bytes += octets
	if !b.lastObserved.IsZero() && now.Before(b.lastObserved) {
		return fmt.Errorf("wire budget: capture timestamps are out of order")
	}
	b.lastObserved = now
	if toTarget && tcp.DstPort == b.port {
		if err := b.observeOutgoing(ip, tcp); err != nil {
			return err
		}
	}
	if b.limits.MaxSYNRetransmissions != nil && toTarget && tcp.DstPort == b.port && tcp.SYN && !tcp.ACK {
		var key synKey
		copy(key.src[:], ip.SrcIP.To4())
		key.port, key.seq = tcp.SrcPort, tcp.Seq
		seen := b.synSeen[key]
		b.synSeen[key] = seen + 1
		if seen > 0 {
			b.synRetransmissions++
			if seen >= *b.limits.MaxSYNRetransmissions {
				return fmt.Errorf("wire budget: SYN retransmission limit reached (%d for one connection)", seen)
			}
		}
	}
	cutoff := now.Add(-time.Second)
	keep := 0
	for _, at := range b.recent {
		if at.After(cutoff) {
			b.recent[keep] = at
			keep++
		}
	}
	b.recent = b.recent[:keep]
	rate := len(b.recent)
	outgoing := toTarget && tcp.DstPort == b.port
	if outgoing {
		rate += segments
	}
	if b.packets >= wireStopThreshold(b.limits.MaxPackets) || b.bytes >= wireStopThreshold(b.limits.MaxBytes) || rate >= wireStopThreshold(b.limits.MaxRatePPS) {
		return fmt.Errorf("wire budget: observed limit reached (%d packets, %d bytes, %d outgoing packets in one second)", b.packets, b.bytes, rate)
	}
	if outgoing {
		for range segments {
			b.recent = append(b.recent, now)
		}
	}
	return nil
}

func (b *wireBudget) frameCost(p gopacket.Packet, ip *layers.IPv4, tcp *layers.TCP, length int, gso wireGSO) (int, int, error) {
	if gso == (wireGSO{}) {
		if b.maxFrameLength > 0 && length > b.maxFrameLength {
			return 0, 0, fmt.Errorf("wire budget: matching frame exceeds interface MTU allowance (%d > %d bytes) without TCP segmentation metadata", length, b.maxFrameLength)
		}
		return 1, length, nil
	}
	payload := len(tcp.Payload)
	headers := len(p.LinkLayer().LayerContents()) + len(ip.Contents) + len(tcp.Contents)
	if vlan := p.Layer(layers.LayerTypeDot1Q); vlan != nil {
		headers += len(vlan.LayerContents())
	}
	if gso.kind&^unix.VIRTIO_NET_HDR_GSO_ECN != unix.VIRTIO_NET_HDR_GSO_TCPV4 ||
		gso.payloadSize <= 0 || payload == 0 || headers+payload != length || tcp.SYN || tcp.RST || tcp.URG {
		return 0, 0, fmt.Errorf("wire budget: cannot account for IPv4 TCP offload record (type %#x, segment payload %d, frame %d bytes)", gso.kind, gso.payloadSize, length)
	}
	if segmentLength := headers + min(gso.payloadSize, payload); b.maxFrameLength > 0 && segmentLength > b.maxFrameLength {
		return 0, 0, fmt.Errorf("wire budget: matching frame exceeds interface MTU allowance: offload segment is %d bytes, limit is %d", segmentLength, b.maxFrameLength)
	}
	segments := (payload-1)/gso.payloadSize + 1
	const minEthernetFrame = 60 // Ethernet header and padding, without FCS.
	lastPayload := payload - (segments-1)*gso.payloadSize
	octets := (segments-1)*max(minEthernetFrame, headers+gso.payloadSize) + max(minEthernetFrame, headers+lastPayload)
	return segments, octets, nil
}

// observeOutgoing detects overlapping TCP sequence space for data and FIN.
// Capture duplicates can conservatively stop a series as if retransmitted.
func (b *wireBudget) observeOutgoing(ip *layers.IPv4, tcp *layers.TCP) error {
	var key flowKey
	copy(key.src[:], ip.SrcIP.To4())
	key.port = tcp.SrcPort
	flow := b.flows[key]
	if flow == nil {
		flow = &flowState{}
		b.flows[key] = flow
	}
	if tcp.SYN && !tcp.ACK {
		if flow.synSeen && flow.synSeq != tcp.Seq {
			flow.ranges = nil
		}
		flow.synSeen, flow.synSeq = true, tcp.Seq
	}
	length := uint32(len(tcp.Payload))
	if tcp.FIN {
		length++
	}
	if length == 0 {
		return nil
	}
	start := tcp.Seq
	if tcp.SYN {
		start++
	}
	for _, previous := range flow.ranges {
		if int32(start-previous.start) < int32(previous.length) && int32(previous.start-start) < int32(length) {
			return fmt.Errorf("wire budget: outgoing data or FIN retransmission detected")
		}
	}
	flow.ranges = append(flow.ranges, sequenceRange{start: start, length: length})
	return nil
}

// wireStopThreshold leaves at least 10% headroom for frames already in
// flight; asynchronous capture cannot guarantee that this headroom suffices.
func wireStopThreshold(limit int) int {
	if limit <= 1 {
		return limit
	}
	reserve := limit / 10
	if limit%10 != 0 {
		reserve++
	}
	return limit - reserve
}
