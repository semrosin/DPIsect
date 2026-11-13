package runner

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// wireBudget belongs to one capture reader; it must not be shared by writers.
// Counts describe observed Ethernet frames, not a guarantee of physical-wire
// packets when capture loses data or interface offloads are active.
type wireBudget struct {
	ip                 net.IP
	port               layers.TCPPort
	limits             Budget
	packets            int
	bytes              int
	recent             []time.Time
	lastMatching       bool
	maxFrameLength     int
	synSeen            map[synKey]int
	synRetransmissions int
}

type synKey struct {
	src  [4]byte
	port layers.TCPPort
	seq  uint32
}

func newWireBudget(ip string, port int, limits Budget) (*wireBudget, error) {
	addr := net.ParseIP(ip).To4()
	if addr == nil || port < 1 || port > 65535 || limits.MaxPackets <= 0 || limits.MaxBytes <= 0 || limits.MaxRatePPS <= 0 {
		return nil, fmt.Errorf("invalid wire budget or IPv4 endpoint")
	}
	if limits.MaxSYNRetransmissions != nil && *limits.MaxSYNRetransmissions <= 0 {
		return nil, fmt.Errorf("invalid SYN retransmission limit")
	}
	return &wireBudget{ip: addr, port: layers.TCPPort(port), limits: limits, synSeen: make(map[synKey]int)}, nil
}

// observe returns an error once an observed limit is reached or the frame
// cannot be accounted for. An asynchronous capture cannot prevent an already
// transmitted packet or guarantee that every frame was observed.
func (b *wireBudget) observe(frame []byte, originalLength int, now time.Time) error {
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
	b.packets++
	b.bytes += originalLength
	if len(b.recent) > 0 && now.Before(b.recent[len(b.recent)-1]) {
		return fmt.Errorf("wire budget: capture timestamps are out of order")
	}
	if b.maxFrameLength > 0 && originalLength > b.maxFrameLength {
		return fmt.Errorf("wire budget: matching frame exceeds interface MTU allowance; offload may obscure packet counts")
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
	b.recent = append(b.recent[:keep], now)
	if b.packets >= wireStopThreshold(b.limits.MaxPackets) || b.bytes >= wireStopThreshold(b.limits.MaxBytes) || len(b.recent) >= wireStopThreshold(b.limits.MaxRatePPS) {
		return fmt.Errorf("wire budget: observed limit reached (%d packets, %d bytes, %d packets in one second)", b.packets, b.bytes, len(b.recent))
	}
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
