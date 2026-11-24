//go:build linux

package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"

	"github.com/semrosin/DPIsect/internal/generator"
)

// rawFlowTracker derives the live TCP sequence space from the
// handshake on the capture interface. TCP_INFO in the pinned x/sys
// version has no snd_nxt/rcv_nxt, so the SYN and SYN-ACK are the
// authoritative source (D02, D03).
type rawFlowTracker struct {
	src          *afpacket.TPacket
	endpointIP   net.IP
	endpointPort int

	localIP   net.IP
	localPort int
	started   bool
	result    chan rawFlowResult
	stop      chan struct{}
	closeOnce sync.Once
}

type rawFlowResult struct {
	flow generator.RawFlow
	err  error
}

func newRawFlowTracker(iface string, endpointIP net.IP, endpointPort int) (*rawFlowTracker, error) {
	if iface == "" {
		return nil, errors.New("raw flow tracker: capture interface is required")
	}
	src, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptPollTimeout(200*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("raw flow tracker: open %s: %w", iface, err)
	}
	return &rawFlowTracker{
		src:          src,
		endpointIP:   endpointIP.To4(),
		endpointPort: endpointPort,
		result:       make(chan rawFlowResult, 1),
		stop:         make(chan struct{}),
	}, nil
}

// Start begins reading the capture ring. The source must be opened
// before dialing so the SYN is already buffered when the local port is
// known.
func (t *rawFlowTracker) Start(localIP net.IP, localPort int) {
	if t.started {
		return
	}
	t.started = true
	t.localIP = localIP.To4()
	t.localPort = localPort
	go t.run()
}

func (t *rawFlowTracker) run() {
	var (
		clientISN    uint32
		clientWindow uint16
		haveClient   bool
	)
	for {
		select {
		case <-t.stop:
			return
		default:
		}
		data, _, err := t.src.ReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			select {
			case <-t.stop:
				return
			default:
			}
			t.result <- rawFlowResult{err: fmt.Errorf("raw flow tracker: read: %w", err)}
			return
		}
		ip, tcp, ok := parseRawIPv4TCP(data)
		if !ok || t.localIP == nil {
			continue
		}

		fromClient := ip.SrcIP.Equal(t.localIP) &&
			tcp.SrcPort == layers.TCPPort(t.localPort) &&
			ip.DstIP.Equal(t.endpointIP) &&
			tcp.DstPort == layers.TCPPort(t.endpointPort)
		if fromClient && tcp.SYN && !tcp.ACK {
			clientISN = tcp.Seq
			clientWindow = tcp.Window
			haveClient = true
			continue
		}

		fromServer := ip.SrcIP.Equal(t.endpointIP) &&
			tcp.SrcPort == layers.TCPPort(t.endpointPort) &&
			ip.DstIP.Equal(t.localIP) &&
			tcp.DstPort == layers.TCPPort(t.localPort)
		if !fromServer || !tcp.SYN || !tcp.ACK {
			continue
		}

		sndNxt := tcp.Ack
		if haveClient {
			sndNxt = clientISN + 1
		}
		t.result <- rawFlowResult{flow: generator.RawFlow{
			SrcIP:   append(net.IP(nil), t.localIP...),
			DstIP:   append(net.IP(nil), t.endpointIP...),
			SrcPort: uint16(t.localPort),
			DstPort: uint16(t.endpointPort),
			SndNxt:  sndNxt,
			RcvNxt:  tcp.Seq + 1,
			Window:  clientWindow,
		}}
		return
	}
}

// Wait returns the handshake flow or a bounded error.
func (t *rawFlowTracker) Wait(ctx context.Context) (generator.RawFlow, error) {
	select {
	case <-ctx.Done():
		return generator.RawFlow{}, fmt.Errorf("raw flow tracker: %w", ctx.Err())
	case res := <-t.result:
		return res.flow, res.err
	}
}

// Close stops the reader and releases the AF_PACKET socket.
func (t *rawFlowTracker) Close() {
	t.closeOnce.Do(func() {
		close(t.stop)
		t.src.Close()
	})
}

func parseRawIPv4TCP(frame []byte) (*layers.IPv4, *layers.TCP, bool) {
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok || ip == nil {
		return nil, nil, false
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || tcp == nil {
		return nil, nil, false
	}
	return ip, tcp, true
}
