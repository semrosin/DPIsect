package main

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/semrosin/DPIsect/internal/tlsparse"
)

type frame struct {
	at       time.Time
	client   netip.AddrPort
	outgoing bool
	tcp      *layers.TCP
}

type evidence struct {
	SYNs        int
	SYNACK      bool
	Reset       bool
	ClientData  bool
	DataRepeat  bool
	ServerData  bool
	HelloSNI    string
	HelloBytes  int
	ServerHello bool
	Alert       *byte
}

func readCapture(path string, ip netip.Addr, trials []trial) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}
	if reader.LinkType() != layers.LinkTypeEthernet {
		return fmt.Errorf("unsupported capture link type %s", reader.LinkType())
	}

	var frames []frame
	for count := 0; ; count++ {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if count >= 100 || ci.Length != ci.CaptureLength {
			return fmt.Errorf("capture is truncated or exceeds the planned packet budget")
		}
		if packet, ok := decodeFrame(data, ci.Timestamp, ip); ok {
			frames = append(frames, packet)
		}
	}
	for i := range trials {
		trials[i].Wire, trials[i].WireNote = matchTrial(frames, trials[i])
	}
	return nil
}

func decodeFrame(data []byte, at time.Time, target netip.Addr) (frame, bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return frame{}, false
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return frame{}, false
	}
	src, _ := netip.AddrFromSlice(ip.SrcIP)
	dst, _ := netip.AddrFromSlice(ip.DstIP)
	switch {
	case dst.Unmap() == target.Unmap() && tcp.DstPort == 443:
		return frame{at, netip.AddrPortFrom(src, uint16(tcp.SrcPort)), true, tcp}, true
	case src.Unmap() == target.Unmap() && tcp.SrcPort == 443:
		return frame{at, netip.AddrPortFrom(dst, uint16(tcp.DstPort)), false, tcp}, true
	default:
		return frame{}, false
	}
}

func matchTrial(frames []frame, attempt trial) (evidence, string) {
	var start *frame
	for i := range frames {
		f := &frames[i]
		if f.at.Before(attempt.Started) || f.at.After(attempt.Finished) || !f.outgoing || !f.tcp.SYN || f.tcp.ACK {
			continue
		}
		if start != nil && (start.client != f.client || start.tcp.Seq != f.tcp.Seq) {
			return evidence{}, "В окне попытки несколько исходящих соединений к этому адресу."
		}
		if start == nil {
			start = f
		}
	}
	if start == nil {
		return evidence{}, "В окне попытки нет исходящего SYN в PCAP."
	}
	var wire evidence
	var clientParts, serverParts []*layers.TCP
	var serverSeq uint32
	for _, f := range frames {
		if f.client != start.client || f.at.Before(start.at) || f.at.After(attempt.Finished) {
			continue
		}
		tcp := f.tcp
		if f.outgoing {
			if tcp.SYN && !tcp.ACK && tcp.Seq == start.tcp.Seq {
				wire.SYNs++
			}
			if len(tcp.Payload) > 0 {
				clientParts = append(clientParts, tcp)
			}
		} else {
			if tcp.SYN && tcp.ACK && tcp.Ack == start.tcp.Seq+1 && !wire.SYNACK {
				wire.SYNACK, serverSeq = true, tcp.Seq
			}
			wire.Reset = wire.Reset || tcp.RST
			if len(tcp.Payload) > 0 {
				serverParts = append(serverParts, tcp)
			}
		}
	}

	wire.ClientData, wire.ServerData = len(clientParts) > 0, len(serverParts) > 0
	client, overlap := streamPrefix(clientParts, start.tcp.Seq+1)
	wire.DataRepeat = overlap
	rec, err := tlsparse.ReadRecord(bytes.NewReader(client))
	if err == nil && rec.Type == tlsparse.TypeHandshake {
		if hello, err := tlsparse.ParseClientHello(rec.Payload); err == nil {
			wire.HelloSNI, wire.HelloBytes = hello.SNI, 5+len(rec.Payload)
		}
	}
	if wire.SYNACK {
		data, _ := streamPrefix(serverParts, serverSeq+1)
		server := bytes.NewReader(data)
		for server.Len() > 0 {
			rec, err := tlsparse.ReadRecord(server)
			if err != nil {
				break
			}
			switch rec.Type {
			case tlsparse.TypeHandshake:
				_, err := tlsparse.ParseServerHello(rec.Payload)
				wire.ServerHello = wire.ServerHello || err == nil
			case tlsparse.TypeAlert:
				if _, desc, err := rec.Alert(); err == nil {
					wire.Alert = &desc
				}
			}
		}
	}
	if wire.HelloBytes != 0 && wire.HelloSNI != strings.TrimSuffix(attempt.SNI, ".") {
		return wire, "SNI в PCAP отличается от запланированного."
	}
	return wire, ""
}

// streamPrefix assembles the contiguous prefix, including reordered and overlapping segments.
func streamPrefix(parts []*layers.TCP, start uint32) (stream []byte, overlap bool) {
	slices.SortStableFunc(parts, func(a, b *layers.TCP) int {
		return cmp.Compare(int32(a.Seq-start), int32(b.Seq-start))
	})
	for _, part := range parts {
		offset := int(int32(part.Seq - start))
		if offset > len(stream) {
			break
		}
		previous := len(stream) - offset
		if previous > 0 && offset >= 0 {
			overlap = true
		}
		if previous < len(part.Payload) {
			stream = append(stream, part.Payload[previous:]...)
		}
	}
	return stream, overlap
}
