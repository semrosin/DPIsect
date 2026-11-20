package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type segment struct {
	Frame       int `json:"frame"`
	Offset      int `json:"offset"`
	HelloBytes  int `json:"client_hello_bytes"`
	PayloadSize int `json:"tcp_payload_bytes"`
}

type review struct {
	Trial                       int            `json:"trial"`
	Client                      netip.AddrPort `json:"client"`
	Server                      netip.AddrPort `json:"server"`
	PlanSHA256                  string         `json:"plan_sha256"`
	CaptureSHA256               string         `json:"capture_sha256"`
	HelloSHA256                 string         `json:"client_hello_sha256"`
	TLSRecordEnds               []int          `json:"tls_record_ends"`
	TCPSplitOffsets             []int          `json:"tcp_split_offsets"`
	SplitOffsetsMatch           *bool          `json:"planned_tcp_split_offsets_match,omitempty"`
	FirstSeen                   []segment      `json:"first_seen_segments_in_capture_order"`
	FirstRepeat                 *segment       `json:"first_repeated_client_hello_range,omitempty"`
	RepeatedRanges              int            `json:"repeated_client_hello_ranges"`
	IncomingAfterHello          int            `json:"incoming_frames_after_complete_hello"`
	IncomingBeforeRepeat        int            `json:"incoming_frames_after_complete_hello_before_first_repeat"`
	IncomingPayloadBeforeRepeat int            `json:"incoming_payload_frames_after_complete_hello_before_first_repeat"`
}

func inspectCapture(input io.Reader, client, server netip.AddrPort, planned []byte) (review, error) {
	result := review{TCPSplitOffsets: []int{}}
	reader, err := pcapgo.NewReader(input)
	if err != nil {
		return result, err
	}
	if reader.LinkType() != layers.LinkTypeEthernet {
		return result, errors.New("expected Ethernet PCAP")
	}
	seen := make([]bool, len(planned))
	var base uint32
	var haveSYN bool
	remaining := len(planned)
	for number := 1; ; number++ {
		data, info, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, fmt.Errorf("read frame %d: %w", number, err)
		}
		tcp, incoming, err := flowPacket(data, info, client, server)
		if err != nil {
			return result, fmt.Errorf("frame %d: %w", number, err)
		}
		if tcp == nil {
			continue
		}
		if !incoming && tcp.SYN && !tcp.ACK {
			if len(tcp.Payload) != 0 || haveSYN && (base != tcp.Seq+1 || remaining != len(planned)) {
				return result, fmt.Errorf("frame %d: data in SYN or ambiguous reuse of TCP tuple", number)
			}
			haveSYN, base = true, tcp.Seq+1
			continue
		}
		if !haveSYN {
			return result, fmt.Errorf("frame %d: selected flow does not start with client SYN", number)
		}
		if incoming {
			if remaining == 0 {
				result.IncomingAfterHello++
				if result.FirstRepeat == nil {
					result.IncomingBeforeRepeat++
					if len(tcp.Payload) > 0 {
						result.IncomingPayloadBeforeRepeat++
					}
				}
			}
			continue
		}
		if len(tcp.Payload) == 0 {
			continue
		}
		// Subtract the SYN-derived base in TCP sequence space, including wrap-around.
		offset := int(int32(tcp.Seq - base))
		if offset < 0 {
			return result, fmt.Errorf("frame %d: payload starts before client stream", number)
		}
		if offset >= len(planned) {
			continue
		}
		overlap := min(len(tcp.Payload), len(planned)-offset)
		if !bytes.Equal(planned[offset:offset+overlap], tcp.Payload[:overlap]) {
			return result, fmt.Errorf("frame %d: ClientHello bytes differ at TCP range [%d,%d)", number, offset, offset+overlap)
		}
		observed := segment{Frame: number, Offset: offset, HelloBytes: overlap, PayloadSize: len(tcp.Payload)}
		coverage := seen[offset : offset+overlap]
		if !slices.Contains(coverage, false) {
			result.RepeatedRanges++
			if result.FirstRepeat == nil {
				result.FirstRepeat = &observed
			}
			continue
		}
		if slices.Contains(coverage, true) {
			return result, fmt.Errorf("frame %d: mixed new and repeated ClientHello bytes", number)
		}
		for i := range coverage {
			coverage[i] = true
		}
		remaining -= overlap
		result.FirstSeen = append(result.FirstSeen, observed)
		if offset > 0 {
			result.TCPSplitOffsets = append(result.TCPSplitOffsets, offset)
		}
	}
	if !haveSYN || remaining != 0 {
		return result, fmt.Errorf("incomplete capture: client SYN observed=%t, missing ClientHello bytes=%d", haveSYN, remaining)
	}
	slices.Sort(result.TCPSplitOffsets)
	return result, nil
}

func flowPacket(data []byte, info gopacket.CaptureInfo, client, server netip.AddrPort) (*layers.TCP, bool, error) {
	if info.CaptureLength != info.Length {
		return nil, false, errors.New("truncated capture frame")
	}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		if packet.ErrorLayer() != nil {
			return nil, false, errors.New("cannot decode Ethernet frame")
		}
		return nil, false, nil
	}
	src, _ := netip.AddrFromSlice(ip.SrcIP)
	dst, _ := netip.AddrFromSlice(ip.DstIP)
	src, dst = src.Unmap(), dst.Unmap()
	outgoing := src == client.Addr() && dst == server.Addr()
	incoming := src == server.Addr() && dst == client.Addr()
	if (!outgoing && !incoming) || ip.Protocol != layers.IPProtocolTCP {
		return nil, false, nil
	}
	if ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
		return nil, false, errors.New("fragmented IPv4 between selected hosts")
	}
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok || packet.Metadata().Truncated {
		return nil, false, errors.New("cannot decode complete IPv4/TCP headers")
	}
	sport, dport := uint16(tcp.SrcPort), uint16(tcp.DstPort)
	if outgoing && sport == client.Port() && dport == server.Port() {
		return tcp, false, nil
	}
	if incoming && sport == server.Port() && dport == client.Port() {
		return tcp, true, nil
	}
	return nil, false, nil
}
