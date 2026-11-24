package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/semrosin/DPIsect/internal/tlsparse"
)

const (
	maxBrowserCapture = 64 << 20
	maxBrowserFlows   = 4096
	maxBrowserMatches = 256
)

type browserReport struct {
	CaptureSHA256 string         `json:"capture_sha256"`
	Trials        []browserTrial `json:"trials"`
}

type browserTrial struct {
	review
	SNIStart *int `json:"sni_start,omitempty"`
	SNIEnd   *int `json:"sni_end,omitempty"`
}

type browserFlow struct {
	client, server netip.AddrPort
}

type browserCandidate struct {
	base  uint32
	bytes []byte
}

type browserHello struct {
	flow   browserFlow
	record []byte
}

func reviewBrowser(path, sni string) (browserReport, error) {
	var result browserReport
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBrowserCapture+1))
	if err != nil {
		return result, fmt.Errorf("read browser capture: %w", err)
	}
	if len(data) > maxBrowserCapture {
		return result, errors.New("browser capture exceeds 64 MiB")
	}
	matches, err := findBrowserHellos(bytes.NewReader(data), sni)
	if err != nil {
		return result, err
	}
	result.CaptureSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	result.Trials = make([]browserTrial, 0, len(matches))
	for _, match := range matches {
		r, err := inspectCapture(bytes.NewReader(data), match.flow.client, match.flow.server, match.record)
		if err != nil {
			return result, fmt.Errorf("%s to %s: %w", match.flow.client, match.flow.server, err)
		}
		r.SNI = sni
		r.Client, r.Server = match.flow.client, match.flow.server
		r.CaptureSHA256 = result.CaptureSHA256
		r.HelloSHA256 = fmt.Sprintf("%x", sha256.Sum256(match.record))
		r.TLSRecordEnds = []int{len(match.record)}
		trial := browserTrial{review: r}
		// The parser proved the name in the SNI extension. A unique byte
		// occurrence gives its offset without guessing between duplicates.
		if name := []byte(sni); bytes.Count(match.record, name) == 1 {
			start := bytes.Index(match.record, name)
			end := start + len(name)
			trial.SNIStart, trial.SNIEnd = &start, &end
		}
		result.Trials = append(result.Trials, trial)
	}
	return result, nil
}

func findBrowserHellos(input io.Reader, sni string) ([]browserHello, error) {
	reader, err := ethernetCapture(input)
	if err != nil {
		return nil, err
	}
	pending := make(map[browserFlow]*browserCandidate)
	var matches []browserHello
	var iface int
	for number := 1; ; number++ {
		data, info, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return matches, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read frame %d: %w", number, err)
		}
		if number == 1 {
			iface = info.InterfaceIndex
		} else if iface != info.InterfaceIndex {
			return nil, errors.New("browser review requires a capture from one interface")
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || ip.Protocol != layers.IPProtocolTCP || ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			continue
		}
		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok || tcp.DstPort != 443 {
			continue
		}
		src, _ := netip.AddrFromSlice(ip.SrcIP)
		dst, _ := netip.AddrFromSlice(ip.DstIP)
		flow := browserFlow{netip.AddrPortFrom(src.Unmap(), uint16(tcp.SrcPort)), netip.AddrPortFrom(dst.Unmap(), uint16(tcp.DstPort))}
		if info.Length != info.CaptureLength || packet.Metadata().Truncated {
			delete(pending, flow)
			continue
		}
		if tcp.SYN && !tcp.ACK && len(tcp.Payload) == 0 {
			if pending[flow] == nil {
				if len(pending) == maxBrowserFlows {
					return nil, errors.New("too many incomplete browser flows")
				}
				pending[flow] = &browserCandidate{base: tcp.Seq + 1}
			}
			continue
		}
		c := pending[flow]
		if c == nil {
			continue
		}
		if tcp.FIN || tcp.RST {
			delete(pending, flow)
			continue
		}
		if len(tcp.Payload) == 0 {
			continue
		}
		if int32(tcp.Seq-c.base) != int32(len(c.bytes)) {
			delete(pending, flow)
			continue
		}
		available := min(len(tcp.Payload), 5+tlsparse.MaxRecordPayload-len(c.bytes))
		c.bytes = append(c.bytes, tcp.Payload[:available]...)
		if len(c.bytes) < 5 {
			continue
		}
		end := 5 + int(binary.BigEndian.Uint16(c.bytes[3:5]))
		if c.bytes[0] != tlsparse.TypeHandshake || c.bytes[1] != 3 || end > 5+tlsparse.MaxRecordPayload {
			delete(pending, flow)
			continue
		}
		if len(c.bytes) < end {
			continue
		}
		delete(pending, flow)
		record := c.bytes[:end]
		message := record[5:]
		if len(message) < 4 || int(message[1])<<16|int(message[2])<<8|int(message[3]) != len(message)-4 {
			continue
		}
		hello, err := tlsparse.ParseClientHello(message)
		if err == nil && hello.SNI == sni {
			if len(matches) == maxBrowserMatches {
				return nil, errors.New("too many browser matches")
			}
			matches = append(matches, browserHello{flow: flow, record: record})
		}
	}
}
