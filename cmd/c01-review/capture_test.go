package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var (
	testClient = netip.MustParseAddrPort("192.0.2.1:40000")
	testServer = netip.MustParseAddrPort("192.0.2.2:443")
)

type testFrame struct {
	seq      uint32
	flags    layers.IPv4Flag
	syn      bool
	rst      bool
	incoming bool
	payload  string
}

func makeCapture(t *testing.T, frames []testFrame) []byte {
	t.Helper()
	var capture bytes.Buffer
	writer := pcapgo.NewWriter(&capture)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	eth := &layers.Ethernet{
		SrcMAC: []byte{2, 0, 0, 0, 0, 1}, DstMAC: []byte{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	for i, frame := range frames {
		src, dst := testClient, testServer
		if frame.incoming {
			src, dst = dst, src
		}
		ip := &layers.IPv4{
			Version: 4, SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice(),
			TTL: 64, Protocol: layers.IPProtocolTCP, Flags: frame.flags,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(src.Port()), DstPort: layers.TCPPort(dst.Port()),
			Seq: frame.seq, SYN: frame.syn, ACK: !frame.syn, RST: frame.rst,
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, eth, ip, tcp, gopacket.Payload(frame.payload)); err != nil {
			t.Fatal(err)
		}
		n := len(buffer.Bytes())
		info := gopacket.CaptureInfo{Timestamp: time.Unix(int64(i), 0), CaptureLength: n, Length: n}
		if err := writer.WritePacket(info, buffer.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	return capture.Bytes()
}

func TestC01InspectCapture(t *testing.T) {
	t.Parallel()
	syn := testFrame{seq: 0xfffffffd, syn: true}
	first := testFrame{seq: 0xfffffffe, payload: "ab"}
	second := testFrame{seq: 0, payload: "cd"}
	ack := testFrame{incoming: true}
	reset := testFrame{incoming: true, rst: true}
	reply := testFrame{incoming: true, payload: "reply"}
	for _, tc := range []struct {
		name   string
		frames []testFrame
		err    string
	}{
		{name: "C01_in_order_with_repeat", frames: []testFrame{syn, first, second, ack, reply, reset, second, ack}},
		{name: "C01_reversed_capture_order", frames: []testFrame{syn, second, first}},
		{name: "C01_gap", frames: []testFrame{syn, second}, err: "missing ClientHello bytes=2"},
		{name: "C01_mismatched_bytes", frames: []testFrame{syn, first, {seq: 0, payload: "xy"}}, err: "ClientHello bytes differ"},
		{name: "C01_mixed_overlap", frames: []testFrame{syn, first, {seq: 0xffffffff, payload: "bcd"}}, err: "mixed new and repeated"},
		{name: "C01_no_syn", frames: []testFrame{first, second}, err: "does not start with client SYN"},
		{name: "C01_tuple_reuse", frames: []testFrame{syn, first, second, {seq: 9, syn: true}}, err: "reuse of TCP tuple"},
		{name: "C01_ip_fragment", frames: []testFrame{syn, {seq: 0xfffffffe, flags: layers.IPv4MoreFragments, payload: "ab"}, second}, err: "fragmented IPv4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := inspectCapture(bytes.NewReader(makeCapture(t, tc.frames)), testClient, testServer, []byte("abcd"))
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(result.TCPSplitOffsets) != 1 || result.TCPSplitOffsets[0] != 2 || len(result.FirstSeen) != 2 {
				t.Fatalf("unexpected boundaries: %+v", result)
			}
			if tc.frames[1] == second && result.FirstSeen[0].Offset != 2 {
				t.Fatalf("capture order lost: %+v", result.FirstSeen)
			}
			if tc.frames[1] == first && (result.FirstRepeat == nil || result.FirstRepeat.Frame != 7 ||
				result.RepeatedRanges != 1 || result.IncomingAfterHello != 4 || result.IncomingBeforeRepeat != 3 ||
				result.IncomingPayloadBeforeRepeat != 1 || result.IncomingACKOnlyBeforeRepeat != 1 || result.IncomingRSTBeforeRepeat != 1) {
				t.Fatalf("unexpected observations: %+v", result)
			}
		})
	}
}

func TestC01RejectsMultipleCaptureInterfaces(t *testing.T) {
	t.Parallel()
	classic := makeCapture(t, []testFrame{
		{seq: 100, syn: true}, {seq: 101, payload: "abcd"},
	})
	reader, err := pcapgo.NewReader(bytes.NewReader(classic))
	if err != nil {
		t.Fatal(err)
	}
	var capture bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&capture, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	index, err := writer.AddInterface(pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: 65535})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		frame, info, err := reader.ReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			info.InterfaceIndex = index
		}
		if err := writer.WritePacket(info, frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	_, err = inspectCapture(&capture, testClient, testServer, []byte("abcd"))
	if err == nil || !strings.Contains(err.Error(), "one interface") {
		t.Fatalf("error = %v, want multiple interface error", err)
	}
}
