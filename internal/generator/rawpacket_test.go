package generator

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func testFlow() RawFlow {
	return RawFlow{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(10, 0, 0, 2),
		SrcPort: 40000,
		DstPort: 8443,
		SndNxt:  1000,
		RcvNxt:  2000,
		Window:  65535,
	}
}

func TestBuildRawIPv4TCPFields(t *testing.T) {
	t.Parallel()

	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00}
	p := PlannedWirePacket{Payload: payload, TTL: 1, Seq: 1000, Ack: 2000}
	raw, err := BuildRawIPv4TCP(p, testFlow())
	if err != nil {
		t.Fatalf("BuildRawIPv4TCP: %v", err)
	}

	packet := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.NoCopy)
	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if ip == nil || tcp == nil {
		t.Fatal("packet did not decode as IPv4/TCP")
	}
	if ip.TTL != 1 || ip.SrcIP.String() != "10.0.0.1" || ip.DstIP.String() != "10.0.0.2" {
		t.Errorf("IP fields = %+v", ip)
	}
	if tcp.SrcPort != 40000 || tcp.DstPort != 8443 ||
		tcp.Seq != 1000 || tcp.Ack != 2000 {
		t.Errorf("TCP fields = src=%d dst=%d seq=%d ack=%d",
			tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack)
	}
	if !tcp.PSH || !tcp.ACK {
		t.Error("flags do not include PSH|ACK")
	}
	if string(tcp.Payload) != string(payload) {
		t.Errorf("payload = %x, want %x", tcp.Payload, payload)
	}
	if err := packet.ErrorLayer(); err != nil {
		t.Errorf("decode error: %v", err)
	}
}

func TestBuildRawIPv4TCPUsesFixedChecksum(t *testing.T) {
	t.Parallel()

	p := PlannedWirePacket{Payload: []byte{1}, Checksum: 0x1234}
	raw, err := BuildRawIPv4TCP(p, testFlow())
	if err != nil {
		t.Fatalf("BuildRawIPv4TCP: %v", err)
	}
	if got := uint16(raw[36])<<8 | uint16(raw[37]); got != 0x1234 {
		t.Errorf("TCP checksum = %#x, want 0x1234", got)
	}
}

func TestBuildRawIPv4TCPCorruptChecksum(t *testing.T) {
	t.Parallel()

	payload := []byte{1, 2, 3}
	correct, err := BuildRawIPv4TCP(PlannedWirePacket{Payload: payload}, testFlow())
	if err != nil {
		t.Fatalf("BuildRawIPv4TCP: %v", err)
	}
	corrupt, err := BuildRawIPv4TCP(PlannedWirePacket{
		Payload: payload, CorruptChecksum: true,
	}, testFlow())
	if err != nil {
		t.Fatalf("BuildRawIPv4TCP: %v", err)
	}
	if got, want := uint16(corrupt[36])<<8|uint16(corrupt[37]), uint16(correct[36])<<8|uint16(correct[37]); got == want {
		t.Errorf("corrupt checksum %#x equals correct %#x", got, want)
	}
}

func TestResolveRawFields(t *testing.T) {
	t.Parallel()

	seq, err := ResolveRawSequence("out_of_order", 100, 7)
	if err != nil || seq != 107 {
		t.Errorf("out_of_order = %d, %v; want 107", seq, err)
	}
	seq, err = ResolveRawSequence("old", OldSequenceOffset+5, 7)
	if err != nil || seq != 5 {
		t.Errorf("old = %d, %v; want 5", seq, err)
	}
	ack, err := ResolveRawAck("wrong", 42)
	if err != nil || ack != 43 {
		t.Errorf("wrong ack = %d, %v; want 43", ack, err)
	}
}
