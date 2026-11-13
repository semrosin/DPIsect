package runner

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func testTCPFrame(t *testing.T, src, dst string, sport, dport uint16) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: true}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestWireBudgetCountsBothDirectionsAndRetransmissions(t *testing.T) {
	t.Parallel()

	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 4, MaxBytes: 10000, MaxRatePPS: 10})
	if err != nil {
		t.Fatal(err)
	}
	out := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	in := testTCPFrame(t, "192.0.2.10", "192.0.2.1", 443, 50000)
	unrelated := testTCPFrame(t, "192.0.2.1", "192.0.2.11", 50000, 443)
	now := time.Unix(100, 0)
	for _, frame := range [][]byte{unrelated, out, in} {
		if err := budget.observe(frame, len(frame), now); err != nil {
			t.Fatalf("observe before limit: %v", err)
		}
	}
	if budget.packets != 2 || budget.bytes != len(out)+len(in) {
		t.Fatalf("counts = %d packets, %d bytes", budget.packets, budget.bytes)
	}
	if err := budget.observe(out, len(out), now); err == nil {
		t.Fatal("third matching packet must reach the limit")
	}
}

func TestWireBudgetStopsOnRateBytesAndIncompleteCapture(t *testing.T) {
	t.Parallel()

	frame := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	now := time.Unix(100, 0)
	t.Run("bytes", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: len(frame), MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now); err == nil {
			t.Fatal("packet reaching byte limit must stop the series")
		}
	})
	t.Run("rate", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: 10000, MaxRatePPS: 3})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now); err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now.Add(time.Millisecond)); err == nil {
			t.Fatal("second packet within a second must reach the rate limit")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: 10000, MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame)+1, now); err == nil {
			t.Fatal("truncated capture must stop the series")
		}
	})
	t.Run("oversize frame", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: 10000, MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		budget.maxFrameLength = len(frame) - 1
		if err := budget.observe(frame, len(frame), now); err == nil {
			t.Fatal("frame above MTU allowance must stop the series")
		}
	})
	t.Run("nonmonotonic timestamps", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now); err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now.Add(-time.Millisecond)); err == nil {
			t.Fatal("out-of-order timestamps cannot provide a reliable rate")
		}
	})
}
