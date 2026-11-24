package runner

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func testTCPFrame(t *testing.T, src, dst string, sport, dport uint16) []byte {
	t.Helper()
	return testTCPFrameWithSeq(t, src, dst, sport, dport, 0)
}

func testTCPFrameWithSeq(t *testing.T, src, dst string, sport, dport uint16, seq uint32) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP(src).To4(), DstIP: net.ParseIP(dst).To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: true, Seq: seq}
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

func testTCPDataFrame(t *testing.T, sport uint16, seq uint32, payload []byte, fin bool) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("192.0.2.10").To4()}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: 443, ACK: true, FIN: fin, Seq: seq}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		&layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestWireBudgetStopsOnDataAndFINRetransmissions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                string
		firstSeq, secondSeq uint32
		first, second       []byte
		firstFIN, secondFIN bool
	}{
		{"data", 100, 100, []byte("abcd"), []byte("abcd"), false, false},
		{"partial overlap", 100, 102, []byte("abcd"), []byte("cdef"), false, false},
		{"FIN", 104, 104, nil, nil, true, true},
		{"wraparound", ^uint32(0) - 1, 0, []byte("abcd"), []byte("cd"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10})
			if err != nil {
				t.Fatal(err)
			}
			first := testTCPDataFrame(t, 50000, tc.firstSeq, tc.first, tc.firstFIN)
			second := testTCPDataFrame(t, 50000, tc.secondSeq, tc.second, tc.secondFIN)
			now := time.Unix(100, 0)
			if err := budget.observe(first, len(first), now, wireGSO{}); err != nil {
				t.Fatal(err)
			}
			if err := budget.observe(second, len(second), now.Add(time.Millisecond), wireGSO{}); err == nil || !strings.Contains(err.Error(), "retransmission") {
				t.Fatalf("repeated sequence error = %v", err)
			}
		})
	}
}

func TestWireBudgetAllowsNewDataAndPureACKs(t *testing.T) {
	t.Parallel()
	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10})
	if err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		testTCPDataFrame(t, 50000, 100, []byte("abcd"), false),
		testTCPDataFrame(t, 50000, 104, []byte("ef"), false),
		testTCPDataFrame(t, 50001, 100, []byte("abcd"), false),
		testTCPDataFrame(t, 50000, 106, nil, false),
		testTCPDataFrame(t, 50000, 106, nil, false),
	}
	for _, frame := range frames {
		if err := budget.observe(frame, len(frame), time.Unix(100, 0), wireGSO{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWireBudgetStartsNewFlowWhenPortIsReused(t *testing.T) {
	t.Parallel()
	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10})
	if err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{
		testTCPFrameWithSeq(t, "192.0.2.1", "192.0.2.10", 50000, 443, 99),
		testTCPDataFrame(t, 50000, 100, []byte("abcd"), false),
		testTCPFrameWithSeq(t, "192.0.2.1", "192.0.2.10", 50000, 443, 199),
		testTCPDataFrame(t, 50000, 100, []byte("abcd"), false),
	}
	for _, frame := range frames {
		if err := budget.observe(frame, len(frame), time.Unix(100, 0), wireGSO{}); err != nil {
			t.Fatalf("new connection on reused port: %v", err)
		}
	}
}

func TestWireBudgetStopsOnPlannedSYNRetry(t *testing.T) {
	t.Parallel()

	limit := 1
	budget, err := newWireBudget("192.0.2.10", 443, Budget{
		MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10, MaxSYNRetransmissions: &limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	other := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50001, 443)
	newSequence := testTCPFrameWithSeq(t, "192.0.2.1", "192.0.2.10", 50000, 443, 12345)
	inbound := testTCPFrame(t, "192.0.2.10", "192.0.2.1", 443, 50000)
	now := time.Unix(100, 0)
	for _, frame := range [][]byte{first, other, newSequence, inbound} {
		if err := budget.observe(frame, len(frame), now, wireGSO{}); err != nil {
			t.Fatalf("first SYNs and inbound traffic must not count as retries: %v", err)
		}
	}
	err = budget.observe(first, len(first), now.Add(time.Second), wireGSO{})
	if err == nil || !strings.Contains(err.Error(), "SYN retransmission") {
		t.Fatalf("repeated SYN error = %v, want retransmission stop", err)
	}
	if budget.synRetransmissions != 1 {
		t.Fatalf("SYN retransmissions = %d, want 1", budget.synRetransmissions)
	}
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
		if err := budget.observe(frame, len(frame), now, wireGSO{}); err != nil {
			t.Fatalf("observe before limit: %v", err)
		}
	}
	if budget.packets != 2 || budget.bytes != len(out)+len(in) {
		t.Fatalf("counts = %d packets, %d bytes", budget.packets, budget.bytes)
	}
	if err := budget.observe(out, len(out), now, wireGSO{}); err == nil {
		t.Fatal("third matching packet must reach the limit")
	}
}

func TestWireBudgetRateCountsOutgoingOnly(t *testing.T) {
	t.Parallel()

	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 3})
	if err != nil {
		t.Fatal(err)
	}
	out := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	in := testTCPFrame(t, "192.0.2.10", "192.0.2.1", 443, 50000)
	now := time.Unix(100, 0)
	for _, frame := range [][]byte{out, in, in, in} {
		if err := budget.observe(frame, len(frame), now, wireGSO{}); err != nil {
			t.Fatalf("incoming packets must not consume the outbound rate budget: %v", err)
		}
	}
	if budget.packets != 4 || budget.bytes != len(out)+3*len(in) {
		t.Fatalf("total budget must include both directions: %d packets, %d bytes", budget.packets, budget.bytes)
	}
	if err := budget.observe(out, len(out), now.Add(time.Millisecond), wireGSO{}); err == nil {
		t.Fatal("second outbound packet must reach the rate threshold")
	}
}

func TestWireBudgetRejectsOutOfOrderInboundFrames(t *testing.T) {
	t.Parallel()

	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10})
	if err != nil {
		t.Fatal(err)
	}
	in := testTCPFrame(t, "192.0.2.10", "192.0.2.1", 443, 50000)
	now := time.Unix(100, 0)
	if err := budget.observe(in, len(in), now, wireGSO{}); err != nil {
		t.Fatal(err)
	}
	if err := budget.observe(in, len(in), now.Add(-time.Millisecond), wireGSO{}); err == nil {
		t.Fatal("out-of-order incoming timestamps must stop accounting")
	}
}

func TestWireBudgetOutboundRateUsesSlidingSecond(t *testing.T) {
	t.Parallel()

	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 3})
	if err != nil {
		t.Fatal(err)
	}
	out := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	in := testTCPFrame(t, "192.0.2.10", "192.0.2.1", 443, 50000)
	now := time.Unix(100, 0)
	for _, trial := range []struct {
		frame []byte
		at    time.Time
	}{{out, now}, {in, now.Add(time.Millisecond)}, {out, now.Add(time.Second)}} {
		if err := budget.observe(trial.frame, len(trial.frame), trial.at, wireGSO{}); err != nil {
			t.Fatalf("expired outgoing packet should not consume the current second: %v", err)
		}
	}
	if err := budget.observe(out, len(out), now.Add(time.Second+time.Millisecond), wireGSO{}); err == nil {
		t.Fatal("two outgoing packets in the current second must reach the rate threshold")
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
		if err := budget.observe(frame, len(frame), now, wireGSO{}); err == nil {
			t.Fatal("packet reaching byte limit must stop the series")
		}
	})
	t.Run("incoming bytes", func(t *testing.T) {
		in := testTCPFrame(t, "192.0.2.10", "192.0.2.1", 443, 50000)
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: len(in), MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(in, len(in), now, wireGSO{}); err == nil {
			t.Fatal("incoming packet reaching byte limit must stop the series")
		}
	})
	t.Run("rate", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: 10000, MaxRatePPS: 3})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now, wireGSO{}); err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now.Add(time.Millisecond), wireGSO{}); err == nil {
			t.Fatal("second packet within a second must reach the rate limit")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: 10000, MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame)+1, now, wireGSO{}); err == nil {
			t.Fatal("truncated capture must stop the series")
		}
	})
	t.Run("oversize frame", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: 10000, MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		budget.maxFrameLength = len(frame) - 1
		if err := budget.observe(frame, len(frame), now, wireGSO{}); err == nil {
			t.Fatal("frame above MTU allowance must stop the series")
		}
	})
	t.Run("nonmonotonic timestamps", func(t *testing.T) {
		budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10})
		if err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now, wireGSO{}); err != nil {
			t.Fatal(err)
		}
		if err := budget.observe(frame, len(frame), now.Add(-time.Millisecond), wireGSO{}); err == nil {
			t.Fatal("out-of-order timestamps cannot provide a reliable rate")
		}
	})
}

func TestWireBudgetAccountsForTCPv4Offload(t *testing.T) {
	t.Parallel()
	const mtuAllowance = 1298
	const payloadSize = 2500
	const headers = 14 + 20 + 20
	frame := testTCPDataFrame(t, 50000, 1, make([]byte, payloadSize), false)
	valid := wireGSO{kind: unix.VIRTIO_NET_HDR_GSO_TCPV4 | unix.VIRTIO_NET_HDR_GSO_ECN, payloadSize: 1220}

	for _, tc := range []struct {
		name         string
		gso          wireGSO
		limit        Budget
		wantError    string
		wantSegments int
	}{
		{"counts all segments", valid, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10}, "", 3},
		{"packet limit", valid, Budget{MaxPackets: 3, MaxBytes: 10000, MaxRatePPS: 10}, "observed limit", 3},
		{"byte limit includes repeated headers", valid, Budget{MaxPackets: 100, MaxBytes: 2900, MaxRatePPS: 10}, "observed limit", 3},
		{"outgoing rate", valid, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 3}, "3 outgoing packets", 3},
		{"no metadata", wireGSO{}, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10}, "without TCP segmentation metadata", 0},
		{"wrong protocol", wireGSO{kind: unix.VIRTIO_NET_HDR_GSO_TCPV6, payloadSize: 1220}, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10}, "cannot account", 0},
		{"oversized segment", wireGSO{kind: unix.VIRTIO_NET_HDR_GSO_TCPV4, payloadSize: 1500}, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10}, "offload segment", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget, err := newWireBudget("192.0.2.10", 443, tc.limit)
			if err != nil {
				t.Fatal(err)
			}
			budget.maxFrameLength = mtuAllowance
			now := time.Unix(100, 0)
			err = budget.observe(frame, len(frame), now, tc.gso)
			if tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("observe = %v, want error %q", err, tc.wantError)
			}
			wantBytes := 0
			if tc.wantSegments != 0 {
				wantBytes = payloadSize + tc.wantSegments*headers
			}
			if budget.packets != tc.wantSegments || budget.bytes != wantBytes {
				t.Fatalf("charged %d packets and %d bytes, want %d packets and %d bytes",
					budget.packets, budget.bytes, tc.wantSegments, wantBytes)
			}
			if tc.wantError == "" {
				if err := budget.observe(frame, len(frame), now.Add(time.Millisecond), tc.gso); err == nil || !strings.Contains(err.Error(), "retransmission") {
					t.Fatalf("overlapping offload record = %v, want retransmission stop", err)
				}
			}
		})
	}
}
