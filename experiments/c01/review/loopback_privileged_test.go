//go:build linux && privileged

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/semrosin/DPIsect/internal/generator"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func TestC01LoopbackSegmentation(t *testing.T) {
	const sni = "c01.example.test"
	hello, err := generator.BuildClientHello(sni, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(hello, []byte(sni)) != 1 {
		t.Fatal("fixture must contain the SNI exactly once")
	}
	start := bytes.Index(hello, []byte(sni))
	for _, tc := range []struct {
		name   string
		splits []int
	}{
		{name: "C01_unsplit"},
		{name: "C01_before_sni", splits: []int{start - 1}},
		{name: "C01_inside_sni", splits: []int{start + len(sni)/2}},
		{name: "C01_after_sni", splits: []int{start + len(sni) + 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pcap, client, server := captureLoopbackTrial(t, hello, tc.splits, true, nil)
			result, err := inspectCapture(bytes.NewReader(pcap.Bytes()), client, server, hello)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(result.TCPSplitOffsets, tc.splits) {
				t.Errorf("captured splits = %v, want %v", result.TCPSplitOffsets, tc.splits)
			}
			recordLoopbackTrial(t, pcap, hello, client, server, result)
			if result.RepeatedRanges != 0 {
				t.Errorf("captured repeated ranges = %d, want 0", result.RepeatedRanges)
			}
		})
	}
}

func captureLoopbackTrial(t *testing.T, hello []byte, splits []int, readEach bool, configure func(context.Context)) (*bytes.Buffer, netip.AddrPort, netip.AddrPort) {
	t.Helper()
	ring := openLoopbackRing(t)
	defer ring.Close()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	deadline := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	var dialer net.Dialer
	clientConn, err := dialer.DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	serverConn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	for _, conn := range []net.Conn{clientConn, serverConn} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}

	if configure != nil {
		configure(ctx)
	}
	received := make([]byte, len(hello))
	start := 0
	for _, end := range append(slices.Clone(splits), len(hello)) {
		if _, err := clientConn.Write(hello[start:end]); err != nil {
			t.Fatal(err)
		}
		if readEach {
			// The receiver consumes this range before the next write.
			if _, err := io.ReadFull(serverConn, received[start:end]); err != nil {
				t.Fatal(err)
			}
		}
		start = end
	}
	if !readEach {
		if _, err := io.ReadFull(serverConn, received); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(hello, received) {
		t.Fatal("receiver reconstructed different bytes")
	}
	// This response marks the end of the capture window for this test.
	marker := []byte{0xc1}
	if _, err := serverConn.Write(marker); err != nil {
		t.Fatal(err)
	}

	client := clientConn.LocalAddr().(*net.TCPAddr).AddrPort()
	server := serverConn.LocalAddr().(*net.TCPAddr).AddrPort()
	pcap := readLoopbackCapture(t, ring, client, server, func(tcp *layers.TCP) bool {
		return bytes.Equal(tcp.Payload, marker)
	})
	return pcap, client, server
}

func openLoopbackRing(t *testing.T) *afpacket.TPacket {
	t.Helper()
	ring, err := afpacket.NewTPacket(
		afpacket.OptInterface("lo"),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion2),
		afpacket.OptNumBlocks(1),
		afpacket.OptPollTimeout(time.Second),
	)
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("requires CAP_NET_RAW: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtType},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.PACKET_OUTGOING, SkipFalse: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: 65535},
	})
	if err != nil {
		ring.Close()
		t.Fatal(err)
	}
	if err := ring.SetBPF(filter); err != nil {
		ring.Close()
		t.Fatal(err)
	}
	return ring
}

func readLoopbackCapture(t *testing.T, ring *afpacket.TPacket, client, server netip.AddrPort, stop func(*layers.TCP) bool) *bytes.Buffer {
	t.Helper()
	var pcap bytes.Buffer
	writer := pcapgo.NewWriter(&pcap)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	for range 64 {
		data, info, err := ring.ZeroCopyReadPacketData()
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WritePacket(info, data); err != nil {
			t.Fatal(err)
		}
		tcp, incoming, err := flowPacket(data, info, client, server)
		if err != nil {
			t.Fatal(err)
		}
		if incoming && stop(tcp) {
			return &pcap
		}
	}
	t.Fatal("stop frame missing from capture")
	return nil
}

// recordLoopbackTrial optionally preserves the in-memory PCAP for a lab report.
func recordLoopbackTrial(t *testing.T, pcap *bytes.Buffer, hello []byte, client, server netip.AddrPort, result review) {
	t.Helper()
	var order []int
	for _, segment := range result.FirstSeen {
		order = append(order, segment.Offset)
	}
	t.Logf("client=%s server=%s tcp_splits=%v capture_order=%v hello_bytes=%d hello_sha256=%x", client, server, result.TCPSplitOffsets, order, len(hello), sha256.Sum256(hello))
	if directory := os.Getenv("DPISECT_LOOPBACK_ARTIFACTS"); directory != "" {
		path := filepath.Join(directory, filepath.Base(t.Name())+".pcap")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		data := pcap.Bytes()
		_, writeErr := file.Write(data)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			t.Fatal(err)
		}
		t.Logf("pcap=%s sha256=%x", path, sha256.Sum256(data))
	}
}
