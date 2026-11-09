//go:build linux && privileged

package capture

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/pcapgo"
	"os"
)

// TestLiveLoopback requires CAP_NET_RAW (docs/GO_STYLE.md §5): it
// captures on lo while a UDP datagram to 127.0.0.1 is sent.
func TestLiveLoopback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lo.pcap")
	l := NewLive(PointClient, "lo", path)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("udp", "127.0.0.1:9") // discard port
	if err != nil {
		_ = l.Stop(ctx)
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("dpisect-probe")); err != nil {
		_ = conn.Close()
		_ = l.Stop(ctx)
		t.Fatalf("write: %v", err)
	}
	_ = conn.Close()
	time.Sleep(300 * time.Millisecond) // give capture time to record

	if err := l.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	found := false
	for !found {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		if string(data) == "" {
			continue
		}
		for i := 0; i+13 <= len(data); i++ {
			if string(data[i:i+13]) == "dpisect-probe" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("probe payload not found in capture")
	}
}
