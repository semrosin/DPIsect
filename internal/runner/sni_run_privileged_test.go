//go:build linux && privileged

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"gopkg.in/yaml.v3"
)

func TestSNIComparisonCapturesLoopback(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr)
	content := runConfigYAML("127.0.0.1", addr.Port, 1, 100, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	// Loopback delivers both copies of a frame to AF_PACKET; this is an
	// isolated local test of capture and not a target experiment.
	cfg.Budget.MaxRatePPS = 100
	cfg.Budget.StopConditions = []string{"budget limit", "capture failure", "SIGINT"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func(iface, path string) (pairWireSource, error) {
		return newAFPacketWireSource(iface, path)
	}
	if err := runSNIComparison(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err != nil {
		t.Fatalf("paired loopback run: %v", err)
	}
	f, err := os.Open(filepath.Join(dir, "client.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var plan sniWirePlan
	if err := yaml.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	found := make([]bool, len(plan.Trials))
	for {
		frame, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			payload := tcpLayer.(*layers.TCP).Payload
			for i, trial := range plan.Trials {
				if bytes.Equal(payload, trial.Packet.Payload) {
					found[i] = true
				}
			}
		}
	}
	for i, ok := range found {
		if !ok {
			t.Errorf("planned ClientHello %d was not found in loopback capture", i)
		}
	}
}

func TestSNIComparisonStopsAtObservedLimit(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr)
	content := runConfigYAML("127.0.0.1", addr.Port, 1, 2, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Budget.MaxRatePPS = 100
	cfg.Budget.StopConditions = []string{"budget limit", "capture failure", "SIGINT"}
	cfg.Schedule.InterTrialGapMS = 100
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func(iface, path string) (pairWireSource, error) {
		return newAFPacketWireSource(iface, path)
	}
	if err := runSNIComparison(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err == nil {
		t.Fatal("want cancellation when capture reaches the packet limit")
	}
	data, err := os.ReadFile(filepath.Join(dir, "sni-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var obs sniObservations
	if err := json.Unmarshal(data, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.ObservedPackets != 1 || len(obs.Trials) > 1 || obs.StopReason == "" {
		t.Fatalf("observations = %+v; want limit and no second trial", obs)
	}
}
