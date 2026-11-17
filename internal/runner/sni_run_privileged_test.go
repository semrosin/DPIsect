//go:build linux && privileged

package runner

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/semrosin/DPIsect/internal/sender"
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
	maxRetries := 3 // loopback may expose two copies of one SYN
	cfg.Budget.MaxSYNRetransmissions = &maxRetries
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func(iface, path string) (pairWireSource, error) {
		return newAFPacketWireSource(iface, path)
	}
	if err := runObservedSeries(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err != nil {
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

func TestB07ShapedPairCompletesUnderRateLimitLoopback(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	sni := cert.DNSNames[0]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var sessions []*sender.PreparedTLS
	for _, offset := range []int{110, 130} {
		p, err := sender.PrepareShapedTLS(ctx, sni, roots, sender.HelloShape{RecordLength: 250, SNIOffset: offset})
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, p)
	}
	defer func() {
		for _, p := range sessions {
			p.Close()
		}
	}()
	source, err := newAFPacketWireSource("lo", filepath.Join(dir, "client.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.stop()
	retry := 1
	budget, err := newWireBudget("127.0.0.1", server.Listener.Addr().(*net.TCPAddr).Port,
		Budget{MaxPackets: 100, MaxBytes: 102400, MaxRatePPS: 10, MaxSYNRetransmissions: &retry})
	if err != nil {
		t.Fatal(err)
	}
	index := 0
	probe := func(ctx context.Context, addr, _ string) sender.TLSObservation {
		p := sessions[index]
		index++
		defer p.Close()
		return p.StartAfter(ctx, addr, 1100*time.Millisecond)
	}
	trials, err := runMonitoredSNITrials(ctx, server.Listener.Addr().String(), []string{sni, sni}, 5*time.Second, 3*time.Second, probe, source, budget)
	if err != nil {
		t.Fatalf("monitored pair: %v; trials: %+v", err, trials)
	}
	if len(trials) != 2 || trials[0].Observation.Stage != "complete" || trials[1].Observation.Stage != "complete" {
		t.Fatalf("TLS trials: %+v", trials)
	}
}

func TestB07ShapedPairCapturesLoopback(t *testing.T) {
	dir := t.TempDir()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr)
	content := runConfigYAML("127.0.0.1", addr.Port, 1, 100, dir) + `paired_sni: control.example
paired_hello:
  control: {record_length: 250, sni_offset: 110}
  treatment: {record_length: 250, sni_offset: 130}
`
	path := writeRunConfig(t, dir, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Budget.MaxRatePPS = 100
	cfg.Budget.StopConditions = []string{"capture failure", "SIGINT"}
	retryLimit := 1
	cfg.Budget.MaxSYNRetransmissions = &retryLimit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func(iface, path string) (pairWireSource, error) { return newAFPacketWireSource(iface, path) }
	if err := runObservedSeries(ctx, cfg, Options{ConfigPath: path, CaptureIface: "lo", Operator: "tester"}, open); err != nil {
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
	f, err := os.Open(filepath.Join(dir, "client.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	found := make([]bool, len(plan.Trials))
	for {
		frame, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
		if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
			for i, trial := range plan.Trials {
				if bytes.Equal(layer.(*layers.TCP).Payload, trial.Packet.Payload) {
					found[i] = true
				}
			}
		}
	}
	if len(found) != 2 || !found[0] || !found[1] {
		t.Fatalf("captured planned ClientHellos: %v", found)
	}
}

func TestTCPControlCapturesLoopbackWithoutPayload(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		received <- data
	}()
	content := strings.Replace(tcpControlConfigYAML(dir), "port: 443", fmt.Sprintf("port: %d", addr.Port), 1)
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Endpoint.Role = RoleHelper
	cfg.Capture.Server = filepath.Join(dir, "unused-server.pcap")
	cfg.Budget.MaxRatePPS = 100
	maxRetries := 3 // loopback may expose two copies of one SYN
	cfg.Budget.MaxSYNRetransmissions = &maxRetries
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func(iface, path string) (pairWireSource, error) {
		return newAFPacketWireSource(iface, path)
	}
	if err := runObservedSeries(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err != nil {
		t.Fatalf("TCP control: %v", err)
	}
	if data := <-received; len(data) != 0 {
		t.Fatalf("TCP control sent %d application bytes", len(data))
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
	packets := 0
	for {
		frame, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			packets++
			if payload := tcpLayer.(*layers.TCP).Payload; len(payload) != 0 {
				t.Fatalf("captured TCP payload: %d bytes", len(payload))
			}
		}
	}
	if packets == 0 {
		t.Fatal("capture contains no TCP packets")
	}
}

func TestTCPControlStopsOnRealSYNRetry(t *testing.T) {
	if _, err := net.InterfaceByName("dpisect0"); err != nil {
		t.Skip("requires an isolated namespace with the dpisect0 test veth")
	}
	dir := t.TempDir()
	content := strings.Replace(tcpControlConfigYAML(dir), "127.0.0.1", "192.0.2.2", 1)
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func(iface, path string) (pairWireSource, error) {
		return newAFPacketWireSource(iface, path)
	}
	err = runObservedSeries(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "dpisect0", Operator: "tester"}, open)
	if err == nil || !strings.Contains(err.Error(), "SYN retransmission") {
		t.Fatalf("want stop on SYN retry, got %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "tcp-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var obs sniObservations
	if err := json.Unmarshal(data, &obs); err != nil {
		t.Fatal(err)
	}
	if !obs.TCPOnly || obs.ObservedSYNRetransmissions == nil || *obs.ObservedSYNRetransmissions != 1 || len(obs.Trials) != 1 || obs.StopReason == "" {
		t.Fatalf("unexpected TCP observations: %+v", obs)
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
	maxRetries := 3
	cfg.Budget.MaxSYNRetransmissions = &maxRetries
	cfg.Schedule.InterTrialGapMS = 100
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func(iface, path string) (pairWireSource, error) {
		return newAFPacketWireSource(iface, path)
	}
	if err := runObservedSeries(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err == nil {
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
