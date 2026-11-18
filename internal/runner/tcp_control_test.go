package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"gopkg.in/yaml.v3"
)

func tcpControlConfigYAML(dir string) string {
	return fmt.Sprintf(`question_id: B02
experiment_id: b02-tcp-control-2026-11
mode: valid-session
tcp_only: true
tcp_timeout_ms: 3000
endpoint: {role: target, ip: 127.0.0.1, port: 443}
budget:
  max_packets: 100
  max_syn_retransmissions: 1
  stop_conditions: [SYN retransmission, capture failure, SIGINT]
schedule: {repetitions: 1, inter_trial_gap_ms: 1000, state_reset: none}
capture: {client: %q}
runner_log: %q
classification_rule: TCP outcome only
`, dir+"/client.pcap", dir+"/runner.log")
}

func TestTCPControlWritesPlanAndSendsNoPayload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().(*net.TCPAddr)
	checked := make(chan bool, 1)
	wrapped := &planCheckingListener{Listener: listener, planPath: filepath.Join(dir, "plan.yaml"), checked: checked}
	received := make(chan []byte, 1)
	go func() {
		conn, err := wrapped.Accept()
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
	frame := testTCPFrame(t, "127.0.0.1", "127.0.0.1", 50000, uint16(addr.Port))
	open := func(_, path string) (pairWireSource, error) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		w := pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			_ = f.Close()
			return nil, err
		}
		source := &testPairCapture{channelWireSource: channelWireSource{frames: make(chan []byte, 1)}, file: f, writer: w}
		source.frames <- frame
		return source, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runObservedSeries(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err != nil {
		t.Fatalf("TCP control: %v", err)
	}
	if !<-checked {
		t.Fatal("TCP connection arrived before the plan was saved")
	}
	if data := <-received; len(data) != 0 {
		t.Fatalf("TCP control sent %d application bytes", len(data))
	}
	data, err := os.ReadFile(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "packet:") || strings.Contains(string(data), "sni:") {
		t.Fatal("TCP-only plan must not invent exact packet fields or an SNI")
	}
	var plan struct {
		TCPOnly bool `yaml:"tcp_only"`
	}
	if err := yaml.Unmarshal(data, &plan); err != nil || !plan.TCPOnly {
		t.Fatalf("TCP plan: %+v, error %v", plan, err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "tcp-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var observations sniObservations
	if err := json.Unmarshal(data, &observations); err != nil || len(observations.Trials) != 1 || observations.Trials[0].Observation.Stage != "complete" {
		t.Fatalf("TCP observations: %+v, error %v", observations, err)
	}
}

func TestLoadTCPControlNeedsNoSNIOrServerCapture(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeConfig(t, tcpControlConfigYAML(t.TempDir())))
	if err != nil {
		t.Fatalf("load TCP control: %v", err)
	}
	if !cfg.TCPOnly || cfg.SNI != "" || cfg.Capture.Server != "" || cfg.TCPTimeoutMS != 3000 {
		t.Fatalf("unexpected TCP configuration: %+v", cfg)
	}
	if err := Run(context.Background(), cfg, Options{ConfigPath: "config.yaml"}); err == nil || !strings.Contains(err.Error(), "capture interface") {
		t.Fatalf("TCP run without capture: %v", err)
	}
	cfg.Budget.MaxSYNRetransmissions = nil
	if err := Run(context.Background(), cfg, Options{ConfigPath: "config.yaml", CaptureIface: "lo", Operator: "tester"}); err == nil || !strings.Contains(err.Error(), "SYN retransmission threshold") {
		t.Fatalf("TCP run without planned SYN retry threshold: %v", err)
	}
}

func TestTCPControlRejectsIgnoredOrUnsafeOptions(t *testing.T) {
	t.Parallel()

	base := tcpControlConfigYAML(t.TempDir())
	tests := []struct {
		name, input string
	}{
		{"raw mode", strings.Replace(base, "mode: valid-session", "mode: raw-experiment", 1)},
		{"paired SNI", base + "paired_sni: web.telegram.org\n"},
		{"SNI", base + "sni: example.com\n"},
		{"paired delay", base + "paired_client_hello_delay_ms: 100\n"},
		{"preflight", base + "preflight: {enabled: true, host: example.com, independent_resolver: 192.0.2.53:53}\n"},
		{"lab profile", base + "lab: {enabled: true, config_id: x}\n"},
		{"IPv6", strings.Replace(base, "127.0.0.1", "2001:db8::1", 1)},
		{"negative gap", strings.Replace(base, "inter_trial_gap_ms: 1000", "inter_trial_gap_ms: -1", 1)},
		{"invalid retry limit", strings.Replace(base, "max_syn_retransmissions: 1", "max_syn_retransmissions: 0", 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Load(writeConfig(t, tt.input)); err == nil {
				t.Fatal("invalid TCP control config was accepted")
			}
		})
	}
}
