package runner

import (
	"context"
	"encoding/json"
	"errors"
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
)

type testPairCapture struct {
	channelWireSource
	file   *os.File
	writer *pcapgo.Writer
}

func TestHistoricalObservationsDoNotInventRetryCount(t *testing.T) {
	t.Parallel()

	var old sniObservations
	if err := json.Unmarshal([]byte(`{"observed_packets":20}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.ObservedSYNRetransmissions != nil {
		t.Fatal("old observations did not measure SYN retransmissions")
	}
	var current sniObservations
	if err := json.Unmarshal([]byte(`{"observed_syn_retransmissions":0}`), &current); err != nil {
		t.Fatal(err)
	}
	if current.ObservedSYNRetransmissions == nil || *current.ObservedSYNRetransmissions != 0 {
		t.Fatal("new observations must preserve a measured zero")
	}
}

func (s *testPairCapture) Record(frame []byte, ci gopacket.CaptureInfo) error {
	return s.writer.WritePacket(ci, frame)
}
func (s *testPairCapture) stop() error { return s.file.Close() }

type planCheckingListener struct {
	net.Listener
	planPath string
	checked  chan bool
}

func (l *planCheckingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		_, statErr := os.Stat(l.planPath)
		l.checked <- statErr == nil
	}
	return conn, err
}

func TestSNIComparisonRunsAfterPlanAndSavesResults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	server := httptest.NewUnstartedServer(nil)
	checked := make(chan bool, 2)
	server.Listener = &planCheckingListener{Listener: server.Listener, planPath: filepath.Join(dir, "plan.yaml"), checked: checked}
	server.StartTLS()
	t.Cleanup(server.Close)
	addr := server.Listener.Addr().(*net.TCPAddr)
	content := runConfigYAML("127.0.0.1", addr.Port, 1, 100, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Budget.StopConditions = []string{"budget limit", "capture failure", "SIGINT"}
	maxRetries := 3
	cfg.Budget.MaxSYNRetransmissions = &maxRetries
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
	err = runObservedSeries(ctx, cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open)
	if err != nil {
		t.Fatalf("run paired trials: %v", err)
	}
	for i := 0; i < 2; i++ {
		select {
		case ok := <-checked:
			if !ok {
				t.Fatal("TCP connection arrived before plan.yaml existed")
			}
		case <-ctx.Done():
			t.Fatal("missing trial connection")
		}
	}
	for _, path := range []string{"plan.yaml", "run.json", "sni-observations.json", "client.pcap"} {
		if _, err := os.Stat(filepath.Join(dir, path)); err != nil {
			t.Errorf("missing %s: %v", path, err)
		}
	}
}

func TestSNIComparisonLeavesNoArtifactsAfterPreflightFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	runPath := filepath.Join(dir, "run.json")
	if err := os.WriteFile(runPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	content := runConfigYAML("127.0.0.1", 443, 1, 100, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Budget.StopConditions = []string{"SIGINT"}
	maxRetries := 1
	cfg.Budget.MaxSYNRetransmissions = &maxRetries
	open := func(_, _ string) (pairWireSource, error) {
		t.Fatal("capture must not start when artifacts already exist")
		return nil, nil
	}
	err = runObservedSeries(context.Background(), cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("error = %v, want an existing artifact refusal", err)
	}
	for _, name := range []string{"sni-observations.json", "runner.log"} {
		if _, statErr := os.Stat(filepath.Join(dir, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("%s must not be created before preflight, stat error = %v", name, statErr)
		}
	}
	if data, readErr := os.ReadFile(runPath); readErr != nil || string(data) != "{}\n" {
		t.Errorf("pre-existing run.json was modified: %q, %v", data, readErr)
	}
}

func TestSNIComparisonRequiresPlanMetadata(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := runConfigYAML("127.0.0.1", 443, 1, 100, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	open := func(_, _ string) (pairWireSource, error) {
		t.Fatal("capture must not start without required metadata")
		return nil, nil
	}
	if err := runObservedSeries(context.Background(), cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err == nil {
		t.Fatal("missing stop conditions must fail")
	}
	cfg.Budget.StopConditions = []string{"SIGINT"}
	if err := runObservedSeries(context.Background(), cfg, Options{ConfigPath: configPath, CaptureIface: "lo"}, open); err == nil {
		t.Fatal("missing operator must fail")
	}
	if err := runObservedSeries(context.Background(), cfg, Options{ConfigPath: configPath, CaptureIface: "lo", Operator: "tester"}, open); err == nil {
		t.Fatal("missing planned SYN retry threshold must fail")
	}
}
