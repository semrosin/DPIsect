package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/dnsprobe"
	"github.com/semrosin/DPIsect/internal/generator"
)

func TestRunRefusesRawWithoutConfirmation(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeConfig(t, `question_id: D01
experiment_id: d01-test-2026-11
mode: raw-experiment
endpoint:
  role: helper
  ip: 192.0.2.10
  port: 443
schedule:
  repetitions: 1
  seed: 1
capture:
  client: artifacts/x/client.pcap
  server: artifacts/x/server.pcap
runner_log: artifacts/x/runner.log
classification_rule: probe delivered
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	err = Run(context.Background(), cfg, Options{AllowRaw: false})
	if err == nil {
		t.Fatal("Run without AllowRaw: want error, got nil")
	}
	if !strings.Contains(err.Error(), "-allow-raw") {
		t.Errorf("Run error %q must be the raw-confirmation refusal", err)
	}
}

func TestRunRefusesRawEvenWithConfirmation(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeConfig(t, `question_id: D01
experiment_id: d01-test-2026-11
mode: raw-experiment
endpoint:
  role: helper
  ip: 192.0.2.10
  port: 443
schedule:
  repetitions: 1
  seed: 1
capture:
  client: artifacts/x/client.pcap
  server: artifacts/x/server.pcap
runner_log: artifacts/x/runner.log
classification_rule: probe delivered
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	err = Run(context.Background(), cfg, Options{AllowRaw: true})
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("Run with AllowRaw: err = %v, want not-implemented refusal", err)
	}
}

// startTCPSink accepts one connection and yields everything it
// received until the client closes.
func startTCPSink(t *testing.T) (host string, port int, received <-chan []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	out := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		buf, _ := io.ReadAll(conn)
		_ = conn.Close()
		out <- buf
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port, out
}

func writeRunConfig(t *testing.T, dir, content string) string {
	t.Helper()

	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func runConfigYAML(host string, port, repetitions, maxPackets int, dir string) string {
	return fmt.Sprintf(`question_id: H01
experiment_id: h01-test-2026-11
mode: valid-session
sni: control.example
endpoint:
  role: helper
  ip: %s
  port: %d
budget:
  max_packets: %d
schedule:
  repetitions: %d
  seed: 7
  inter_trial_gap_ms: 0
capture:
  client: %s/client.pcap
  server: %s/server.pcap
runner_log: %s/runner.log
classification_rule: probe delivered
`, host, port, maxPackets, repetitions, dir, dir, dir)
}

func TestRunDeliversPlanOverTCP(t *testing.T) {
	t.Parallel()

	host, port, received := startTCPSink(t)
	dir := t.TempDir()
	cfgPath := writeRunConfig(t, dir, runConfigYAML(host, port, 1, 100, dir))
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	err = Run(context.Background(), cfg, Options{
		ConfigPath:  cfgPath,
		Operator:    "tester",
		ToolVersion: "v0-test",
		ToolCommit:  "cafe",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	plan, err := ReadPlan(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatalf("ReadPlan: %v", err)
	}
	if len(plan.Packets) != 1 {
		t.Fatalf("plan packets = %d, want 1", len(plan.Packets))
	}
	got := <-received
	if string(got) != string(plan.Packets[0].Payload) {
		t.Errorf("received %d bytes, want the planned ClientHello (%d bytes)",
			len(got), len(plan.Packets[0].Payload))
	}

	raw, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var rec RunRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("parse run.json: %v", err)
	}
	if rec.ExperimentID != "h01-test-2026-11" || rec.QuestionID != "H01" ||
		rec.Operator != "tester" || rec.Seed != 7 || rec.ConfigFile != cfgPath {
		t.Errorf("run.json = %+v, missing run identity fields", rec)
	}
	if _, err := time.Parse(time.RFC3339, rec.StartedUTC); err != nil {
		t.Errorf("started_utc %q: %v", rec.StartedUTC, err)
	}
	if _, err := time.Parse(time.RFC3339, rec.FinishedUTC); err != nil {
		t.Errorf("finished_utc %q: %v", rec.FinishedUTC, err)
	}
	if len(rec.DependencyVersions) == 0 {
		t.Error("dependency_versions is empty, want module versions (H07)")
	}
	logSum, ok := rec.Artifacts[dir+"/runner.log"]
	if !ok || len(logSum) != 64 {
		t.Errorf("artifacts = %v, want sha256 of runner.log", rec.Artifacts)
	}
	if _, ok := rec.Artifacts[dir+"/client.pcap"]; ok {
		t.Error("client.pcap must be absent from artifacts when capture never ran")
	}
}

// hookSender records sends for assertions without a real socket.
type hookSender struct {
	onSend  func(generator.PlannedWirePacket) error
	onClose func()
	sent    int
}

func (h *hookSender) Send(_ context.Context, p generator.PlannedWirePacket) error {
	if h.onSend != nil {
		if err := h.onSend(p); err != nil {
			return err
		}
	}
	h.sent++
	return nil
}

func (h *hookSender) Close() error {
	if h.onClose != nil {
		h.onClose()
	}
	return nil
}

func TestRunHoldsConnectionDuringSettle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := writeRunConfig(t, dir, runConfigYAML("192.0.2.10", 8443, 1, 100, dir))
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	var sentAt, closedAt time.Time
	sess := &hookSender{
		onSend: func(generator.PlannedWirePacket) error {
			sentAt = time.Now()
			return nil
		},
		onClose: func() { closedAt = time.Now() },
	}
	err = run(context.Background(), cfg, Options{ConfigPath: cfgPath}, dependencies{
		newSender: func(string) sendSession { return sess },
		settle:    60 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sentAt.IsZero() || closedAt.IsZero() {
		t.Fatal("send and close must both have happened")
	}
	if hold := closedAt.Sub(sentAt); hold < 60*time.Millisecond {
		t.Errorf("connection held for %s, want >= 60ms settle (helper must answer first)", hold)
	}
}

func TestRunPersistsPlanBeforeFirstPacket(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := writeRunConfig(t, dir, runConfigYAML("192.0.2.10", 8443, 1, 100, dir))
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	planPath := filepath.Join(dir, "plan.yaml")
	planExistedAtSend := false
	sess := &hookSender{onSend: func(generator.PlannedWirePacket) error {
		_, err := os.Stat(planPath)
		planExistedAtSend = err == nil
		return nil
	}}
	err = run(context.Background(), cfg, Options{ConfigPath: cfgPath}, dependencies{
		newSender: func(string) sendSession { return sess },
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !planExistedAtSend {
		t.Error("plan.yaml did not exist when the first packet was sent")
	}
	if sess.sent != 1 {
		t.Errorf("sent packets = %d, want 1", sess.sent)
	}
}

func TestRunPreflightWritesDNSLog(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	yaml := runConfigYAML("192.0.2.10", 8443, 1, 100, dir) +
		"preflight:\n  enabled: true\n  host: control.example\n  independent_resolver: 192.0.2.53:53\n"
	cfgPath := writeRunConfig(t, dir, yaml)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	called := false
	err = run(context.Background(), cfg, Options{ConfigPath: cfgPath}, dependencies{
		checkPreflight: func(context.Context, Config) (dnsprobe.Report, error) {
			called = true
			return dnsprobe.Report{
				Host:             "control.example",
				SystemAddrs:      []string{"192.0.2.1"},
				IndependentAddrs: []string{"192.0.2.1"},
				AddrsMatch:       true,
				TCPReachable:     true,
			}, nil
		},
		newSender: func(string) sendSession { return &hookSender{} },
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !called {
		t.Fatal("preflight checker was not called")
	}
	dnsLog, err := os.ReadFile(filepath.Join(dir, "dns_log.yaml"))
	if err != nil {
		t.Fatalf("read dns_log.yaml: %v", err)
	}
	if !strings.Contains(string(dnsLog), "addrs_match: true") {
		t.Errorf("dns_log.yaml = %s, want addrs_match: true", dnsLog)
	}
}

func TestRunPreflightFailureStopsBeforePlan(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	yaml := runConfigYAML("192.0.2.10", 8443, 1, 100, dir) +
		"preflight:\n  enabled: true\n  host: control.example\n  independent_resolver: 192.0.2.53:53\n"
	cfgPath := writeRunConfig(t, dir, yaml)
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	senderCalled := false
	err = run(context.Background(), cfg, Options{ConfigPath: cfgPath}, dependencies{
		checkPreflight: func(context.Context, Config) (dnsprobe.Report, error) {
			return dnsprobe.Report{}, errors.New("servfail")
		},
		newSender: func(string) sendSession {
			senderCalled = true
			return &hookSender{}
		},
	})
	if err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("err = %v, want preflight failure", err)
	}
	if senderCalled {
		t.Error("sender must not be created after a failed preflight")
	}
	if _, err := os.Stat(filepath.Join(dir, "plan.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plan.yaml stat err = %v, want not-exist", err)
	}
}

func TestRunBudgetStopsAtMaxPackets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := writeRunConfig(t, dir, runConfigYAML("192.0.2.10", 8443, 3, 2, dir))
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	sess := &hookSender{}
	err = run(context.Background(), cfg, Options{ConfigPath: cfgPath}, dependencies{
		newSender: func(string) sendSession { return sess },
	})
	if err == nil || !strings.Contains(err.Error(), "max_packets") {
		t.Fatalf("err = %v, want max_packets budget refusal", err)
	}
	if sess.sent != 2 {
		t.Errorf("sent packets = %d, want exactly the budget (2)", sess.sent)
	}
}
