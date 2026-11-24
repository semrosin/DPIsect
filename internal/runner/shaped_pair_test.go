package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"gopkg.in/yaml.v3"
)

func TestB07SameSNIPairPersistsIndependentShapes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := runConfigYAML("192.0.2.10", 443, 2, 100, dir) + `paired_sni: control.example
paired_hello:
  control: {record_length: 250, sni_offset: 110, ignored_data: blocked.example}
  treatment: {record_length: 250, sni_offset: 130, ignored_data: blocked.example}
`
	path := writeRunConfig(t, dir, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareSNIComparison(cfg, path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, sessions, err := prepareSNIWirePlan(ctx, cfg, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	data, err := os.ReadFile(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var plan sniWirePlan
	if err := yaml.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	want := []struct {
		role   string
		offset int
	}{{"control", 110}, {"treatment", 130}, {"treatment", 130}, {"control", 110}}
	if len(plan.Trials) != len(want) {
		t.Fatalf("trials = %d", len(plan.Trials))
	}
	for i, trial := range plan.Trials {
		if trial.Variant != want[i].role || len(trial.Packet.Payload) != 250 || bytes.Index(trial.Packet.Payload, []byte("control.example")) != want[i].offset {
			t.Errorf("trial %d: role=%q length=%d offset=%d", i, trial.Variant, len(trial.Packet.Payload), bytes.Index(trial.Packet.Payload, []byte("control.example")))
		}
	}
}

func TestB07SameSNIObservationsIdentifyEachVariant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	port := server.Listener.Addr().(*net.TCPAddr).Port
	content := runConfigYAML("127.0.0.1", port, 1, 100, dir) + `paired_sni: control.example
paired_hello:
  control: {record_length: 250, sni_offset: 110}
  treatment: {record_length: 250, sni_offset: 130}
`
	path := writeRunConfig(t, dir, content)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	retryLimit := 1
	cfg.Budget.MaxSYNRetransmissions = &retryLimit
	cfg.Budget.StopConditions = []string{"capture failure", "SIGINT"}
	frame := testTCPFrame(t, "127.0.0.1", "127.0.0.1", 50000, uint16(port))
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
	if err := runObservedSeries(ctx, cfg, Options{ConfigPath: path, CaptureIface: "lo", Operator: "tester"}, open); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "sni-observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var observations sniObservations
	if err := json.Unmarshal(data, &observations); err != nil {
		t.Fatal(err)
	}
	if len(observations.Trials) != 2 || observations.Trials[0].Variant != "control" || observations.Trials[1].Variant != "treatment" {
		t.Fatalf("trials = %+v", observations.Trials)
	}
}

func TestB04ShapedPairRequiresExplicitValidShapes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := runConfigYAML("192.0.2.10", 443, 1, 100, dir) + "paired_sni: blocked.example\n"
	for _, tc := range []struct{ name, shape string }{
		{"missing treatment", "paired_hello:\n  control: {record_length: 250, sni_offset: 110}\n"},
		{"negative offset", "paired_hello:\n  control: {record_length: 250, sni_offset: -1}\n  treatment: {record_length: 250, sni_offset: 110}\n"},
		{"offset outside record", "paired_hello:\n  control: {record_length: 250, sni_offset: 250}\n  treatment: {record_length: 250, sni_offset: 110}\n"},
		{"oversized record", "paired_hello:\n  control: {record_length: 16390, sni_offset: 110}\n  treatment: {record_length: 250, sni_offset: 110}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRunConfig(t, t.TempDir(), base+tc.shape)
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "paired_hello") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestB07RejectsIdenticalProfilesWithSameSNI(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := runConfigYAML("192.0.2.10", 443, 1, 100, dir) + `paired_sni: control.example
paired_hello:
  control: {record_length: 250, sni_offset: 110}
  treatment: {record_length: 250, sni_offset: 110}
`
	if _, err := Load(writeRunConfig(t, dir, base)); err == nil {
		t.Fatal("identical SNI and profiles cannot form a comparison")
	}
}

func TestC01SplitPlan(t *testing.T) {
	dir := t.TempDir()
	config := runConfigYAML("127.0.0.1", 443, 2, 100, dir) + `paired_sni: control.example
paired_split: {control: 0, treatment: 32}
`
	config = strings.Replace(config, "question_id: H01", "question_id: C01", 1)
	config = strings.Replace(config, "experiment_id: h01-", "experiment_id: c01-", 1)
	configPath := writeRunConfig(t, dir, config)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, sessions, err := prepareSNIWirePlan(context.Background(), cfg, configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	want := []int{0, 32, 32, 0}
	for i, trial := range plan.Trials {
		offsets := trial.Packet.SplitOffsets
		if (want[i] == 0 && len(offsets) != 0) || (want[i] != 0 && (len(offsets) != 1 || offsets[0] != want[i])) {
			t.Fatalf("trial %d offsets = %v, want %d", i, offsets, want[i])
		}
	}
}

func TestC01SplitExplicitTreatmentFirst(t *testing.T) {
	dir := t.TempDir()
	config := runConfigYAML("127.0.0.1", 443, 1, 100, dir) + `paired_sni: treatment.example
paired_split: {control: 0, treatment: 32, first: treatment}
`
	configPath := writeRunConfig(t, dir, config)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, sessions, err := prepareSNIWirePlan(context.Background(), cfg, configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	if plan.Trials[0].SNI != "treatment.example" || plan.Trials[0].Variant != "treatment" ||
		len(plan.Trials[0].Packet.SplitOffsets) != 1 || plan.Trials[0].Packet.SplitOffsets[0] != 32 ||
		plan.Trials[1].SNI != "control.example" || plan.Trials[1].Variant != "control" ||
		len(plan.Trials[1].Packet.SplitOffsets) != 0 {
		t.Fatalf("unexpected trial order: %+v", plan.Trials)
	}
}
