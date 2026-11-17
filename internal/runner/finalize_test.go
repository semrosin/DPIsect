package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestFinalizeAfterHelperStops verifies that the initial record never
// treats a still-growing helper file as final and that finalization hashes
// its later contents without requiring a network connection.
func TestFinalizeAfterHelperStops(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := writeRunConfig(t, dir, runConfigYAML("192.0.2.10", 8443, 1, 100, dir)+"helper_log: "+dir+"/helper.log\n")
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{cfg.Capture.Server, cfg.HelperLog} {
		if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(context.Background(), cfg, Options{ConfigPath: cfgPath}, dependencies{
		newSender: func(string) sendSession { return &hookSender{} },
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	recordPath := filepath.Join(dir, "run.json")
	readRecord := func() RunRecord {
		t.Helper()
		raw, err := os.ReadFile(recordPath)
		if err != nil {
			t.Fatal(err)
		}
		var rec RunRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	initial := readRecord()
	for _, path := range []string{cfg.Capture.Server, cfg.HelperLog} {
		if _, ok := initial.Artifacts[path]; ok {
			t.Fatalf("initial run.json contains unfinalized server artifact %s", path)
		}
		if err := os.WriteFile(path, []byte("closed and complete"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Finalize(cfg, cfgPath); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	got := readRecord()
	for _, path := range []string{cfg.Capture.Server, cfg.HelperLog} {
		sum, err := fileSHA256(path)
		if err != nil || got.Artifacts[path] != sum {
			t.Errorf("final hash for %s = %q, want %q (err=%v)", path, got.Artifacts[path], sum, err)
		}
	}
	if got.Artifacts[cfg.RunnerLog] != initial.Artifacts[cfg.RunnerLog] || got.ExperimentID != initial.ExperimentID {
		t.Fatal("finalization changed existing client metadata")
	}
	if err := Finalize(cfg, cfgPath); err != nil {
		t.Fatalf("second Finalize: %v", err)
	}
}

func TestFinalizeDoesNotRewriteRecordOnFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := Config{
		QuestionID: "H07", ExperimentID: "h07-finalize-2026-11",
		Capture:   CapturePaths{Client: filepath.Join(dir, "client.pcap"), Server: filepath.Join(dir, "server.pcap")},
		HelperLog: filepath.Join(dir, "helper.log"), RunnerLog: filepath.Join(dir, "runner.log"),
	}
	if err := WriteRun(dir, RunRecord{QuestionID: cfg.QuestionID, ExperimentID: cfg.ExperimentID, ConfigFile: cfgPath}); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(dir, "run.json")
	original, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Capture.Server, []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Finalize(cfg, cfgPath); err == nil {
		t.Fatal("missing helper log: expected an error")
	}
	got, err := os.ReadFile(recordPath)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("failed finalization changed run.json: err=%v", err)
	}
	cfg.ExperimentID = "h07-other-2026-11"
	if err := Finalize(cfg, cfgPath); err == nil {
		t.Fatal("mismatched experiment: expected an error")
	}
	got, err = os.ReadFile(recordPath)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("identity mismatch changed run.json: err=%v", err)
	}
	cfg.ExperimentID = "h07-finalize-2026-11"
	cfg.Capture.Server = recordPath
	if err := Finalize(cfg, cfgPath); err == nil {
		t.Fatal("run.json as server artifact: expected an error")
	}
	got, err = os.ReadFile(recordPath)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("overlapping path changed run.json: err=%v", err)
	}
}
