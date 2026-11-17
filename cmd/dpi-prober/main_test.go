package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/semrosin/DPIsect/internal/runner"
)

func TestFinalizeCommandDoesNotStartProbe(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	server := filepath.Join(dir, "server.pcap")
	helper := filepath.Join(dir, "helper.log")
	yaml := fmt.Sprintf(`question_id: H07
experiment_id: h07-finalize-2026-11
mode: valid-session
sni: control.example
endpoint: {role: helper, ip: 127.0.0.1, port: 18443}
schedule: {repetitions: 1}
capture: {client: %q, server: %q}
helper_log: %q
runner_log: %q
classification_rule: complete
`, filepath.Join(dir, "client.pcap"), server, helper, filepath.Join(dir, "runner.log"))
	if err := os.WriteFile(config, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{server, helper} {
		if err := os.WriteFile(file, []byte("finished"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := runner.WriteRun(dir, runner.RunRecord{
		ExperimentID: "h07-finalize-2026-11", QuestionID: "H07", ConfigFile: config,
	}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-config", config, "-finalize"}); err != nil {
		t.Fatalf("finalize command: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got runner.RunRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Artifacts[server]) != 64 || len(got.Artifacts[helper]) != 64 {
		t.Fatalf("missing final server hashes: %v", got.Artifacts)
	}
	if _, err := os.Stat(filepath.Join(dir, "plan.yaml")); !os.IsNotExist(err) {
		t.Fatalf("finalize must not start a probe or write a plan: %v", err)
	}
	if err := run([]string{"-config", config, "-finalize", "-capture-iface", "lo"}); err == nil {
		t.Fatal("finalize with capture option must fail")
	}
}
