package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteRun(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	want := RunRecord{
		ExperimentID:       "b01-test-2026-11",
		QuestionID:         "B01",
		ToolVersion:        "dev",
		ToolCommit:         "abc1234",
		DependencyVersions: map[string]string{"gopacket": "v1.6.1"},
		Seed:               42,
		StartedUTC:         "2026-11-05T10:00:00Z",
		FinishedUTC:        "2026-11-05T10:00:30Z",
		Operator:           "darya",
		ConfigFile:         "experiments/b01-test-2026-11/config.yaml",
		LabConfigID:        "netem-loss10-2026-11",
		Artifacts: map[string]string{
			"artifacts/b01-test-2026-11/client.pcap": "deadbeef",
		},
	}
	if err := WriteRun(dir, want); err != nil {
		t.Fatalf("WriteRun: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "run.json"))
	if err != nil {
		t.Fatalf("read run.json: %v", err)
	}
	var got RunRecord
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal run.json: %v", err)
	}
	if got.ExperimentID != want.ExperimentID || got.QuestionID != want.QuestionID {
		t.Errorf("ids = %q/%q, want %q/%q",
			got.ExperimentID, got.QuestionID, want.ExperimentID, want.QuestionID)
	}
	if got.Seed != want.Seed || got.Operator != want.Operator ||
		got.LabConfigID != want.LabConfigID || got.ToolCommit != want.ToolCommit {
		t.Errorf("record = %+v, want %+v", got, want)
	}
	if got.Artifacts["artifacts/b01-test-2026-11/client.pcap"] != "deadbeef" {
		t.Errorf("artifacts = %v, want sha256 for client.pcap", got.Artifacts)
	}
}
