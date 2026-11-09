package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// RunRecord is the machine-readable run metadata written to
// experiments/<experiment_id>/run.json (H07; docs/ARCHITECTURE.md §4).
// Time fields are RFC3339 in UTC.
type RunRecord struct {
	ExperimentID       string            `json:"experiment_id"`
	QuestionID         string            `json:"question_id"`
	ToolVersion        string            `json:"tool_version"`
	ToolCommit         string            `json:"tool_commit"`
	DependencyVersions map[string]string `json:"dependency_versions"`
	Seed               int64             `json:"seed"`
	StartedUTC         string            `json:"started_utc"`
	FinishedUTC        string            `json:"finished_utc"`
	Operator           string            `json:"operator"`
	ConfigFile         string            `json:"config_file"`
	LabConfigID        string            `json:"lab_config_id"`
	// Artifacts maps artifact paths (outside git) to sha256 hex digests.
	Artifacts map[string]string `json:"artifacts"`
}

// WriteRun persists rec as dir/run.json, creating dir if needed.
func WriteRun(dir string, rec RunRecord) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run record: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create experiment dir: %w", err)
	}
	path := filepath.Join(dir, "run.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write run record: %w", err)
	}
	return nil
}
