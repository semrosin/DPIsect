package runner

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/semrosin/DPIsect/internal/generator"
	"gopkg.in/yaml.v3"
)

// PlanFile is the persisted packet plan
// (experiments/<experiment_id>/plan.yaml), fixed before the first
// packet is sent (docs/ARCHITECTURE.md §4, docs/EXPERIMENTS.md §2).
type PlanFile struct {
	ExperimentID string                        `yaml:"experiment_id"`
	Packets      []generator.PlannedWirePacket `yaml:"packets"`
}

// WritePlan persists plan as dir/plan.yaml, creating dir if needed.
func WritePlan(dir string, plan PlanFile) error {
	data, err := yaml.Marshal(plan)
	if err != nil {
		return fmt.Errorf("marshal plan: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create experiment dir: %w", err)
	}
	path := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	return nil
}

// ReadPlan loads a persisted plan with strict field checking.
func ReadPlan(path string) (PlanFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return PlanFile{}, fmt.Errorf("open plan: %w", err)
	}
	defer func() {
		// Closing a read-only file cannot affect the result.
		_ = f.Close()
	}()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var plan PlanFile
	if err := dec.Decode(&plan); err != nil {
		return PlanFile{}, fmt.Errorf("decode plan: %w", err)
	}
	return plan, nil
}
