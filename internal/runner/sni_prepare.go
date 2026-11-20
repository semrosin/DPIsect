package runner

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// PrepareSNIComparison saves a logical schedule without opening any network
// connections. This is not a planned-wire-packets file or permission to run.
func PrepareSNIComparison(cfg Config, configPath string) error {
	if configPath == "" || cfg.PairedSNI == "" {
		return errors.New("config path and paired_sni are required")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	names, err := pairedSNIScheduleFor(cfg.SNI, cfg.PairedSNI, cfg.Schedule.Repetitions, cfg.PairedHello != nil || cfg.PairedSplit != nil)
	if err != nil {
		return err
	}
	plan := struct {
		ExperimentID string   `yaml:"experiment_id"`
		Endpoint     Endpoint `yaml:"endpoint"`
		Names        []string `yaml:"sni_schedule"`
		Variants     []string `yaml:"variants,omitempty"`
		GapMS        int      `yaml:"inter_trial_gap_ms"`
		TimeoutMS    int      `yaml:"trial_timeout_ms"`
		DelayMS      int      `yaml:"client_hello_delay_ms,omitempty"`
		CloseDelayMS int      `yaml:"close_delay_ms,omitempty"`
	}{ExperimentID: cfg.ExperimentID, Endpoint: cfg.Endpoint, Names: names, GapMS: cfg.Schedule.InterTrialGapMS, TimeoutMS: cfg.PairedTimeoutMS, DelayMS: cfg.PairedClientHelloDelayMS, CloseDelayMS: cfg.PairedCloseDelayMS}
	if cfg.PairedHello != nil || cfg.PairedSplit != nil {
		for i := range names {
			plan.Variants = append(plan.Variants, pairedVariant(i))
		}
	}
	data, err := yaml.Marshal(plan)
	if err != nil {
		return fmt.Errorf("marshal SNI schedule: %w", err)
	}
	path := filepath.Join(filepath.Dir(configPath), "sni-schedule.yaml")
	f, err := os.CreateTemp(filepath.Dir(path), ".sni-schedule-*")
	if err != nil {
		return fmt.Errorf("create temporary SNI schedule: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return fmt.Errorf("set SNI schedule permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write SNI schedule: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close SNI schedule: %w", err)
	}
	if err := os.Link(f.Name(), path); errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read existing SNI schedule: %w", readErr)
		}
		if bytes.Equal(existing, data) {
			return nil
		}
		return fmt.Errorf("SNI schedule already exists with different content: %s", path)
	} else if err != nil {
		return fmt.Errorf("install SNI schedule: %w", err)
	}
	return nil
}
