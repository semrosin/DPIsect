package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/semrosin/DPIsect/internal/generator"
	"github.com/semrosin/DPIsect/internal/sender"
	"gopkg.in/yaml.v3"
)

type sniWireTrial struct {
	SNI    string                      `yaml:"sni"`
	Packet generator.PlannedWirePacket `yaml:"packet"`
}

type sniWirePlan struct {
	ExperimentID string         `yaml:"experiment_id"`
	QuestionID   string         `yaml:"question_id"`
	Mode         string         `yaml:"mode"`
	Endpoint     Endpoint       `yaml:"endpoint"`
	Trials       []sniWireTrial `yaml:"trials"`
	GapMS        int            `yaml:"inter_trial_gap_ms"`
	TimeoutMS    int            `yaml:"trial_timeout_ms"`
	StateReset   string         `yaml:"state_reset"`
	Budget       Budget         `yaml:"budget"`
	Rule         string         `yaml:"classification_rule"`
	WireNotes    string         `yaml:"wire_notes"`
}

// prepareSNIWirePlan holds each TLS handshake before its first write and saves
// the exact ClientHello bytes before any socket is opened. The caller closes
// the returned sessions, including when a series is cancelled.
func prepareSNIWirePlan(ctx context.Context, cfg Config, configPath string) (sniWirePlan, []*sender.PreparedTLS, error) {
	if configPath == "" || cfg.PairedSNI == "" {
		return sniWirePlan{}, nil, errors.New("config path and paired_sni are required")
	}
	if err := cfg.Validate(); err != nil {
		return sniWirePlan{}, nil, fmt.Errorf("invalid config: %w", err)
	}
	names, err := pairedSNISchedule(cfg.SNI, cfg.PairedSNI, cfg.Schedule.Repetitions)
	if err != nil {
		return sniWirePlan{}, nil, err
	}
	plan := sniWirePlan{
		ExperimentID: cfg.ExperimentID, QuestionID: cfg.QuestionID, Mode: cfg.Mode, Endpoint: cfg.Endpoint,
		GapMS: cfg.Schedule.InterTrialGapMS, TimeoutMS: cfg.PairedTimeoutMS, StateReset: cfg.Schedule.StateReset, Budget: cfg.Budget,
		Rule:      cfg.ClassificationRule,
		WireNotes: "TCP segmentation and retransmissions are kernel-managed; TLS after ClientHello depends on the server; TLS randomness uses crypto/rand, not schedule seed",
	}
	sessions := make([]*sender.PreparedTLS, 0, len(names))
	complete := false
	defer func() {
		if !complete {
			for _, session := range sessions {
				session.Close()
			}
		}
	}()
	for _, name := range names {
		session, err := sender.PrepareTLS(ctx, name, nil)
		if err != nil {
			return sniWirePlan{}, nil, fmt.Errorf("prepare %q: %w", name, err)
		}
		sessions = append(sessions, session)
		payload := session.ClientHello()
		plan.Trials = append(plan.Trials, sniWireTrial{SNI: name, Packet: generator.PlannedWirePacket{
			Payload: payload, TLSRecordEnds: []int{len(payload)},
		}})
	}
	data, err := yaml.Marshal(plan)
	if err != nil {
		return sniWirePlan{}, nil, fmt.Errorf("marshal wire plan: %w", err)
	}
	if err := writeNewSNIWirePlan(filepath.Join(filepath.Dir(configPath), "plan.yaml"), data); err != nil {
		return sniWirePlan{}, nil, err
	}
	complete = true
	return plan, sessions, nil
}

func writeNewSNIWirePlan(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".wire-plan-*")
	if err != nil {
		return fmt.Errorf("create temporary wire plan: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return fmt.Errorf("set wire plan permissions: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write wire plan: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close wire plan: %w", err)
	}
	if err := os.Link(f.Name(), path); err != nil {
		return fmt.Errorf("install wire plan (existing plans are not replaced): %w", err)
	}
	return nil
}
