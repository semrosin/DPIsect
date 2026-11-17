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
	SNI     string                       `yaml:"sni,omitempty"`
	Variant string                       `yaml:"variant,omitempty"`
	Shape   *HelloVariant                `yaml:"shape,omitempty"`
	Packet  *generator.PlannedWirePacket `yaml:"packet,omitempty"`
}

type sniWirePlan struct {
	ExperimentID       string         `yaml:"experiment_id"`
	QuestionID         string         `yaml:"question_id"`
	Mode               string         `yaml:"mode"`
	TCPOnly            bool           `yaml:"tcp_only,omitempty"`
	Endpoint           Endpoint       `yaml:"endpoint"`
	Trials             []sniWireTrial `yaml:"trials"`
	GapMS              int            `yaml:"inter_trial_gap_ms"`
	TimeoutMS          int            `yaml:"trial_timeout_ms"`
	ClientHelloDelayMS int            `yaml:"client_hello_delay_ms,omitempty"`
	StateReset         string         `yaml:"state_reset"`
	Budget             Budget         `yaml:"budget"`
	Rule               string         `yaml:"classification_rule"`
	WireNotes          string         `yaml:"wire_notes"`
}

// prepareTCPWirePlan records the kernel-managed TCP control before any dial.
func prepareTCPWirePlan(cfg Config, configPath string) (sniWirePlan, error) {
	if configPath == "" || !cfg.TCPOnly {
		return sniWirePlan{}, errors.New("config path and tcp_only are required")
	}
	if err := cfg.Validate(); err != nil {
		return sniWirePlan{}, fmt.Errorf("invalid config: %w", err)
	}
	plan := sniWirePlan{
		ExperimentID: cfg.ExperimentID, QuestionID: cfg.QuestionID, Mode: cfg.Mode,
		TCPOnly: true, Endpoint: cfg.Endpoint, GapMS: cfg.Schedule.InterTrialGapMS,
		TimeoutMS: cfg.TCPTimeoutMS, StateReset: cfg.Schedule.StateReset,
		Budget: cfg.Budget, Rule: cfg.ClassificationRule,
		WireNotes: fmt.Sprintf("ordinary TCP connect and close with no application data; kernel chooses sequence numbers, TCP options, TTL, checksums and retransmissions; capture continues up to %s after the final completed trial if the series is not canceled", postTrialCaptureWindow),
		Trials:    make([]sniWireTrial, cfg.Schedule.Repetitions),
	}
	data, err := yaml.Marshal(plan)
	if err != nil {
		return sniWirePlan{}, fmt.Errorf("marshal TCP plan: %w", err)
	}
	if err := writeNewSNIWirePlan(filepath.Join(filepath.Dir(configPath), "plan.yaml"), data); err != nil {
		return sniWirePlan{}, err
	}
	return plan, nil
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
	names, err := pairedSNIScheduleFor(cfg.SNI, cfg.PairedSNI, cfg.Schedule.Repetitions, cfg.PairedHello != nil)
	if err != nil {
		return sniWirePlan{}, nil, err
	}
	plan := sniWirePlan{
		ExperimentID: cfg.ExperimentID, QuestionID: cfg.QuestionID, Mode: cfg.Mode, Endpoint: cfg.Endpoint,
		GapMS: cfg.Schedule.InterTrialGapMS, TimeoutMS: cfg.PairedTimeoutMS, ClientHelloDelayMS: cfg.PairedClientHelloDelayMS, StateReset: cfg.Schedule.StateReset, Budget: cfg.Budget,
		Rule:      cfg.ClassificationRule,
		WireNotes: fmt.Sprintf("TCP segmentation and retransmissions are kernel-managed; TLS after ClientHello depends on the server; TLS randomness uses crypto/rand, not schedule seed; capture continues up to %s after the final completed trial if the series is not canceled", postTrialCaptureWindow),
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
	for i, name := range names {
		var session *sender.PreparedTLS
		var shape *HelloVariant
		variant := ""
		if cfg.PairedHello == nil {
			session, err = sender.PrepareTLS(ctx, name, nil)
		} else {
			variant = pairedVariant(i)
			value := cfg.PairedHello.Control
			if variant == "treatment" {
				value = cfg.PairedHello.Treatment
			}
			shape = &value
			session, err = sender.PrepareShapedTLS(ctx, name, nil, sender.HelloShape{RecordLength: value.RecordLength, SNIOffset: value.SNIOffset, IgnoredBytes: []byte(value.IgnoredData)})
		}
		if err != nil {
			return sniWirePlan{}, nil, fmt.Errorf("prepare %q: %w", name, err)
		}
		sessions = append(sessions, session)
		payload := session.ClientHello()
		plan.Trials = append(plan.Trials, sniWireTrial{SNI: name, Variant: variant, Shape: shape, Packet: &generator.PlannedWirePacket{
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
