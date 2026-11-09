// Package runner orchestrates one experiment run: it loads the
// config, enforces the safety gates, then drives the generator,
// sender and capture (docs/ARCHITECTURE.md §1, §4).
package runner

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/semrosin/DPIsect/internal/generator"
	"gopkg.in/yaml.v3"
)

// Endpoint roles as defined by docs/SAFETY.md §1.
const (
	RoleLab    = "lab"
	RoleHelper = "helper"
	RoleTarget = "target"
)

// ErrNotImplemented is returned by run paths that exist as contracts
// only; stage-1 code lands per docs/DEVELOPMENT.md.
var ErrNotImplemented = errors.New("run not implemented yet (stage 1, docs/DEVELOPMENT.md)")

// Config is the experiment run configuration loaded from
// experiments/<experiment_id>/config.yaml. The schema is mirrored by
// docs/config.example.yaml; report front-matter — docs/EXPERIMENTS.md §4.
type Config struct {
	QuestionID   string `yaml:"question_id"`
	ExperimentID string `yaml:"experiment_id"`
	Mode         string `yaml:"mode"`
	// SNI is the host name put into the ClientHello of a
	// valid-session run; raw plans carry their own bytes.
	SNI       string       `yaml:"sni"`
	Endpoint  Endpoint     `yaml:"endpoint"`
	Budget    Budget       `yaml:"budget"`
	Schedule  Schedule     `yaml:"schedule"`
	Capture   CapturePaths `yaml:"capture"`
	HelperLog string       `yaml:"helper_log"`
	RunnerLog string       `yaml:"runner_log"`
	// ClassificationRule must be fixed before the first packet is
	// sent (docs/EXPERIMENTS.md §2); the verdict is set by the
	// operator/agent, not by the analyzer (docs/EXPERIMENTS.md §7).
	ClassificationRule string    `yaml:"classification_rule"`
	Preflight          Preflight `yaml:"preflight"`
	Lab                Lab       `yaml:"lab"`
}

// Endpoint is the single destination of the run.
type Endpoint struct {
	Role string `yaml:"role"` // lab | helper | target
	IP   string `yaml:"ip"`
	Port int    `yaml:"port"`
}

// Budget are the per-series limits of docs/SAFETY.md §3. Zero fields
// are replaced by DefaultBudget values at load time.
type Budget struct {
	MaxPackets     int      `yaml:"max_packets"`
	MaxBytes       int      `yaml:"max_bytes"`
	MaxRatePPS     int      `yaml:"max_rate_pps"`
	MaxDurationS   int      `yaml:"max_duration_s"`
	StopConditions []string `yaml:"stop_conditions"`
}

// Schedule controls repetitions and randomness of a run.
type Schedule struct {
	Repetitions     int    `yaml:"repetitions"`
	Seed            int64  `yaml:"seed"`
	InterTrialGapMS int    `yaml:"inter_trial_gap_ms"`
	StateReset      string `yaml:"state_reset"`
}

// CapturePaths are the two PCAP destinations, outside git
// (docs/SAFETY.md §5).
type CapturePaths struct {
	Client string `yaml:"client"`
	Server string `yaml:"server"`
}

// Preflight configures availability checks before the series
// (G01, G02; docs/ARCHITECTURE.md §1).
type Preflight struct {
	Enabled bool `yaml:"enabled"`
	// Host is the name resolved by both sources (G01).
	Host string `yaml:"host"`
	// IndependentResolver is the second source, e.g. "8.8.8.8:53".
	IndependentResolver string `yaml:"independent_resolver"`
}

// Lab selects the impairment profile for lab runs
// (docs/ARCHITECTURE.md §1); ConfigID is recorded as lab_config_id
// for reproducibility (H07).
type Lab struct {
	Enabled        bool    `yaml:"enabled"`
	ConfigID       string  `yaml:"config_id"`
	LossPercent    float64 `yaml:"loss_percent"`
	ReorderPercent float64 `yaml:"reorder_percent"`
	DelayMS        int     `yaml:"delay_ms"`
	// MTU is zero when the link MTU is left unchanged.
	MTU int `yaml:"mtu"`
}

// DefaultBudget returns the starting limits of docs/SAFETY.md §3.
func DefaultBudget() Budget {
	return Budget{
		MaxPackets:   100,
		MaxBytes:     100 * 1024,
		MaxRatePPS:   10,
		MaxDurationS: 60,
	}
}

// Load reads, validates and defaults a config file. Unknown fields
// are an error so that typos cannot silently disable a limit.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer func() {
		// Closing a read-only file cannot affect the result.
		_ = f.Close()
	}()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

// applyDefaults fills zero budget fields with docs/SAFETY.md §3
// starting limits (docs/EXPERIMENTS.md §4).
func (c *Config) applyDefaults() {
	d := DefaultBudget()
	if c.Budget.MaxPackets == 0 {
		c.Budget.MaxPackets = d.MaxPackets
	}
	if c.Budget.MaxBytes == 0 {
		c.Budget.MaxBytes = d.MaxBytes
	}
	if c.Budget.MaxRatePPS == 0 {
		c.Budget.MaxRatePPS = d.MaxRatePPS
	}
	if c.Budget.MaxDurationS == 0 {
		c.Budget.MaxDurationS = d.MaxDurationS
	}
}

// Validate reports every violated rule at once.
func (c Config) Validate() error {
	var errs []error

	if c.QuestionID == "" {
		errs = append(errs, errors.New("question_id is required"))
	}
	if c.ExperimentID == "" {
		errs = append(errs, errors.New("experiment_id is required"))
	} else if c.QuestionID != "" &&
		!strings.HasPrefix(c.ExperimentID, strings.ToLower(c.QuestionID)+"-") {
		errs = append(errs, fmt.Errorf(
			"experiment_id %q must start with %q (docs/EXPERIMENTS.md §4)",
			c.ExperimentID, strings.ToLower(c.QuestionID)+"-"))
	}

	mode, modeErr := generator.ParseMode(c.Mode)
	if modeErr != nil {
		errs = append(errs, modeErr)
	}

	switch c.Endpoint.Role {
	case RoleLab, RoleHelper, RoleTarget:
	default:
		errs = append(errs, fmt.Errorf(
			"endpoint.role %q must be lab, helper or target", c.Endpoint.Role))
	}
	if modeErr == nil && mode == generator.ValidSession && c.SNI == "" {
		errs = append(errs, errors.New(
			"sni is required for a valid-session run (ClientHello)"))
	}
	if modeErr == nil && mode == generator.RawExperiment && c.Endpoint.Role == RoleTarget {
		errs = append(errs, errors.New(
			"raw-experiment against target is forbidden (docs/SAFETY.md §1)"))
	}
	if net.ParseIP(c.Endpoint.IP) == nil {
		errs = append(errs, fmt.Errorf("endpoint.ip %q is not a valid IP", c.Endpoint.IP))
	}
	if c.Endpoint.Port < 1 || c.Endpoint.Port > 65535 {
		errs = append(errs, fmt.Errorf("endpoint.port %d out of range 1-65535", c.Endpoint.Port))
	}

	if c.Budget.MaxPackets <= 0 {
		errs = append(errs, errors.New("budget.max_packets must be positive"))
	}
	if c.Budget.MaxBytes <= 0 {
		errs = append(errs, errors.New("budget.max_bytes must be positive"))
	}
	if c.Budget.MaxRatePPS <= 0 {
		errs = append(errs, errors.New("budget.max_rate_pps must be positive"))
	}
	if c.Budget.MaxDurationS <= 0 {
		errs = append(errs, errors.New("budget.max_duration_s must be positive"))
	}

	if c.Schedule.Repetitions < 1 {
		errs = append(errs, errors.New("schedule.repetitions must be at least 1"))
	}

	if c.Capture.Client == "" {
		errs = append(errs, errors.New("capture.client path is required"))
	}
	if c.Capture.Server == "" {
		errs = append(errs, errors.New("capture.server path is required"))
	}
	if c.RunnerLog == "" {
		errs = append(errs, errors.New("runner_log path is required"))
	}
	if c.ClassificationRule == "" {
		errs = append(errs, errors.New(
			"classification_rule must be fixed before the first packet (docs/EXPERIMENTS.md §2)"))
	}

	if c.Preflight.Enabled {
		if c.Preflight.Host == "" {
			errs = append(errs, errors.New(
				"preflight.host is required when preflight.enabled (G01)"))
		}
		if c.Preflight.IndependentResolver == "" {
			errs = append(errs, errors.New(
				"preflight.independent_resolver is required when preflight.enabled (G01)"))
		}
	}

	if c.Lab.Enabled && c.Lab.ConfigID == "" {
		errs = append(errs, errors.New(
			"lab.config_id is required when lab.enabled (H07)"))
	}
	if c.Lab.LossPercent < 0 || c.Lab.LossPercent > 100 {
		errs = append(errs, fmt.Errorf(
			"lab.loss_percent %v out of range 0-100", c.Lab.LossPercent))
	}
	if c.Lab.ReorderPercent < 0 || c.Lab.ReorderPercent > 100 {
		errs = append(errs, fmt.Errorf(
			"lab.reorder_percent %v out of range 0-100", c.Lab.ReorderPercent))
	}
	if c.Lab.DelayMS < 0 {
		errs = append(errs, fmt.Errorf(
			"lab.delay_ms %d must not be negative", c.Lab.DelayMS))
	}
	if c.Lab.MTU < 0 {
		errs = append(errs, fmt.Errorf(
			"lab.mtu %d must not be negative", c.Lab.MTU))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// GeneratorMode returns the validated experiment mode.
func (c Config) GeneratorMode() (generator.Mode, error) {
	return generator.ParseMode(c.Mode)
}
