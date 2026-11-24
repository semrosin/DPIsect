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
// experiments/<question_id>/<series>/<experiment_id>/config.yaml. The schema is mirrored by
// docs/config.example.yaml; report front-matter — docs/EXPERIMENTS.md §4.
type Config struct {
	QuestionID   string `yaml:"question_id"`
	ExperimentID string `yaml:"experiment_id"`
	Mode         string `yaml:"mode"`
	// SNI is the host name put into the ClientHello of a
	// valid-session run; raw plans carry their own bytes.
	SNI string `yaml:"sni"`
	// PairedSNI requests a paired comparison; SNI is the control name.
	PairedSNI string `yaml:"paired_sni,omitempty"`
	// PairedTimeoutMS bounds each TCP/TLS attempt.
	PairedTimeoutMS int `yaml:"paired_timeout_ms,omitempty"`
	// PairedClientHelloDelayMS delays TLS after TCP connects in paired runs.
	PairedClientHelloDelayMS int `yaml:"paired_client_hello_delay_ms,omitempty"`
	// PairedCloseDelayMS holds successful connections before closing.
	PairedCloseDelayMS int `yaml:"paired_close_delay_ms,omitempty"`
	// PairedHello enables independently shaped ClientHellos for B04/B07.
	PairedHello *PairedHello `yaml:"paired_hello,omitempty"`
	// PairedSplit selects intended first-write boundaries for C01.
	PairedSplit *PairedSplit `yaml:"paired_split,omitempty"`
	// TCPOnly runs ordinary TCP connectivity controls without application data.
	TCPOnly      bool         `yaml:"tcp_only,omitempty"`
	TCPTimeoutMS int          `yaml:"tcp_timeout_ms,omitempty"`
	Endpoint     Endpoint     `yaml:"endpoint"`
	Budget       Budget       `yaml:"budget"`
	Schedule     Schedule     `yaml:"schedule"`
	Capture      CapturePaths `yaml:"capture"`
	HelperLog    string       `yaml:"helper_log"`
	RunnerLog    string       `yaml:"runner_log"`
	// ClassificationRule must be fixed before the first packet is
	// sent (docs/EXPERIMENTS.md §2); the verdict is set by the
	// operator/agent, not by the analyzer (docs/EXPERIMENTS.md §7).
	ClassificationRule string    `yaml:"classification_rule"`
	Preflight          Preflight `yaml:"preflight"`
	Lab                Lab       `yaml:"lab"`
	// Raw controls the raw-experiment sequence (D01–D04). It is
	// required for mode raw-experiment and rejected otherwise.
	Raw *RawConfig `yaml:"raw,omitempty"`
}

// PairedSplit specifies offsets for alternating control and treatment trials.
type PairedSplit struct {
	Control   int    `yaml:"control"`
	Treatment int    `yaml:"treatment"`
	First     string `yaml:"first,omitempty"`
}

// HelloVariant defines exact ClientHello coordinates and ignored bytes.
type HelloVariant struct {
	RecordLength int    `yaml:"record_length"`
	SNIOffset    int    `yaml:"sni_offset"`
	IgnoredData  string `yaml:"ignored_data"`
}

// PairedHello specifies the control and treatment wire layouts.
type PairedHello struct {
	Control   HelloVariant `yaml:"control"`
	Treatment HelloVariant `yaml:"treatment"`
}

// RawConfig describes the single fake probe and how the real
// ClientHello follows it (docs/ARCHITECTURE.md §4, D01–D04).
type RawConfig struct {
	// Sequence is same_tcp (fake and real ClientHello share one TCP
	// connection) or fresh_tcp (fake uses a throwaway connection).
	Sequence string `yaml:"sequence"`
	// TimeoutMS bounds connection, flow tracking and probe settle.
	TimeoutMS int     `yaml:"timeout_ms"`
	Fake      RawFake `yaml:"fake"`
}

// RawFake is the deliberately malformed packet sent before the real
// ClientHello. Only one field may differ from the correct value in a
// given experiment arm; the runner enforces that independently.
type RawFake struct {
	Enabled     bool   `yaml:"enabled"`
	TTL         uint8  `yaml:"ttl"`
	Seq         string `yaml:"seq"`      // correct | out_of_order | old
	Ack         string `yaml:"ack"`      // correct | wrong
	Checksum    string `yaml:"checksum"` // correct | corrupt
	SendAfterMS int64  `yaml:"send_after_ms"`
}

const (
	RawSequenceSameTCP  = "same_tcp"
	RawSequenceFreshTCP = "fresh_tcp"

	RawFieldCorrect     = "correct"
	RawFieldOutOfOrder  = "out_of_order"
	RawFieldOld         = "old"
	RawFieldWrong       = "wrong"
	RawFieldCorrupt     = "corrupt"
	defaultRawTimeoutMS = 5000
)

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
	// MaxSYNRetransmissions is the per-connection observed retry threshold.
	// A nil value preserves historical configurations but cannot run paired probes.
	MaxSYNRetransmissions *int `yaml:"max_syn_retransmissions,omitempty"`
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
	if c.PairedSNI != "" && c.PairedTimeoutMS == 0 {
		c.PairedTimeoutMS = 5000
	}
	if c.TCPOnly && c.TCPTimeoutMS == 0 {
		c.TCPTimeoutMS = 5000
	}
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
	if c.Raw != nil {
		if c.Raw.Sequence == "" {
			c.Raw.Sequence = RawSequenceSameTCP
		}
		if c.Raw.TimeoutMS == 0 {
			c.Raw.TimeoutMS = defaultRawTimeoutMS
		}
		if c.Raw.Fake.Enabled {
			if c.Raw.Fake.TTL == 0 {
				c.Raw.Fake.TTL = 64
			}
			if c.Raw.Fake.Seq == "" {
				c.Raw.Fake.Seq = RawFieldCorrect
			}
			if c.Raw.Fake.Ack == "" {
				c.Raw.Fake.Ack = RawFieldCorrect
			}
			if c.Raw.Fake.Checksum == "" {
				c.Raw.Fake.Checksum = RawFieldCorrect
			}
		}
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
	if modeErr == nil && mode == generator.ValidSession && !c.TCPOnly && c.SNI == "" {
		errs = append(errs, errors.New(
			"sni is required for a valid-session run (ClientHello)"))
	}
	if c.TCPOnly {
		if modeErr == nil && mode != generator.ValidSession {
			errs = append(errs, errors.New("tcp_only requires valid-session mode"))
		}
		if c.SNI != "" || c.PairedSNI != "" {
			errs = append(errs, errors.New("tcp_only does not accept SNI fields"))
		}
		if ip := net.ParseIP(c.Endpoint.IP); ip == nil || ip.To4() == nil {
			errs = append(errs, errors.New("tcp_only requires an IPv4 endpoint"))
		}
		if c.TCPTimeoutMS <= 0 || int64(c.TCPTimeoutMS) > int64(c.Budget.MaxDurationS)*1000 {
			errs = append(errs, errors.New("tcp_timeout_ms must be positive and within the series duration"))
		}
		if c.Schedule.InterTrialGapMS < 0 || (c.Schedule.StateReset != "" && c.Schedule.StateReset != "none") {
			errs = append(errs, errors.New("tcp_only requires a nonnegative gap and state_reset: none"))
		}
		if c.Schedule.Repetitions > c.Budget.MaxPackets {
			errs = append(errs, errors.New("TCP attempts exceed packet budget before overhead"))
		}
		if c.Endpoint.Role == RoleTarget {
			limits := DefaultBudget()
			if c.Budget.MaxPackets > limits.MaxPackets || c.Budget.MaxBytes > limits.MaxBytes ||
				c.Budget.MaxRatePPS > limits.MaxRatePPS || c.Budget.MaxDurationS > limits.MaxDurationS {
				errs = append(errs, errors.New("TCP target budget exceeds target limits"))
			}
		}
	}
	if (c.TCPOnly || c.PairedSNI != "") && (c.Preflight.Enabled || c.Lab.Enabled) {
		errs = append(errs, errors.New("TCP and paired SNI runs do not support preflight or lab profiles"))
	}
	if c.PairedSNI == "" && c.PairedClientHelloDelayMS != 0 {
		errs = append(errs, errors.New("paired_client_hello_delay_ms requires paired_sni"))
	}
	if c.PairedSNI == "" && c.PairedCloseDelayMS != 0 {
		errs = append(errs, errors.New("paired_close_delay_ms requires paired_sni"))
	}
	if c.PairedSNI == "" && c.PairedTimeoutMS != 0 {
		errs = append(errs, errors.New("paired_timeout_ms requires paired_sni"))
	}
	if !c.TCPOnly && c.TCPTimeoutMS != 0 {
		errs = append(errs, errors.New("tcp_timeout_ms requires tcp_only"))
	}
	if c.PairedSplit != nil {
		if c.PairedSplit.First != "" && c.PairedSplit.First != "control" && c.PairedSplit.First != "treatment" {
			errs = append(errs, errors.New("paired_split.first must be control or treatment"))
		}
		if c.PairedSplit.First != "" && (c.PairedSplit.Control != 0 || c.PairedSplit.Treatment <= 0) {
			errs = append(errs, errors.New("explicit split order requires unsplit control and positive treatment offset"))
		}
		if c.PairedSNI == "" || c.TCPOnly || c.PairedSplit.Control < 0 || c.PairedSplit.Treatment < 0 || c.PairedSplit.Control == c.PairedSplit.Treatment {
			errs = append(errs, errors.New("paired_split requires paired_sni and distinct nonnegative offsets"))
		}
	}
	if c.PairedHello != nil {
		if c.PairedSNI == "" || c.TCPOnly {
			errs = append(errs, errors.New("paired_hello requires paired_sni"))
		}
		for _, v := range []HelloVariant{c.PairedHello.Control, c.PairedHello.Treatment} {
			if v.RecordLength <= 0 || v.RecordLength > 5+(1<<14) || v.SNIOffset <= 0 || v.SNIOffset >= v.RecordLength || len(v.IgnoredData) > 253 {
				errs = append(errs, errors.New("paired_hello requires valid record lengths, SNI offsets and ignored data"))
			}
		}
		if c.PairedSplit == nil && strings.EqualFold(c.SNI, c.PairedSNI) && c.PairedHello.Control == c.PairedHello.Treatment {
			errs = append(errs, errors.New("paired_hello variants must differ when SNI is identical"))
		}
	}
	if c.PairedSNI != "" {
		if ip := net.ParseIP(c.Endpoint.IP); ip == nil || ip.To4() == nil {
			errs = append(errs, errors.New("paired SNI requires an IPv4 endpoint"))
		}
		if c.Schedule.StateReset != "" && c.Schedule.StateReset != "none" {
			errs = append(errs, errors.New("paired SNI supports only state_reset: none"))
		}
		if c.PairedTimeoutMS <= 0 || int64(c.PairedTimeoutMS) > int64(c.Budget.MaxDurationS)*1000 {
			errs = append(errs, errors.New("paired_timeout_ms must be positive and within the series duration"))
		}
		if c.PairedClientHelloDelayMS < 0 || c.PairedClientHelloDelayMS >= c.PairedTimeoutMS {
			errs = append(errs, errors.New("paired_client_hello_delay_ms must be nonnegative and shorter than paired_timeout_ms"))
		}
		if c.PairedCloseDelayMS < 0 || int64(c.PairedCloseDelayMS)+int64(c.PairedClientHelloDelayMS) >= int64(c.PairedTimeoutMS) {
			errs = append(errs, errors.New("paired_close_delay_ms must be nonnegative and both delays must fit within paired_timeout_ms"))
		}
		if modeErr == nil && mode != generator.ValidSession {
			errs = append(errs, errors.New("paired_sni requires valid-session mode"))
		}
		if _, err := pairedSNIScheduleFor(c.SNI, c.PairedSNI, 1, c.PairedHello != nil || c.PairedSplit != nil); err != nil {
			errs = append(errs, err)
		}
		if c.Schedule.Repetitions > c.Budget.MaxPackets/2 {
			errs = append(errs, errors.New("paired attempts exceed packet budget before TCP overhead"))
		}
		for _, name := range []string{c.SNI, c.PairedSNI} {
			if _, err := generator.BuildClientHello(name, [32]byte{}); err != nil {
				errs = append(errs, fmt.Errorf("invalid paired SNI: %w", err))
			}
		}
		if c.Schedule.InterTrialGapMS < 0 {
			errs = append(errs, errors.New("paired inter_trial_gap_ms must not be negative"))
		}
		if c.Endpoint.Role == RoleTarget {
			limits := DefaultBudget()
			if c.Budget.MaxPackets > limits.MaxPackets || c.Budget.MaxBytes > limits.MaxBytes ||
				c.Budget.MaxRatePPS > limits.MaxRatePPS || c.Budget.MaxDurationS > limits.MaxDurationS {
				errs = append(errs, errors.New("paired target budget exceeds target limits"))
			}
		}
	}
	if modeErr == nil && mode == generator.RawExperiment && c.Endpoint.Role == RoleTarget {
		errs = append(errs, errors.New(
			"raw-experiment against target is forbidden (docs/SAFETY.md §1)"))
	}
	if modeErr == nil {
		errs = append(errs, c.validateRaw(mode)...)
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
	if c.Budget.MaxSYNRetransmissions != nil && *c.Budget.MaxSYNRetransmissions <= 0 {
		errs = append(errs, errors.New("budget.max_syn_retransmissions must be positive"))
	}

	if c.Schedule.Repetitions < 1 {
		errs = append(errs, errors.New("schedule.repetitions must be at least 1"))
	}

	if c.Capture.Client == "" {
		errs = append(errs, errors.New("capture.client path is required"))
	}
	if c.Capture.Server == "" && !((c.PairedSNI != "" || c.TCPOnly) && c.Endpoint.Role == RoleTarget) {
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

// validateRaw checks the D01–D04 sequence contract and keeps raw
// blocks out of the valid-session path.
func (c Config) validateRaw(mode generator.Mode) []error {
	if mode == generator.ValidSession {
		if c.Raw != nil {
			return []error{errors.New("raw block is only valid with mode raw-experiment")}
		}
		return nil
	}
	if c.Raw == nil {
		return []error{errors.New(
			"raw block is required for mode raw-experiment (D01–D04)")}
	}
	if c.SNI == "" {
		return []error{errors.New("sni is required for a raw-experiment ClientHello")}
	}
	if ip := net.ParseIP(c.Endpoint.IP); ip == nil || ip.To4() == nil {
		return []error{fmt.Errorf(
			"raw-experiment requires an IPv4 endpoint, got %q", c.Endpoint.IP)}
	}

	var errs []error
	switch c.Raw.Sequence {
	case RawSequenceSameTCP, RawSequenceFreshTCP:
	default:
		errs = append(errs, fmt.Errorf(
			"raw.sequence %q must be same_tcp or fresh_tcp", c.Raw.Sequence))
	}
	if c.Raw.TimeoutMS < 1 || c.Raw.TimeoutMS > c.Budget.MaxDurationS*1000 {
		errs = append(errs, fmt.Errorf(
			"raw.timeout_ms %d out of range 1-%d",
			c.Raw.TimeoutMS, c.Budget.MaxDurationS*1000))
	}
	if c.Raw.Sequence == RawSequenceFreshTCP && !c.Raw.Fake.Enabled {
		errs = append(errs, errors.New(
			"raw.sequence fresh_tcp requires raw.fake.enabled"))
	}
	if !c.Raw.Fake.Enabled {
		return errs
	}
	if c.Raw.Fake.TTL == 0 {
		errs = append(errs, errors.New("raw.fake.ttl must be 1-255"))
	}
	switch c.Raw.Fake.Seq {
	case RawFieldCorrect, RawFieldOutOfOrder, RawFieldOld:
	default:
		errs = append(errs, fmt.Errorf(
			"raw.fake.seq %q must be correct, out_of_order or old", c.Raw.Fake.Seq))
	}
	switch c.Raw.Fake.Ack {
	case RawFieldCorrect, RawFieldWrong:
	default:
		errs = append(errs, fmt.Errorf(
			"raw.fake.ack %q must be correct or wrong", c.Raw.Fake.Ack))
	}
	switch c.Raw.Fake.Checksum {
	case RawFieldCorrect, RawFieldCorrupt:
	default:
		errs = append(errs, fmt.Errorf(
			"raw.fake.checksum %q must be correct or corrupt", c.Raw.Fake.Checksum))
	}
	if c.Raw.Fake.SendAfterMS < 0 {
		errs = append(errs, fmt.Errorf(
			"raw.fake.send_after_ms %d must not be negative", c.Raw.Fake.SendAfterMS))
	}
	return errs
}

// GeneratorMode returns the validated experiment mode.
func (c Config) GeneratorMode() (generator.Mode, error) {
	return generator.ParseMode(c.Mode)
}
