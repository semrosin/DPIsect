package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/semrosin/DPIsect/internal/capture"
	"github.com/semrosin/DPIsect/internal/generator"
	"github.com/semrosin/DPIsect/internal/sender"
)

// rawFakeSettle gives the fake probe time to reach the endpoint before
// the real ClientHello follows in the same connection.
const rawFakeSettle = 100 * time.Millisecond

// RawPlanFile is the D01–D04 plan persisted before the first packet.
// Unlike the valid plan it keeps field modes, not a resolved sequence
// space: SEQ/ACK depend on the live handshake.
type RawPlanFile struct {
	ExperimentID    string       `yaml:"experiment_id"`
	QuestionID      string       `yaml:"question_id"`
	Mode            string       `yaml:"mode"`
	Sequence        string       `yaml:"sequence"`
	TimeoutMS       int          `yaml:"timeout_ms"`
	Fake            *RawPlanFake `yaml:"fake,omitempty"`
	RealClientHello []byte       `yaml:"real_client_hello"`
}

// RawPlanFake is the exact fake payload and field modes of one arm.
type RawPlanFake struct {
	Payload     []byte `yaml:"payload"`
	TTL         uint8  `yaml:"ttl"`
	Seq         string `yaml:"seq"`
	Ack         string `yaml:"ack"`
	Checksum    string `yaml:"checksum"`
	SendAfterMS int64  `yaml:"send_after_ms"`
}

// RawTrialObservation is the runner-side record for one repetition.
// The offline analyzer checks it against the client PCAP.
type RawTrialObservation struct {
	Repetition        int               `json:"repetition"`
	StartedUTC        string            `json:"started_utc"`
	FinishedUTC       string            `json:"finished_utc"`
	Sequence          string            `json:"sequence"`
	FakeSent          bool              `json:"fake_sent"`
	FakeBytes         int               `json:"fake_bytes"`
	FakePayloadSHA256 string            `json:"fake_payload_sha256"`
	FakeTTL           uint8             `json:"fake_ttl"`
	FakeSeqMode       string            `json:"fake_seq_mode"`
	FakeAckMode       string            `json:"fake_ack_mode"`
	FakeChecksumMode  string            `json:"fake_checksum_mode"`
	FakeSeq           uint32            `json:"fake_seq"`
	FakeAck           uint32            `json:"fake_ack"`
	FakeChecksum      uint16            `json:"fake_checksum"`
	Flow              generator.RawFlow `json:"flow"`
	RealBytes         int               `json:"real_client_hello_bytes"`
	RealPayloadSHA256 string            `json:"real_payload_sha256"`
	RealWritten       bool              `json:"real_client_hello_written"`
	Error             string            `json:"error,omitempty"`
}

// RawObservations is experiments/<id>/raw-observations.json.
type RawObservations struct {
	ExperimentID string                `json:"experiment_id"`
	QuestionID   string                `json:"question_id"`
	Mode         string                `json:"mode"`
	Sequence     string                `json:"sequence"`
	Trials       []RawTrialObservation `json:"trials"`
}

type rawBudget struct {
	packets int
	bytes   int
	last    time.Time
	minGap  time.Duration
	limit   Budget
}

func (b *rawBudget) before(ctx context.Context, bytes int) error {
	if b.packets+1 > b.limit.MaxPackets {
		return fmt.Errorf("budget: max_packets %d exceeded (docs/SAFETY.md §3)", b.limit.MaxPackets)
	}
	if b.bytes+bytes > b.limit.MaxBytes {
		return fmt.Errorf("budget: max_bytes %d exceeded (docs/SAFETY.md §3)", b.limit.MaxBytes)
	}
	if !b.last.IsZero() {
		if wait := b.minGap - time.Since(b.last); wait > 0 {
			if err := sleepCtx(ctx, wait); err != nil {
				return fmt.Errorf("rate limit: %w", err)
			}
		}
	}
	return nil
}

func (b *rawBudget) after(bytes int) {
	b.packets++
	b.bytes += bytes
	b.last = time.Now()
}

func runRaw(ctx context.Context, cfg Config, opts Options) error {
	if cfg.Raw == nil {
		return errors.New("raw config is required")
	}
	if opts.ConfigPath == "" {
		return errors.New("config path is required to place plan.yaml and run.json")
	}
	if cfg.Lab.Enabled {
		return fmt.Errorf("lab profile %q: %w", cfg.Lab.ConfigID, ErrNotImplemented)
	}

	expDir := filepath.Dir(opts.ConfigPath)
	started := time.Now().UTC()
	logFile, logger, err := openRunLogger(cfg.RunnerLog)
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()

	logger.Info("run start", "event", "run_start",
		"experiment", cfg.ExperimentID, "mode", cfg.Mode,
		"endpoint", net.JoinHostPort(cfg.Endpoint.IP, strconv.Itoa(cfg.Endpoint.Port)),
		"operator", opts.Operator, "sequence", cfg.Raw.Sequence)

	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Budget.MaxDurationS)*time.Second)
	defer cancel()

	var fakeRnd, realRnd [32]byte
	rand.New(rand.NewSource(cfg.Schedule.Seed)).Read(fakeRnd[:])
	rand.New(rand.NewSource(cfg.Schedule.Seed + 1)).Read(realRnd[:])
	fakePayload, err := generator.BuildClientHello(cfg.SNI, fakeRnd)
	if err != nil {
		return fmt.Errorf("build fake ClientHello: %w", err)
	}
	realPayload, err := generator.BuildClientHello(cfg.SNI, realRnd)
	if err != nil {
		return fmt.Errorf("build real ClientHello: %w", err)
	}

	plan := RawPlanFile{
		ExperimentID:    cfg.ExperimentID,
		QuestionID:      cfg.QuestionID,
		Mode:            cfg.Mode,
		Sequence:        cfg.Raw.Sequence,
		TimeoutMS:       cfg.Raw.TimeoutMS,
		RealClientHello: realPayload,
	}
	if cfg.Raw.Fake.Enabled {
		plan.Fake = &RawPlanFake{
			Payload:     fakePayload,
			TTL:         cfg.Raw.Fake.TTL,
			Seq:         cfg.Raw.Fake.Seq,
			Ack:         cfg.Raw.Fake.Ack,
			Checksum:    cfg.Raw.Fake.Checksum,
			SendAfterMS: cfg.Raw.Fake.SendAfterMS,
		}
	}
	planPath := filepath.Join(expDir, "plan.yaml")
	if err := writeYAMLExclusive(planPath, plan); err != nil {
		return err
	}
	logger.Info("raw plan written", "event", "plan_written", "path", planPath)

	if opts.CaptureIface == "" {
		return errors.New("raw-experiment requires -capture-iface for actual-wire validation")
	}
	live := capture.NewLive(capture.PointClient, opts.CaptureIface, cfg.Capture.Client)
	if err := live.Start(ctx); err != nil {
		return fmt.Errorf("start capture: %w", err)
	}
	defer func() { _ = live.Stop(context.Background()) }()
	logger.Info("capture started", "event", "capture_start",
		"point", "client", "iface", opts.CaptureIface, "path", cfg.Capture.Client)

	rawSender, err := sender.NewRaw()
	if err != nil {
		return err
	}
	defer func() { _ = rawSender.Close() }()

	endpointIP := net.ParseIP(cfg.Endpoint.IP).To4()
	addr := net.JoinHostPort(cfg.Endpoint.IP, strconv.Itoa(cfg.Endpoint.Port))
	timeout := time.Duration(cfg.Raw.TimeoutMS) * time.Millisecond
	budget := &rawBudget{
		minGap: time.Second / time.Duration(cfg.Budget.MaxRatePPS),
		limit:  cfg.Budget,
	}
	obs := RawObservations{
		ExperimentID: cfg.ExperimentID,
		QuestionID:   cfg.QuestionID,
		Mode:         cfg.Mode,
		Sequence:     cfg.Raw.Sequence,
	}

	for rep := 0; rep < cfg.Schedule.Repetitions; rep++ {
		trial := runRawTrial(ctx, cfg, opts.CaptureIface, addr, endpointIP, timeout,
			rawSender, budget, fakePayload, realPayload, rep, logger)
		obs.Trials = append(obs.Trials, trial)
		if trial.Error != "" {
			logger.Warn("raw trial failed", "event", "trial_error",
				"repetition", rep+1, "error", trial.Error)
		}
		if rep+1 < cfg.Schedule.Repetitions {
			gap := time.Duration(cfg.Schedule.InterTrialGapMS) * time.Millisecond
			if err := sleepCtx(ctx, gap); err != nil {
				return fmt.Errorf("inter-trial gap: %w", err)
			}
		}
	}

	if err := live.Stop(context.Background()); err != nil {
		return fmt.Errorf("stop capture: %w", err)
	}
	obsPath := filepath.Join(expDir, "raw-observations.json")
	if err := writeJSON(obsPath, obs); err != nil {
		return err
	}
	if err := logFile.Close(); err != nil {
		return fmt.Errorf("close runner_log: %w", err)
	}

	artifacts, err := hashArtifacts(logger, []string{cfg.Capture.Client, cfg.RunnerLog, obsPath})
	if err != nil {
		return err
	}
	rec := RunRecord{
		ExperimentID:       cfg.ExperimentID,
		QuestionID:         cfg.QuestionID,
		ToolVersion:        opts.ToolVersion,
		ToolCommit:         opts.ToolCommit,
		DependencyVersions: dependencyVersions(),
		Seed:               cfg.Schedule.Seed,
		StartedUTC:         started.Format(time.RFC3339),
		FinishedUTC:        time.Now().UTC().Format(time.RFC3339),
		Operator:           opts.Operator,
		ConfigFile:         opts.ConfigPath,
		LabConfigID:        cfg.Lab.ConfigID,
		Artifacts:          artifacts,
	}
	return WriteRun(expDir, rec)
}

func runRawTrial(
	parent context.Context,
	cfg Config,
	iface string,
	addr string,
	endpointIP net.IP,
	timeout time.Duration,
	rawSender *sender.Raw,
	budget *rawBudget,
	fakePayload, realPayload []byte,
	rep int,
	logger *slog.Logger,
) (trial RawTrialObservation) {
	started := time.Now().UTC()
	trial = RawTrialObservation{
		Repetition:        rep + 1,
		StartedUTC:        started.Format(time.RFC3339Nano),
		Sequence:          cfg.Raw.Sequence,
		FakeTTL:           cfg.Raw.Fake.TTL,
		FakeSeqMode:       cfg.Raw.Fake.Seq,
		FakeAckMode:       cfg.Raw.Fake.Ack,
		FakeChecksumMode:  cfg.Raw.Fake.Checksum,
		FakePayloadSHA256: payloadSHA256(fakePayload),
		RealBytes:         len(realPayload),
		RealPayloadSHA256: payloadSHA256(realPayload),
	}
	defer func() { trial.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano) }()

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	if !cfg.Raw.Fake.Enabled {
		conn, err := dialRaw(ctx, addr, timeout)
		if err != nil {
			trial.Error = err.Error()
			return trial
		}
		if err := writeClientHello(conn, realPayload, budget, ctx); err != nil {
			trial.Error = err.Error()
			_ = conn.Close()
			return trial
		}
		trial.RealWritten = true
		if err := sleepCtx(ctx, rawFakeSettle); err != nil {
			trial.Error = err.Error()
		}
		_ = conn.Close()
		return trial
	}

	tracker, err := newRawFlowTracker(iface, endpointIP, cfg.Endpoint.Port)
	if err != nil {
		trial.Error = err.Error()
		return trial
	}
	defer tracker.Close()

	conn, err := dialRaw(ctx, addr, timeout)
	if err != nil {
		trial.Error = err.Error()
		return trial
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = conn.Close()
		trial.Error = "local address is not TCP"
		return trial
	}
	tracker.Start(local.IP, local.Port)
	flow, err := tracker.Wait(ctx)
	if err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}
	trial.Flow = flow

	if err := sleepCtx(ctx, time.Duration(cfg.Raw.Fake.SendAfterMS)*time.Millisecond); err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}
	seq, err := generator.ResolveRawSequence(cfg.Raw.Fake.Seq, flow.SndNxt, len(fakePayload))
	if err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}
	ack, err := generator.ResolveRawAck(cfg.Raw.Fake.Ack, flow.RcvNxt)
	if err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}
	pkt := generator.PlannedWirePacket{
		Payload:         fakePayload,
		TTL:             cfg.Raw.Fake.TTL,
		Seq:             seq,
		Ack:             ack,
		CorruptChecksum: cfg.Raw.Fake.Checksum == RawFieldCorrupt,
	}
	raw, err := generator.BuildRawIPv4TCP(pkt, flow)
	if err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}
	trial.FakeSeq = seq
	trial.FakeAck = ack
	trial.FakeChecksum = uint16(raw[36])<<8 | uint16(raw[37])
	if err := budget.before(ctx, len(fakePayload)); err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}
	if err := rawSender.SendIPv4(ctx, raw, endpointIP); err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}
	budget.after(len(fakePayload))
	trial.FakeSent = true
	trial.FakeBytes = len(fakePayload)
	logger.Info("raw fake sent", "event", "fake_sent",
		"repetition", rep+1, "ttl", cfg.Raw.Fake.TTL,
		"seq", seq, "ack", ack, "checksum", trial.FakeChecksum)

	if err := sleepCtx(ctx, rawFakeSettle); err != nil {
		_ = conn.Close()
		trial.Error = err.Error()
		return trial
	}

	if cfg.Raw.Sequence == RawSequenceFreshTCP {
		_ = conn.Close()
		conn, err = dialRaw(ctx, addr, timeout)
		if err != nil {
			trial.Error = err.Error()
			return trial
		}
	}
	if err := writeClientHello(conn, realPayload, budget, ctx); err != nil {
		trial.Error = err.Error()
		_ = conn.Close()
		return trial
	}
	trial.RealWritten = true
	if err := sleepCtx(ctx, rawFakeSettle); err != nil {
		trial.Error = err.Error()
	}
	_ = conn.Close()
	return trial
}

func dialRaw(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	return conn, nil
}

func writeClientHello(conn net.Conn, payload []byte, budget *rawBudget, ctx context.Context) error {
	if err := budget.before(ctx, len(payload)); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("write ClientHello: %w", err)
	}
	budget.after(len(payload))
	return nil
}

func writeYAMLExclusive(path string, v any) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create dir for %s: %w", filepath.Base(path), err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	return nil
}

func payloadSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", filepath.Base(path), err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create dir for %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}
