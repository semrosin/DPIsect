package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/semrosin/DPIsect/internal/capture"
	"github.com/semrosin/DPIsect/internal/dnsprobe"
	"github.com/semrosin/DPIsect/internal/generator"
	"github.com/semrosin/DPIsect/internal/sender"
)

// Options are run-time gates and metadata that must not live in the
// config file.
type Options struct {
	// AllowRaw confirms a raw-experiment run. The flag is the
	// explicit confirmation required by docs/GO_STYLE.md §4; without
	// it Run refuses even a valid raw config.
	AllowRaw bool
	// Operator, ToolVersion and ToolCommit are recorded in run.json
	// (H07; docs/ARCHITECTURE.md §4).
	Operator    string
	ToolVersion string
	ToolCommit  string
	// ConfigPath is the loaded config file path; plan.yaml, run.json
	// and dns_log.yaml are written to its directory.
	ConfigPath string
	// CaptureIface enables the client-side PCAP capture on that
	// interface (requires CAP_NET_RAW; empty: no capture).
	CaptureIface string
}

// sendSession is the runner-side view of a sender: plan packets plus
// an explicit teardown per repetition.
type sendSession interface {
	Send(ctx context.Context, p generator.PlannedWirePacket) error
	Close() error
}

// dependencies are injectable for tests (docs/GO_STYLE.md §6).
type dependencies struct {
	checkPreflight func(ctx context.Context, cfg Config) (dnsprobe.Report, error)
	newSender      func(addr string) sendSession
	// settle is how long a connection stays open after its last
	// packet so the helper can answer before the socket closes.
	settle time.Duration
}

func defaultDependencies() dependencies {
	return dependencies{
		checkPreflight: func(ctx context.Context, cfg Config) (dnsprobe.Report, error) {
			return dnsprobe.New(cfg.Preflight.IndependentResolver).Check(
				ctx, cfg.Preflight.Host, cfg.Endpoint.IP, cfg.Endpoint.Port)
		},
		newSender: func(addr string) sendSession { return sender.NewOS(addr) },
		settle:    settleAfterSend,
	}
}

// Run executes one experiment according to cfg: safety gates first,
// then preflight, plan persistence, capture and the budgeted send
// loop, finishing with run.json (docs/ARCHITECTURE.md §2).
func Run(ctx context.Context, cfg Config, opts Options) error {
	mode, err := cfg.GeneratorMode()
	if err != nil {
		return fmt.Errorf("resolve mode: %w", err)
	}
	if mode == generator.RawExperiment && !opts.AllowRaw {
		return errors.New(
			"raw-experiment requires explicit confirmation: pass -allow-raw (docs/SAFETY.md §1)")
	}
	if mode == generator.RawExperiment {
		// TODO(semrosin): raw-socket sender for crafted packets;
		// the plan builder and the -allow-raw gate already exist.
		return fmt.Errorf("raw-experiment sending: %w", sender.ErrNotImplemented)
	}
	if opts.ConfigPath == "" {
		return errors.New("config path is required to place plan.yaml and run.json")
	}
	return run(ctx, cfg, opts, defaultDependencies())
}

// run is Run with injectable dependencies.
func run(ctx context.Context, cfg Config, opts Options, deps dependencies) error {
	expDir := filepath.Dir(opts.ConfigPath)
	started := time.Now().UTC()

	if cfg.Lab.Enabled {
		// TODO(semrosin): apply netem from the run; an interface
		// name has to reach internal/lab first.
		return fmt.Errorf("lab profile %q: %w", cfg.Lab.ConfigID, ErrNotImplemented)
	}

	logFile, logger, err := openRunLogger(cfg.RunnerLog)
	if err != nil {
		return err
	}
	defer func() { _ = logFile.Close() }()

	logger.Info("run start", "event", "run_start",
		"experiment", cfg.ExperimentID, "mode", cfg.Mode,
		"endpoint", net.JoinHostPort(cfg.Endpoint.IP, strconv.Itoa(cfg.Endpoint.Port)),
		"operator", opts.Operator)

	// Kill switch: the whole series is bounded by max_duration_s
	// (docs/SAFETY.md §3).
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Budget.MaxDurationS)*time.Second)
	defer cancel()

	// Preflight (G01, G02) → experiments/<id>/dns_log.yaml.
	if cfg.Preflight.Enabled {
		rep, err := deps.checkPreflight(ctx, cfg)
		if err != nil {
			return fmt.Errorf("preflight: %w", err)
		}
		if !rep.AddrsMatch {
			logger.Warn("resolver answers diverge", "event", "preflight_diverge", "host", rep.Host)
		}
		if err := writeYAML(filepath.Join(expDir, "dns_log.yaml"), rep); err != nil {
			return err
		}
		logger.Info("preflight done", "event", "preflight",
			"addrs_match", rep.AddrsMatch, "tcp_reachable", rep.TCPReachable)
	}

	// Build the plan and persist it before the first packet
	// (docs/EXPERIMENTS.md §2). The random field is derived from
	// schedule.seed so the plan is reproducible (H07).
	var rnd [32]byte
	rand.New(rand.NewSource(cfg.Schedule.Seed)).Read(rnd[:])
	valid, err := generator.BuildValidSession(cfg.ExperimentID, cfg.SNI, rnd)
	if err != nil {
		return fmt.Errorf("generate plan: %w", err)
	}
	plan := PlanFile{ExperimentID: cfg.ExperimentID, Packets: valid.Packets}
	planPath := filepath.Join(expDir, "plan.yaml")
	if err := WritePlan(expDir, plan); err != nil {
		return err
	}
	logger.Info("plan written", "event", "plan_written",
		"packets", len(plan.Packets), "path", planPath)

	// Client capture point (opt-in; CAP_NET_RAW).
	var live *capture.Live
	if opts.CaptureIface != "" {
		live = capture.NewLive(capture.PointClient, opts.CaptureIface, cfg.Capture.Client)
		if err := live.Start(ctx); err != nil {
			return fmt.Errorf("start capture: %w", err)
		}
		defer func() { _ = live.Stop(context.Background()) }()
		logger.Info("capture started", "event", "capture_start",
			"point", "client", "iface", opts.CaptureIface, "path", cfg.Capture.Client)
	} else {
		logger.Warn("client capture not requested", "event", "capture_skipped", "point", "client")
	}

	if cfg.Schedule.StateReset != "" && cfg.Schedule.StateReset != "none" {
		logger.Warn("state reset not implemented", "event", "state_reset_unsupported",
			"state_reset", cfg.Schedule.StateReset)
	}

	// Budgeted send loop (docs/SAFETY.md §3).
	addr := net.JoinHostPort(cfg.Endpoint.IP, strconv.Itoa(cfg.Endpoint.Port))
	minSendGap := time.Second / time.Duration(cfg.Budget.MaxRatePPS)
	var (
		sentPackets, sentBytes int
		lastSend               time.Time
	)
	for rep := 0; rep < cfg.Schedule.Repetitions; rep++ {
		sess := deps.newSender(addr)
		if err := sendPlan(ctx, sess, plan, &sentPackets, &sentBytes, cfg.Budget, &lastSend, minSendGap, rep, logger); err != nil {
			_ = sess.Close()
			return err
		}
		// Keep the connection open while the helper answers: an
		// immediate close turns the response flight into EPIPE.
		if err := sleepCtx(ctx, deps.settle); err != nil {
			_ = sess.Close()
			return fmt.Errorf("settle: %w", err)
		}
		if err := sess.Close(); err != nil {
			return fmt.Errorf("close sender: %w", err)
		}
		if rep+1 < cfg.Schedule.Repetitions {
			gap := time.Duration(cfg.Schedule.InterTrialGapMS) * time.Millisecond
			if err := sleepCtx(ctx, gap); err != nil {
				return fmt.Errorf("inter-trial gap: %w", err)
			}
		}
	}

	if live != nil {
		if err := live.Stop(context.Background()); err != nil {
			return fmt.Errorf("stop capture: %w", err)
		}
	}

	logger.Info("run complete", "event", "run_complete",
		"packets", sentPackets, "bytes", sentBytes)
	if err := logFile.Close(); err != nil {
		return fmt.Errorf("close runner_log: %w", err)
	}

	// Artifacts exist outside git (docs/SAFETY.md §5); missing ones
	// (e.g. capture skipped) are recorded by absence, not fabricated.
	artifacts, err := hashArtifacts(logger, []string{
		captureClientPath(live, cfg.Capture.Client),
		cfg.Capture.Server,
		cfg.HelperLog,
		cfg.RunnerLog,
	})
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

// settleAfterSend is the production delay between the last packet and
// the connection close: it lets the helper and the capture writer
// observe the response before teardown.
const settleAfterSend = 500 * time.Millisecond

// sendPlan walks plan.Packets once, enforcing packet/byte budgets
// and rate pacing before each send.
func sendPlan(
	ctx context.Context,
	sess sendSession,
	plan PlanFile,
	sentPackets, sentBytes *int,
	budget Budget,
	lastSend *time.Time,
	minSendGap time.Duration,
	rep int,
	logger *slog.Logger,
) error {
	for _, p := range plan.Packets {
		if *sentPackets+1 > budget.MaxPackets {
			return fmt.Errorf("budget: max_packets %d exceeded (docs/SAFETY.md §3)",
				budget.MaxPackets)
		}
		if *sentBytes+len(p.Payload) > budget.MaxBytes {
			return fmt.Errorf("budget: max_bytes %d exceeded (docs/SAFETY.md §3)",
				budget.MaxBytes)
		}
		if !lastSend.IsZero() {
			if wait := minSendGap - time.Since(*lastSend); wait > 0 {
				if err := sleepCtx(ctx, wait); err != nil {
					return fmt.Errorf("rate limit: %w", err)
				}
			}
		}
		if err := sess.Send(ctx, p); err != nil {
			return fmt.Errorf("send packet %d (repetition %d): %w",
				*sentPackets+1, rep+1, err)
		}
		*sentPackets++
		*sentBytes += len(p.Payload)
		*lastSend = time.Now()
		logger.Info("packet sent", "event", "packet_sent",
			"seq", *sentPackets, "repetition", rep+1, "bytes", len(p.Payload))
	}
	return nil
}

// sleepCtx waits for d unless ctx is done first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// captureClientPath returns the client PCAP path only when a capture
// actually ran, so a skipped capture never appears in artifacts.
func captureClientPath(live *capture.Live, path string) string {
	if live == nil {
		return ""
	}
	return path
}

// openRunLogger opens runner_log (JSON lines, 0600,
// docs/SAFETY.md §5).
func openRunLogger(path string) (*os.File, *slog.Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create runner_log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open runner_log: %w", err)
	}
	return f, slog.New(slog.NewJSONHandler(f, nil)), nil
}

// writeYAML persists a metadata value next to the config (in git,
// docs/EXPERIMENTS.md §5).
func writeYAML(path string, v any) error {
	data, err := yaml.Marshal(v)
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

// hashArtifacts digests every existing artifact path; a missing file
// is logged and skipped, an I/O failure aborts the run.
func hashArtifacts(logger *slog.Logger, paths []string) (map[string]string, error) {
	out := make(map[string]string, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				logger.Warn("artifact missing", "event", "artifact_missing", "path", path)
				continue
			}
			return nil, fmt.Errorf("stat artifact %s: %w", path, err)
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return nil, err
		}
		out[path] = sum
	}
	return out, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open artifact %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash artifact %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dependencyVersions reports the module versions of the running
// binary for run.json (H07; docs/ARCHITECTURE.md §4).
func dependencyVersions() map[string]string {
	versions := make(map[string]string)
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return versions
	}
	for _, dep := range bi.Deps {
		if dep.Version != "" {
			versions[dep.Path] = dep.Version
		}
	}
	return versions
}
