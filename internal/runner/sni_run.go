package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/semrosin/DPIsect/internal/sender"
)

type pairWireSource interface {
	wireSource
	stop() error
}

type pairSourceFactory func(iface, path string) (pairWireSource, error)

type sniObservations struct {
	Trials          []sniTrial `json:"trials"`
	ObservedPackets int        `json:"observed_packets"`
	ObservedBytes   int        `json:"observed_ethernet_bytes"`
	CaptureDrops    uint       `json:"capture_drops"`
	StopReason      string     `json:"stop_reason,omitempty"`
	Limitation      string     `json:"limitation"`
}

// runSNIComparison prepares the exact TLS bytes before opening any socket,
// then starts capture and records each bounded attempt and its outcome.
func runSNIComparison(ctx context.Context, cfg Config, opts Options, open pairSourceFactory) error {
	if opts.CaptureIface == "" {
		return errors.New("paired TLS requires a capture interface")
	}
	if opts.ConfigPath == "" || open == nil {
		return errors.New("paired TLS requires a config path and capture source")
	}
	if strings.TrimSpace(opts.Operator) == "" || len(cfg.Budget.StopConditions) == 0 {
		return errors.New("paired TLS requires an operator and planned stop conditions")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := checkCaptureRoute(ctx, opts.CaptureIface, cfg.Endpoint.IP, cfg.Endpoint.Port); err != nil {
		return err
	}
	started := time.Now().UTC()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Budget.MaxDurationS)*time.Second)
	defer cancel()

	plan, sessions, err := prepareSNIWirePlan(ctx, cfg, opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("prepare wire plan: %w", err)
	}
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	budget, err := newWireBudget(cfg.Endpoint.IP, cfg.Endpoint.Port, cfg.Budget)
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(opts.CaptureIface)
	if err != nil {
		return fmt.Errorf("capture interface: %w", err)
	}
	// Ethernet plus one VLAN tag; oversized frames may be offload aggregates.
	budget.maxFrameLength = iface.MTU + 18
	if err := os.MkdirAll(filepath.Dir(cfg.RunnerLog), 0o700); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	obsPath := filepath.Join(filepath.Dir(cfg.RunnerLog), "sni-observations.json")
	obsFile, err := os.OpenFile(obsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("reserve observations: %w", err)
	}
	defer func() { _ = obsFile.Close() }()
	runPath := filepath.Join(filepath.Dir(opts.ConfigPath), "run.json")
	runFile, err := os.OpenFile(runPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("reserve run metadata: %w", err)
	}
	defer func() { _ = runFile.Close() }()
	logFile, err := os.OpenFile(cfg.RunnerLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("reserve runner log: %w", err)
	}
	defer func() { _ = logFile.Close() }()
	logger := slog.New(slog.NewJSONHandler(logFile, nil))
	source, err := open(opts.CaptureIface, cfg.Capture.Client)
	if err != nil {
		return fmt.Errorf("start capture: %w", err)
	}
	addr := net.JoinHostPort(cfg.Endpoint.IP, strconv.Itoa(cfg.Endpoint.Port))
	names := make([]string, len(plan.Trials))
	for i, trial := range plan.Trials {
		names[i] = trial.SNI
	}
	index := 0
	probe := func(ctx context.Context, addr, name string) sender.TLSObservation {
		if index >= len(sessions) || name != plan.Trials[index].SNI {
			return sender.TLSObservation{Stage: "tcp", Error: "trial does not match saved plan"}
		}
		session := sessions[index]
		index++
		defer session.Close()
		return session.Start(ctx, addr)
	}
	logger.Info("paired series started", "event", "paired_start", "experiment", cfg.ExperimentID)
	trials, trialErr := runMonitoredSNITrials(ctx, addr, names,
		time.Duration(cfg.PairedTimeoutMS)*time.Millisecond,
		time.Duration(cfg.Schedule.InterTrialGapMS)*time.Millisecond, probe, source, budget)
	drops, dropsErr := source.Drops()
	closeErr := source.stop()
	var runErr error
	if dropsErr != nil || drops > 0 {
		runErr = fmt.Errorf("capture drops %d, stats error: %v", drops, dropsErr)
	}
	if budget.packets == 0 {
		runErr = errors.Join(runErr, errors.New("capture contains no matching packets"))
	}
	runErr = errors.Join(runErr, trialErr, closeErr)
	obs := sniObservations{
		Trials: trials, ObservedPackets: budget.packets, ObservedBytes: budget.bytes, CaptureDrops: drops,
		Limitation: "capture counts are interface observations; offload, packet loss and NAT can differ from the physical wire",
	}
	if runErr != nil {
		obs.StopReason = runErr.Error()
	}
	if err := json.NewEncoder(obsFile).Encode(obs); err != nil {
		return errors.Join(runErr, fmt.Errorf("write observations: %w", err))
	}
	if err := obsFile.Close(); err != nil {
		return errors.Join(runErr, fmt.Errorf("close observations: %w", err))
	}
	logger.Info("paired series stopped", "event", "paired_stop", "packets", budget.packets, "bytes", budget.bytes, "error", obs.StopReason)
	if err := logFile.Close(); err != nil {
		return errors.Join(runErr, fmt.Errorf("close runner log: %w", err))
	}
	artifacts, err := hashArtifacts(logger, []string{cfg.Capture.Client, obsPath, cfg.RunnerLog})
	if err != nil {
		return errors.Join(runErr, err)
	}
	rec := RunRecord{
		ExperimentID: cfg.ExperimentID, QuestionID: cfg.QuestionID, ToolVersion: opts.ToolVersion,
		ToolCommit: opts.ToolCommit, DependencyVersions: dependencyVersions(), Seed: cfg.Schedule.Seed,
		StartedUTC: started.Format(time.RFC3339Nano), FinishedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Operator: opts.Operator, ConfigFile: opts.ConfigPath, Artifacts: artifacts,
	}
	if err := json.NewEncoder(runFile).Encode(rec); err != nil {
		return errors.Join(runErr, fmt.Errorf("write run metadata: %w", err))
	}
	if err := runFile.Close(); err != nil {
		return errors.Join(runErr, fmt.Errorf("close run metadata: %w", err))
	}
	return runErr
}
