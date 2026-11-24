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
	TCPOnly                    bool       `json:"tcp_only,omitempty"`
	Trials                     []sniTrial `json:"trials"`
	ObservedPackets            int        `json:"observed_packets"`
	ObservedBytes              int        `json:"observed_ethernet_bytes"`
	CaptureDrops               uint       `json:"capture_drops"`
	ObservedSYNRetransmissions *int       `json:"observed_syn_retransmissions,omitempty"`
	StopReason                 string     `json:"stop_reason,omitempty"`
	Limitation                 string     `json:"limitation"`
}

// runObservedSeries persists its plan, starts capture and records each attempt.
func runObservedSeries(ctx context.Context, cfg Config, opts Options, open pairSourceFactory) error {
	if opts.CaptureIface == "" {
		return errors.New("TCP and paired TLS runs require a capture interface")
	}
	if opts.ConfigPath == "" || open == nil {
		return errors.New("TCP and paired TLS runs require a config path and capture source")
	}
	if strings.TrimSpace(opts.Operator) == "" || len(cfg.Budget.StopConditions) == 0 {
		return errors.New("TCP and paired TLS runs require an operator and planned stop conditions")
	}
	if cfg.Budget.MaxSYNRetransmissions == nil || *cfg.Budget.MaxSYNRetransmissions <= 0 {
		return errors.New("TCP and paired TLS runs require a planned SYN retransmission threshold")
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

	var plan sniWirePlan
	var sessions []*sender.PreparedTLS
	var err error
	if cfg.TCPOnly {
		plan, err = prepareTCPWirePlan(cfg, opts.ConfigPath)
	} else {
		plan, sessions, err = prepareSNIWirePlan(ctx, cfg, opts.ConfigPath)
	}
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
	// Ethernet plus one VLAN tag, checked per segment for offload records.
	budget.maxFrameLength = iface.MTU + 18
	if err := os.MkdirAll(filepath.Dir(cfg.RunnerLog), 0o700); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	obsName := "sni-observations.json"
	if cfg.TCPOnly {
		obsName = "tcp-observations.json"
	}
	obsPath := filepath.Join(filepath.Dir(cfg.RunnerLog), obsName)
	runPath := filepath.Join(filepath.Dir(opts.ConfigPath), "run.json")
	for _, path := range []string{obsPath, runPath} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing artifact: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect artifact path %s: %w", path, err)
		}
	}
	logFile, err := os.OpenFile(cfg.RunnerLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("reserve runner log: %w", err)
	}
	defer func() { _ = logFile.Close() }()
	logger := slog.New(slog.NewJSONHandler(logFile, nil))
	source, err := open(opts.CaptureIface, cfg.Capture.Client)
	if err != nil {
		logger.Error("capture failed to start", "event", "capture_start_failed", "error", err.Error())
		return fmt.Errorf("start capture: %w", err)
	}
	addr := net.JoinHostPort(cfg.Endpoint.IP, strconv.Itoa(cfg.Endpoint.Port))
	names := make([]string, len(plan.Trials))
	for i, trial := range plan.Trials {
		names[i] = trial.SNI
	}
	index := 0
	probe := func(ctx context.Context, addr, name string) sender.TLSObservation {
		if cfg.TCPOnly {
			return sender.TCPProbe(ctx, addr)
		}
		if index >= len(sessions) || name != plan.Trials[index].SNI {
			return sender.TLSObservation{Stage: "tcp", Error: "trial does not match saved plan"}
		}
		session := sessions[index]
		index++
		defer session.Close()
		result := session.StartAfter(ctx, addr, time.Duration(cfg.PairedClientHelloDelayMS)*time.Millisecond)
		return waitBeforeClose(ctx, result, time.Duration(cfg.PairedCloseDelayMS)*time.Millisecond)
	}
	logger.Info("series started", "event", "series_start", "experiment", cfg.ExperimentID, "tcp_only", cfg.TCPOnly)
	timeoutMS := cfg.PairedTimeoutMS
	if cfg.TCPOnly {
		timeoutMS = cfg.TCPTimeoutMS
	}
	trials, trialErr := runMonitoredSNITrials(ctx, addr, names,
		time.Duration(timeoutMS)*time.Millisecond,
		time.Duration(cfg.Schedule.InterTrialGapMS)*time.Millisecond, probe, source, budget)
	if cfg.PairedHello != nil {
		for i := range trials {
			trials[i].Variant = plan.Trials[i].Variant
		}
	}
	drops, dropsErr := source.Drops()
	closeErr := source.stop()
	var runErr error
	if dropsErr != nil || drops > 0 {
		runErr = fmt.Errorf("capture drops %d, stats error: %v", drops, dropsErr)
	}
	if budget.packets == 0 && trialErr == nil {
		runErr = errors.Join(runErr, errors.New("capture contains no matching packets"))
	}
	runErr = errors.Join(runErr, trialErr, closeErr)
	obs := sniObservations{
		TCPOnly: cfg.TCPOnly,
		Trials:  trials, ObservedPackets: budget.packets, ObservedBytes: budget.bytes, CaptureDrops: drops,
		ObservedSYNRetransmissions: &budget.synRetransmissions,
		Limitation:                 "budget counts include segments and repeated headers from kernel TCP offload metadata; PCAP retains the original capture records; counts may differ from the physical wire",
	}
	if runErr != nil {
		obs.StopReason = runErr.Error()
	}
	obsFile, err := os.OpenFile(obsPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.Join(runErr, fmt.Errorf("create observations: %w", err))
	}
	if err := json.NewEncoder(obsFile).Encode(obs); err != nil {
		_ = obsFile.Close()
		return errors.Join(runErr, fmt.Errorf("write observations: %w", err))
	}
	if err := obsFile.Close(); err != nil {
		return errors.Join(runErr, fmt.Errorf("close observations: %w", err))
	}
	logger.Info("series stopped", "event", "series_stop", "packets", budget.packets, "bytes", budget.bytes, "error", obs.StopReason)
	if err := logFile.Close(); err != nil {
		return errors.Join(runErr, fmt.Errorf("close runner log: %w", err))
	}
	artifacts, err := hashArtifacts(slog.New(slog.NewTextHandler(os.Stderr, nil)), []string{cfg.Capture.Client, obsPath, cfg.RunnerLog})
	if err != nil {
		return errors.Join(runErr, err)
	}
	rec := RunRecord{
		ExperimentID: cfg.ExperimentID, QuestionID: cfg.QuestionID, ToolVersion: opts.ToolVersion,
		ToolCommit: opts.ToolCommit, DependencyVersions: dependencyVersions(), Seed: cfg.Schedule.Seed,
		StartedUTC: started.Format(time.RFC3339Nano), FinishedUTC: time.Now().UTC().Format(time.RFC3339Nano),
		Operator: opts.Operator, ConfigFile: opts.ConfigPath, Artifacts: artifacts,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return errors.Join(runErr, fmt.Errorf("marshal run metadata: %w", err))
	}
	if err := writeNewFile(runPath, append(data, '\n'), 0o644); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

// waitBeforeClose keeps a completed session open while the monitor remains active.
func waitBeforeClose(ctx context.Context, result sender.TLSObservation, delay time.Duration) sender.TLSObservation {
	if result.Stage != "complete" || delay <= 0 {
		return result
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return result
	case <-ctx.Done():
		result.Error = "close delay interrupted: " + ctx.Err().Error()
		return result
	}
}
