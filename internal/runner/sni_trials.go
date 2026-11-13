package runner

import (
	"context"
	"fmt"
	"time"

	"github.com/semrosin/DPIsect/internal/sender"
)

type sniTrial struct {
	SNI         string                `json:"sni"`
	StartedUTC  string                `json:"started_utc"`
	FinishedUTC string                `json:"finished_utc"`
	Observation sender.TLSObservation `json:"observation"`
}

type tlsProbe func(context.Context, string, string) sender.TLSObservation

// observeSNITrials keeps completed observations when cancellation stops a series.
func observeSNITrials(ctx context.Context, addr string, names []string, timeout, gap time.Duration, probe tlsProbe) ([]sniTrial, error) {
	if addr == "" || len(names) == 0 || timeout <= 0 || gap < 0 || probe == nil {
		return nil, fmt.Errorf("invalid TLS trial parameters")
	}
	trials := make([]sniTrial, 0, len(names))
	for i, name := range names {
		if err := ctx.Err(); err != nil {
			return trials, err
		}
		if i > 0 {
			if err := sleepCtx(ctx, gap); err != nil {
				return trials, err
			}
		}
		started := time.Now().UTC()
		trialCtx, cancel := context.WithTimeout(ctx, timeout)
		observation := probe(trialCtx, addr, name)
		cancel()
		trials = append(trials, sniTrial{
			SNI: name, StartedUTC: started.Format(time.RFC3339Nano),
			FinishedUTC: time.Now().UTC().Format(time.RFC3339Nano), Observation: observation,
		})
	}
	if err := ctx.Err(); err != nil {
		return trials, err
	}
	return trials, nil
}

// runMonitoredSNITrials cancels active probes when capture or budgeting fails.
// The caller opens and closes source and may read budget after this returns.
func runMonitoredSNITrials(ctx context.Context, addr string, names []string, timeout, gap time.Duration, probe tlsProbe, source wireSource, budget *wireBudget) ([]sniTrial, error) {
	if source == nil || budget == nil {
		return nil, fmt.Errorf("wire monitor and budget are required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	monitorDone := make(chan error, 1)
	go func() {
		defer func() {
			if v := recover(); v != nil {
				cancel()
				monitorDone <- fmt.Errorf("wire monitor panic: %v", v)
			}
		}()
		monitorDone <- monitorWire(ctx, source, budget, cancel)
	}()
	trials, trialErr := observeSNITrials(ctx, addr, names, timeout, gap, probe)
	if trialErr == nil {
		// Give the capture reader a bounded opportunity to collect the
		// final connection teardown before stopping it.
		trialErr = sleepCtx(ctx, 250*time.Millisecond)
	}
	cancel()
	monitorErr := <-monitorDone
	if monitorErr != nil {
		return trials, monitorErr
	}
	return trials, trialErr
}
