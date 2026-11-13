package runner

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/sender"
)

func TestObserveSNITrialsRecordsEachOutcome(t *testing.T) {
	t.Parallel()

	names := []string{"control.example", "web.telegram.org", "web.telegram.org", "control.example"}
	var gotNames []string
	probe := func(_ context.Context, addr, sni string) sender.TLSObservation {
		if addr != "127.0.0.1:443" {
			t.Errorf("address = %q, want fixed endpoint", addr)
		}
		gotNames = append(gotNames, sni)
		if sni == "control.example" {
			return sender.TLSObservation{Stage: "tls", Error: "certificate rejected"}
		}
		return sender.TLSObservation{Stage: "complete", Version: 0x0304}
	}
	got, err := observeSNITrials(context.Background(), "127.0.0.1:443", names, time.Second, 0, probe)
	if err != nil {
		t.Fatalf("observe trials: %v", err)
	}
	if !reflect.DeepEqual(gotNames, names) || len(got) != len(names) {
		t.Fatalf("probes = %v, observations = %d, want %v", gotNames, len(got), names)
	}
	for i, trial := range got {
		if trial.SNI != names[i] || trial.StartedUTC == "" || trial.FinishedUTC == "" {
			t.Errorf("trial %d has incomplete identity: %+v", i, trial)
		}
		if names[i] == "control.example" && trial.Observation.Error == "" {
			t.Errorf("trial %d lost the TLS error", i)
		}
	}
}

func TestObserveSNITrialsStopsOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	probe := func(context.Context, string, string) sender.TLSObservation {
		cancel()
		return sender.TLSObservation{Stage: "tcp", Error: "cancelled"}
	}
	got, err := observeSNITrials(ctx, "127.0.0.1:443", []string{"a.example", "b.example"}, time.Second, 0, probe)
	if !errors.Is(err, context.Canceled) || len(got) != 1 {
		t.Fatalf("trials = %d, error = %v; want one result and cancellation", len(got), err)
	}
}
