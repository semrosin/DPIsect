package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/sender"
)

func TestCloseDelayAfterSuccessfulTLS(t *testing.T) {
	start := time.Now()
	got := waitBeforeClose(context.Background(), sender.TLSObservation{Stage: "complete"}, 80*time.Millisecond)
	if got.Stage != "complete" || time.Since(start) < 65*time.Millisecond {
		t.Fatalf("got %+v after %v", got, time.Since(start))
	}
}

func TestCloseDelayCancellationAndFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := waitBeforeClose(ctx, sender.TLSObservation{Stage: "complete"}, time.Second)
	if got.Stage != "complete" || !strings.Contains(got.Error, "close delay interrupted") {
		t.Fatalf("cancelled delay: %+v", got)
	}
	start := time.Now()
	got = waitBeforeClose(context.Background(), sender.TLSObservation{Stage: "tls", Error: "failure"}, time.Second)
	if got.Error != "failure" || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("failed handshake delayed: %+v", got)
	}
}
