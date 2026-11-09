//go:build linux && privileged

package lab

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestNetemControllerOnLoopback exercises the real tc/ip path on lo.
// It skips when tc/ip are missing or when the process lacks
// CAP_NET_ADMIN (docs/GO_STYLE.md §5).
func TestNetemControllerOnLoopback(t *testing.T) {
	for _, bin := range []string{"tc", "ip"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found: %v", bin, err)
		}
	}

	ctx := context.Background()
	c := New("lo", nil)
	t.Cleanup(func() {
		if err := c.Reset(context.Background()); err != nil {
			t.Errorf("cleanup Reset: %v", err)
		}
	})

	// Probe permission once with a clean reset attempt.
	if err := c.Reset(ctx); err != nil {
		if strings.Contains(err.Error(), "Operation not permitted") ||
			strings.Contains(err.Error(), "not allowed") {
			t.Skipf("requires CAP_NET_ADMIN: %v", err)
		}
		t.Fatalf("Reset: %v", err)
	}

	if err := c.Apply(ctx, Profile{
		Name: "h02-loss10-delay1", LossPercent: 10, DelayMS: 1, MTU: 65536,
	}); err != nil {
		if strings.Contains(err.Error(), "Operation not permitted") {
			t.Skipf("requires CAP_NET_ADMIN: %v", err)
		}
		t.Fatalf("Apply: %v", err)
	}
	out, err := ExecCommander{}.Run(ctx, "tc", "qdisc", "show", "dev", "lo")
	if err != nil {
		t.Fatalf("tc show: %v", err)
	}
	for _, want := range []string{"netem", "delay 1ms", "loss 10%"} {
		if !strings.Contains(out, want) {
			t.Errorf("tc show = %q, want %q", out, want)
		}
	}

	if err := c.Apply(ctx, Profile{
		Name: "h02-reorder", ReorderPercent: 25, DelayMS: 1,
	}); err != nil {
		t.Fatalf("Apply reorder: %v", err)
	}
	out, err = ExecCommander{}.Run(ctx, "tc", "qdisc", "show", "dev", "lo")
	if err != nil {
		t.Fatalf("tc show: %v", err)
	}
	if !strings.Contains(out, "reorder 25%") {
		t.Errorf("tc show = %q, want reorder 25%%", out)
	}

	if err := c.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	out, err = ExecCommander{}.Run(ctx, "tc", "qdisc", "show", "dev", "lo")
	if err != nil {
		t.Fatalf("tc show: %v", err)
	}
	if strings.Contains(out, "netem") {
		t.Errorf("tc show = %q, netem must be gone after Reset", out)
	}
}
