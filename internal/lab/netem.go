//go:build linux

package lab

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// Commander runs one external command and returns its combined output.
// Tests inject recorders instead of running tc/ip for real.
type Commander interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecCommander executes commands with os/exec and a bound context
// (docs/GO_STYLE.md §4: explicit timeouts come from ctx).
type ExecCommander struct{}

// Run executes name args... and returns combined output; on failure
// the error carries the output for diagnosis.
func (ExecCommander) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// NetemController applies profiles to one interface via tc/netem and
// ip/mtu. It is idempotent: Apply uses tc replace, and the original
// MTU is captured once before the first change so Reset can restore
// it (docs/ARCHITECTURE.md §1).
type NetemController struct {
	mu      sync.Mutex
	iface   string
	cmd     Commander
	origMTU int // 0: unknown or unchanged
}

// New builds a controller for iface; a nil cmd selects ExecCommander.
func New(iface string, cmd Commander) *NetemController {
	if cmd == nil {
		cmd = ExecCommander{}
	}
	return &NetemController{iface: iface, cmd: cmd}
}

// Apply sets the impairment profile on the controlled interface.
func (s *NetemController) Apply(ctx context.Context, p Profile) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("lab profile %q: %w", p.Name, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if p.MTU > 0 && s.origMTU == 0 {
		mtu, err := s.queryMTU(ctx)
		if err != nil {
			return fmt.Errorf("lab %s: query mtu: %w", s.iface, err)
		}
		s.origMTU = mtu
	}

	args := append([]string{
		"qdisc", "replace", "dev", s.iface, "root", "netem",
	}, netemOptions(p)...)
	if out, err := s.cmd.Run(ctx, "tc", args...); err != nil {
		return fmt.Errorf("lab %s: apply netem: %w: %s", s.iface, err, strings.TrimSpace(out))
	}

	wantMTU := p.MTU
	if wantMTU == 0 && s.origMTU > 0 {
		wantMTU = s.origMTU
	}
	if wantMTU > 0 {
		if _, err := s.cmd.Run(ctx,
			"ip", "link", "set", "dev", s.iface, "mtu", fmt.Sprint(wantMTU)); err != nil {
			return fmt.Errorf("lab %s: set mtu: %w", s.iface, err)
		}
	}
	return nil
}

// Reset removes all impairments: the netem qdisc goes away and a
// previously changed MTU is restored. Removing an already-clean root
// qdisc ("Invalid argument" / "No such file") is not an error, so
// Reset is idempotent.
func (s *NetemController) Reset(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.cmd.Run(ctx, "tc", "qdisc", "del", "dev", s.iface, "root")
	if err != nil && !isMissingQdisc(err) {
		return fmt.Errorf("lab %s: reset netem: %w", s.iface, err)
	}

	if s.origMTU > 0 {
		if _, err := s.cmd.Run(ctx,
			"ip", "link", "set", "dev", s.iface, "mtu", fmt.Sprint(s.origMTU)); err != nil {
			return fmt.Errorf("lab %s: restore mtu: %w", s.iface, err)
		}
		s.origMTU = 0
	}
	return nil
}

// queryMTU parses `ip -o link show dev <iface>` output for "mtu N".
func (s *NetemController) queryMTU(ctx context.Context) (int, error) {
	out, err := s.cmd.Run(ctx, "ip", "-o", "link", "show", "dev", s.iface)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "mtu" {
			var mtu int
			if _, err := fmt.Sscanf(fields[i+1], "%d", &mtu); err == nil && mtu > 0 {
				return mtu, nil
			}
		}
	}
	return 0, fmt.Errorf("no mtu in %q", strings.TrimSpace(out))
}

// netemOptions renders the profile as tc netem arguments (order:
// delay first — tc rejects reorder without delay).
func netemOptions(p Profile) []string {
	var args []string
	if p.DelayMS > 0 {
		args = append(args, "delay", fmt.Sprintf("%dms", p.DelayMS))
	}
	if p.LossPercent > 0 {
		args = append(args, "loss", fmt.Sprintf("%g%%", p.LossPercent))
	}
	if p.ReorderPercent > 0 {
		args = append(args, "reorder", fmt.Sprintf("%g%%", p.ReorderPercent))
	}
	return args
}

// isMissingQdisc recognizes tc/ip "nothing to delete" failures so
// Reset stays idempotent across drivers.
func isMissingQdisc(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "Invalid argument") ||
		strings.Contains(msg, "No such file") ||
		strings.Contains(msg, "Cannot find")
}
