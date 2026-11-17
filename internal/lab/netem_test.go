//go:build linux

package lab

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeCmd records invocations and returns scripted outputs/errors.
type fakeCmd struct {
	calls   []string
	outputs map[string]string // key: joined args
	err     error
}

func (f *fakeCmd) Run(_ context.Context, name string, args ...string) (string, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, key)
	if f.err != nil {
		return "", f.err
	}
	if out, ok := f.outputs[key]; ok {
		return out, nil
	}
	return "", nil
}

func TestNetemOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    Profile
		want string // joined args after "netem"
	}{
		{name: "empty", p: Profile{}, want: ""},
		{name: "loss only", p: Profile{LossPercent: 10}, want: "loss 10%"},
		{
			name: "delay and loss",
			p:    Profile{DelayMS: 5, LossPercent: 10.5},
			want: "delay 5ms loss 10.5%",
		},
		{
			name: "reorder with delay",
			p:    Profile{DelayMS: 1, ReorderPercent: 25},
			want: "delay 1ms reorder 25%",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := strings.Join(netemOptions(tt.p), " ")
			if got != tt.want {
				t.Errorf("netemOptions = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProfileValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    Profile
		ok   bool
	}{
		{name: "clean", p: Profile{}, ok: true},
		{name: "loss delay", p: Profile{LossPercent: 10, DelayMS: 5}, ok: true},
		{name: "reorder with delay", p: Profile{ReorderPercent: 25, DelayMS: 1}, ok: true},
		{name: "reorder without delay", p: Profile{ReorderPercent: 25}},
		{name: "loss above 100", p: Profile{LossPercent: 101}},
		{name: "negative loss", p: Profile{LossPercent: -1}},
		{name: "negative delay", p: Profile{DelayMS: -1}},
		{name: "negative mtu", p: Profile{MTU: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.p.Validate()
			if tt.ok && err != nil {
				t.Errorf("Validate: %v", err)
			}
			if !tt.ok && err == nil {
				t.Error("Validate: want error, got nil")
			}
		})
	}
}

func TestApplyRendersExactCommands(t *testing.T) {
	t.Parallel()

	f := &fakeCmd{outputs: map[string]string{
		"ip -o link show dev veth0": "3: veth0: <UP> mtu 1500 qdisc noqueue",
	}}
	c := New("veth0", f)
	err := c.Apply(context.Background(), Profile{
		Name: "loss10", LossPercent: 10, DelayMS: 5, MTU: 1400,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []string{
		"ip -o link show dev veth0",
		"tc qdisc replace dev veth0 root netem delay 5ms loss 10%",
		"ip link set dev veth0 mtu 1400",
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", f.calls, want)
	}
	for i := range want {
		if f.calls[i] != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, f.calls[i], want[i])
		}
	}
}

func TestApplyWithoutMTUSkipsLinkCommands(t *testing.T) {
	t.Parallel()

	f := &fakeCmd{}
	c := New("veth0", f)
	if err := c.Apply(context.Background(), Profile{Name: "loss5", LossPercent: 5}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(f.calls) != 1 ||
		f.calls[0] != "tc qdisc replace dev veth0 root netem loss 5%" {
		t.Errorf("calls = %v, want only the tc replace", f.calls)
	}
}

func TestApplyQueriesMTUOnceAndRestoresOnReset(t *testing.T) {
	t.Parallel()

	f := &fakeCmd{outputs: map[string]string{
		"ip -o link show dev veth0": "3: veth0: <UP> mtu 1500 qdisc noqueue",
	}}
	c := New("veth0", f)
	ctx := context.Background()

	if err := c.Apply(ctx, Profile{Name: "a", MTU: 1400}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := c.Apply(ctx, Profile{Name: "b", MTU: 1300}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	queries := 0
	for _, call := range f.calls {
		if call == "ip -o link show dev veth0" {
			queries++
		}
	}
	if queries != 1 {
		t.Errorf("mtu queries = %d, want 1", queries)
	}

	if err := c.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	last := f.calls[len(f.calls)-1]
	if last != "ip link set dev veth0 mtu 1500" {
		t.Errorf("last call = %q, want restore of original mtu 1500", last)
	}
}

func TestApplyRejectsInvalidProfileWithoutRunning(t *testing.T) {
	t.Parallel()

	f := &fakeCmd{}
	c := New("veth0", f)
	err := c.Apply(context.Background(), Profile{Name: "bad", ReorderPercent: 25})
	if err == nil {
		t.Fatal("Apply: want error, got nil")
	}
	if len(f.calls) != 0 {
		t.Errorf("commands must not run on invalid profile, calls = %v", f.calls)
	}
}

func TestApplyWrapsCommandError(t *testing.T) {
	t.Parallel()

	f := &fakeCmd{err: errors.New("EPERM")}
	c := New("veth0", f)
	err := c.Apply(context.Background(), Profile{Name: "x", LossPercent: 1})
	if err == nil || !strings.Contains(err.Error(), "EPERM") ||
		!strings.Contains(err.Error(), "veth0") {
		t.Errorf("err = %v, want wrapped EPERM with iface", err)
	}
}

func TestResetToleratesMissingQdiscAndIsIdempotent(t *testing.T) {
	t.Parallel()

	f := &fakeCmd{err: errors.New("RTNETLINK answers: Invalid argument")}
	c := New("veth0", f)
	ctx := context.Background()
	if err := c.Reset(ctx); err != nil {
		t.Errorf("first Reset: %v", err)
	}
	if err := c.Reset(ctx); err != nil {
		t.Errorf("second Reset: %v", err)
	}
}

func TestResetPropagatesRealErrors(t *testing.T) {
	t.Parallel()

	f := &fakeCmd{err: errors.New("something exploded")}
	c := New("veth0", f)
	if err := c.Reset(context.Background()); err == nil {
		t.Fatal("Reset: want error, got nil")
	}
}

func TestExecCommanderErrorCarriesOutput(t *testing.T) {
	t.Parallel()

	_, err := ExecCommander{}.Run(context.Background(),
		"sh", "-c", "echo detail >&2; exit 1")
	if err == nil {
		t.Fatal("want error, got nil")
	}
	if !strings.Contains(err.Error(), "detail") {
		t.Errorf("error %q must carry command output", err)
	}
}
