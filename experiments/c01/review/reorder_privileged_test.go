//go:build linux && privileged

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/generator"
	"github.com/semrosin/DPIsect/internal/lab"
)

// TestC03LoopbackReorder runs tc only in a fresh network namespace.
func TestC03LoopbackReorder(t *testing.T) {
	if !enterLoopbackNamespace(t) {
		return
	}

	hello, err := generator.BuildClientHello("c03.example.test", [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	const split = 48
	for _, tc := range []struct {
		name    string
		reorder bool
		order   []int
	}{
		{name: "C03_in_order", order: []int{0, split}},
		{name: "C03_reversed", reorder: true, order: []int{split, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pcap, client, server := captureLoopbackTrial(t, hello, []int{split}, false, func(ctx context.Context) {
				configureLoopbackDelay(t, ctx, tc.reorder)
			})
			result, err := inspectCapture(bytes.NewReader(pcap.Bytes()), client, server, hello)
			if err != nil {
				t.Fatal(err)
			}
			var order []int
			for _, segment := range result.FirstSeen {
				order = append(order, segment.Offset)
			}
			if !slices.Equal(result.TCPSplitOffsets, []int{split}) || !slices.Equal(order, tc.order) || result.RepeatedRanges != 0 {
				t.Fatalf("captured splits=%v order=%v repeats=%d, want splits=[%d] order=%v repeats=0",
					result.TCPSplitOffsets, order, result.RepeatedRanges, split, tc.order)
			}
			recordLoopbackTrial(t, pcap, hello, client, server, result)
		})
	}
}

// enterLoopbackNamespace runs the named test in a network namespace that
// contains only lo. The parent waits for the child and reports its result.
func enterLoopbackNamespace(t *testing.T) bool {
	t.Helper()
	const parentNet = "DPISECT_C03_PARENT_NETNS"
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent := os.Getenv(parentNet)
	if parent == "" {
		for _, command := range []string{"unshare", "ip", "tc"} {
			if _, err := exec.LookPath(command); err != nil {
				t.Skipf("requires %s: %v", command, err)
			}
		}
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-Urn", "sh", "-c",
			`ip link set lo up && exec "$@"`, "sh", binary, "-test.v", "-test.run", "^"+t.Name()+"$")
		cmd.Env = append(os.Environ(), parentNet+"="+current)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated C03 test: %v\n%s", err, output)
		}
		t.Logf("isolated C03 test:\n%s", output)
		return false
	}
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if parent == current || len(links) != 1 || links[0].Name != "lo" {
		t.Fatal("loopback qdisc must be changed in a fresh loopback-only network namespace")
	}

	return true
}

func configureLoopbackDelay(t *testing.T, ctx context.Context, reorder bool) {
	t.Helper()
	args := []string{"qdisc", "replace", "dev", "lo", "root", "netem", "delay", "30ms"}
	if reorder {
		args = append(args, "reorder", "100%", "gap", "2")
	}
	if output, err := (lab.ExecCommander{}).Run(ctx, "tc", args...); err != nil {
		t.Fatalf("configure netem: %v: %s", err, output)
	}
}
