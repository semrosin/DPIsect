package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semrosin/DPIsect/internal/generator"
	"gopkg.in/yaml.v3"
)

func TestC01ReviewSeries(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	writeFile := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sni := "example.test"
	hello, err := generator.BuildClientHello(sni, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{
		"endpoint": map[string]any{"ip": testServer.Addr().String(), "port": testServer.Port()},
		"trials": []map[string]any{
			{"sni": sni, "packet": generator.PlannedWirePacket{Payload: hello, TLSRecordEnds: []int{len(hello)}}},
			{"sni": sni, "packet": generator.PlannedWirePacket{Payload: hello, TLSRecordEnds: []int{len(hello)}, SplitOffsets: []int{8}}},
		},
	}
	data, err := yaml.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	writeFile("plan.yaml", data)
	writeFile("control.pcap", makeCapture(t, []testFrame{
		{seq: 100, syn: true},
		{seq: 101, payload: string(hello)},
		{seq: 101, payload: string(hello)},
	}))
	writeFile("comparison.pcap", makeCapture(t, []testFrame{
		{seq: 200, syn: true},
		{seq: 201, payload: string(hello[:8])},
		{seq: 209, payload: string(hello[8:])},
		{incoming: true, payload: "reply"},
	}))
	control := manifestTrial{Label: "control", Plan: "plan.yaml", PCAP: "control.pcap", Trial: 1, Source: testClient.String()}
	comparison := manifestTrial{Label: "comparison", Plan: "plan.yaml", PCAP: "comparison.pcap", Trial: 2, Source: testClient.String()}
	for _, tc := range []struct {
		name  string
		entry manifestTrial
		err   string
	}{
		{name: "C01_distinct_captures", entry: comparison},
		{name: "C01_duplicate_label", entry: control, err: "unique nonempty label"},
		{name: "C01_duplicate_flow", entry: manifestTrial{Label: "other", Plan: control.Plan, PCAP: control.PCAP, Trial: 1, Source: control.Source}, err: "repeats a flow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal([]manifestTrial{control, tc.entry})
			if err != nil {
				t.Fatal(err)
			}
			writeFile("series.json", data)
			var output strings.Builder
			err = run([]string{"-series", filepath.Join(directory, "series.json")}, &output)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || output.Len() != 0 {
					t.Fatalf("error=%v, output=%q, want %q and no output", err, output.String(), tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var result seriesReview
			if err := json.Unmarshal([]byte(output.String()), &result); err != nil {
				t.Fatal(err)
			}
			if !result.SameEndpoint || !result.SameSNI || !result.SameClientIP || !result.SameHelloBytes || !result.SameTLSRecords || !result.DifferentTCPSplits ||
				len(result.Trials) != 2 || result.Trials[0].FirstRepeat == nil || result.Trials[1].IncomingPayloadBeforeRepeat != 1 {
				t.Fatalf("unexpected series: %s", output.String())
			}
		})
	}
}
