package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/semrosin/DPIsect/internal/generator"
	"gopkg.in/yaml.v3"
)

func TestC01ReviewPlanAndCapture(t *testing.T) {
	t.Parallel()
	const sni = "example.test"
	record, err := generator.BuildClientHello(sni, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	// Keep two TLS records while varying the observed TCP boundary.
	firstRecord := slices.Clone(record[:23])
	binary.BigEndian.PutUint16(firstRecord[3:5], 18)
	secondRecord := append(slices.Clone(record[:5]), record[23:]...)
	binary.BigEndian.PutUint16(secondRecord[3:5], uint16(len(secondRecord)-5))
	hello := append(firstRecord, secondRecord...)

	for _, tc := range []struct {
		name          string
		plannedSplits []int
		actualSplit   int
		match         bool
	}{
		{name: "C01_matching", plannedSplits: []int{8}, actualSplit: 8, match: true},
		{name: "C01_coalesced", plannedSplits: []int{8}},
		{name: "C01_unsplit_control", plannedSplits: []int{}, match: true},
		{name: "C01_unspecified", actualSplit: 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := generator.PlannedWirePacket{
				Payload: hello, SplitOffsets: tc.plannedSplits, TLSRecordEnds: []int{23, len(hello)},
			}
			dir := t.TempDir()
			planName, captureName := filepath.Join(dir, "plan.yaml"), filepath.Join(dir, "test.pcap")
			plan := map[string]any{
				"endpoint": map[string]any{"ip": testServer.Addr().String(), "port": testServer.Port()},
				"trials":   []map[string]any{{"sni": sni, "packet": packet}},
			}
			// yaml marshals nil slices as empty lists. To test an omitted field,
			// remove the key before marshaling the plan.
			if tc.plannedSplits == nil {
				plan["trials"] = []map[string]any{{"sni": sni, "packet": map[string]any{
					"payload": hello, "tls_record_ends": packet.TLSRecordEnds,
				}}}
			}
			data, err := yaml.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(planName, data, 0o600); err != nil {
				t.Fatal(err)
			}
			frames := []testFrame{{seq: 100, syn: true}}
			if tc.actualSplit > 0 {
				frames = append(frames, testFrame{seq: 101, payload: string(hello[:tc.actualSplit])})
			}
			frames = append(frames, testFrame{seq: 101 + uint32(tc.actualSplit), payload: string(hello[tc.actualSplit:])})
			if err := os.WriteFile(captureName, makeCapture(t, frames), 0o600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := run([]string{"-plan", planName, "-pcap", captureName, "-trial", "1", "-source", testClient.String()}, &out); err != nil {
				t.Fatal(err)
			}
			var result review
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(result.TLSRecordEnds, packet.TLSRecordEnds) || result.HelloSHA256 == "" || result.CaptureSHA256 == "" {
				t.Fatalf("unexpected TLS result: %+v", result)
			}
			if tc.plannedSplits == nil {
				if result.SplitOffsetsMatch != nil {
					t.Fatalf("unexpected comparison: %v", *result.SplitOffsetsMatch)
				}
			} else if result.SplitOffsetsMatch == nil || *result.SplitOffsetsMatch != tc.match {
				t.Fatalf("unexpected comparison: %s", out.Bytes())
			}
		})
	}
}
