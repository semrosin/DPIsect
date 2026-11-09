package generator

import (
	"bytes"
	"testing"
)

// Valid-session path: well-formed output only, errors on bad input
// (docs/GO_STYLE.md §4).
func TestBuildValidSessionProducesWellFormedPlan(t *testing.T) {
	t.Parallel()

	plan, err := BuildValidSession("b01-test-2026-11", "example.com", [32]byte{7})
	if err != nil {
		t.Fatalf("BuildValidSession: %v", err)
	}
	if plan.ExperimentID != "b01-test-2026-11" {
		t.Errorf("ExperimentID = %q", plan.ExperimentID)
	}
	if len(plan.Packets) != 1 {
		t.Fatalf("len(Packets) = %d, want 1", len(plan.Packets))
	}
	p := plan.Packets[0]
	if len(p.Payload) == 0 || p.Payload[0] != 0x16 {
		t.Errorf("payload is not a handshake record: % 02x", p.Payload[:min(4, len(p.Payload))])
	}
	if p.TTL != 64 {
		t.Errorf("TTL = %d, want 64", p.TTL)
	}
	if p.CorruptChecksum {
		t.Error("valid-session must never set CorruptChecksum")
	}
	if len(p.TLSRecordEnds) != 1 || p.TLSRecordEnds[0] != len(p.Payload) {
		t.Errorf("TLSRecordEnds = %v, want [%d]", p.TLSRecordEnds, len(p.Payload))
	}
	if len(p.SplitOffsets) != 0 {
		t.Errorf("SplitOffsets = %v, want empty (single segment)", p.SplitOffsets)
	}
}

func TestBuildValidSessionRejectsBadInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		experimentID string
		sni          string
	}{
		{name: "missing experiment id", experimentID: "", sni: "example.com"},
		{name: "empty sni", experimentID: "b01-test-2026-11", sni: ""},
		{name: "bad sni", experimentID: "b01-test-2026-11", sni: "a/b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := BuildValidSession(tt.experimentID, tt.sni, [32]byte{}); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestValidSessionPayloadMatchesClientHello(t *testing.T) {
	t.Parallel()

	rnd := [32]byte{3}
	plan, err := BuildValidSession("b01-test-2026-11", "example.com", rnd)
	if err != nil {
		t.Fatalf("BuildValidSession: %v", err)
	}
	want, err := BuildClientHello("example.com", rnd)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if !bytes.Equal(plan.Packets[0].Payload, want) {
		t.Error("plan payload differs from BuildClientHello output")
	}
}
