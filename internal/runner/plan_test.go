package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/semrosin/DPIsect/internal/generator"
)

func TestWriteReadPlanRoundtrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	want := PlanFile{
		ExperimentID: "b01-test-2026-11",
		Packets: []generator.PlannedWirePacket{
			{
				Payload:       []byte{0x16, 0x03, 0x01, 0x00, 0x05},
				SplitOffsets:  []int{2},
				TLSRecordEnds: []int{5},
				TTL:           64,
				Seq:           1,
				SendAfterMS:   25,
			},
		},
	}
	if err := WritePlan(dir, want); err != nil {
		t.Fatalf("WritePlan: %v", err)
	}

	got, err := ReadPlan(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatalf("ReadPlan: %v", err)
	}
	if got.ExperimentID != want.ExperimentID {
		t.Errorf("ExperimentID = %q, want %q", got.ExperimentID, want.ExperimentID)
	}
	if len(got.Packets) != 1 {
		t.Fatalf("len(Packets) = %d, want 1", len(got.Packets))
	}
	p, w := got.Packets[0], want.Packets[0]
	if !bytes.Equal(p.Payload, w.Payload) {
		t.Errorf("Payload = %v, want %v", p.Payload, w.Payload)
	}
	if p.TTL != w.TTL || p.Seq != w.Seq || p.SendAfterMS != w.SendAfterMS {
		t.Errorf("packet = %+v, want %+v", p, w)
	}
	if len(p.SplitOffsets) != 1 || p.SplitOffsets[0] != 2 {
		t.Errorf("SplitOffsets = %v, want [2]", p.SplitOffsets)
	}
}

func TestReadPlanRejectsUnknownField(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := WritePlan(dir, PlanFile{ExperimentID: "b01-test-2026-11"}); err != nil {
		t.Fatalf("WritePlan: %v", err)
	}
	path := filepath.Join(dir, "plan.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	if err := os.WriteFile(path, append(data, []byte("bogus: 1\n")...), 0o644); err != nil {
		t.Fatalf("rewrite plan: %v", err)
	}
	if _, err := ReadPlan(path); err == nil {
		t.Fatal("ReadPlan: want error for unknown field, got nil")
	}
}
