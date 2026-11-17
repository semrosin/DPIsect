package generator

import "testing"

// Raw path: malformed packet content is allowed, structural errors are
// not (docs/GO_STYLE.md §4).
func TestBuildRawAllowsMalformedPackets(t *testing.T) {
	t.Parallel()

	packets := []PlannedWirePacket{
		{
			Payload:         []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00},
			SplitOffsets:    []int{2, 5},
			TLSRecordEnds:   []int{7},
			TTL:             1,
			CorruptChecksum: true,
			SendAfterMS:     10,
		},
		{
			Payload: []byte{0x00},
			TTL:     255,
			Seq:     0xffffffff,
		},
	}
	plan, err := BuildRaw("h01-rst-2026-11", packets)
	if err != nil {
		t.Fatalf("BuildRaw: %v", err)
	}
	if len(plan.Packets) != 2 {
		t.Fatalf("len(Packets) = %d, want 2", len(plan.Packets))
	}
	if !plan.Packets[0].CorruptChecksum || plan.Packets[0].TTL != 1 {
		t.Errorf("malformed packet was altered: %+v", plan.Packets[0])
	}
}

func TestBuildRawRejectsStructuralErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		experimentID string
		packets      []PlannedWirePacket
	}{
		{
			name:         "missing experiment id",
			experimentID: "",
			packets:      []PlannedWirePacket{{Payload: []byte{1}}},
		},
		{
			name:         "no packets",
			experimentID: "h01-rst-2026-11",
			packets:      nil,
		},
		{
			name:         "empty payload",
			experimentID: "h01-rst-2026-11",
			packets:      []PlannedWirePacket{{Payload: nil}},
		},
		{
			name:         "split offset out of bounds",
			experimentID: "h01-rst-2026-11",
			packets:      []PlannedWirePacket{{Payload: []byte{1, 2}, SplitOffsets: []int{3}}},
		},
		{
			name:         "tls record end out of bounds",
			experimentID: "h01-rst-2026-11",
			packets:      []PlannedWirePacket{{Payload: []byte{1, 2}, TLSRecordEnds: []int{-1}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := BuildRaw(tt.experimentID, tt.packets); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestBuildRawCopiesPackets(t *testing.T) {
	t.Parallel()

	packets := []PlannedWirePacket{{Payload: []byte{1, 2, 3}}}
	plan, err := BuildRaw("h01-rst-2026-11", packets)
	if err != nil {
		t.Fatalf("BuildRaw: %v", err)
	}
	packets[0].Payload[0] = 0xff
	if plan.Packets[0].Payload[0] == 0xff {
		t.Error("BuildRaw must copy packets, not alias caller memory")
	}
}
