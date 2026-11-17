package generator

import "fmt"

// RawExperimentPlan is the result of the raw path: packets may be
// deliberately malformed (corrupt checksum, odd TTL, arbitrary
// splits). This type exists only for lab and helper endpoints
// (docs/SAFETY.md §1, docs/GO_STYLE.md §4).
type RawExperimentPlan struct {
	ExperimentID string              `yaml:"experiment_id"`
	Packets      []PlannedWirePacket `yaml:"packets"`
}

// BuildRaw validates the structural constraints of a raw plan.
// Content validity is deliberately not required — malformed packets
// are the point of this path; only index bounds and non-empty
// payloads must hold for the plan to be executable at all.
func BuildRaw(experimentID string, packets []PlannedWirePacket) (RawExperimentPlan, error) {
	if experimentID == "" {
		return RawExperimentPlan{}, fmt.Errorf("raw-experiment: experiment id is required")
	}
	if len(packets) == 0 {
		return RawExperimentPlan{}, fmt.Errorf("raw-experiment: at least one packet required")
	}
	out := make([]PlannedWirePacket, len(packets))
	for i, p := range packets {
		if len(p.Payload) == 0 {
			return RawExperimentPlan{}, fmt.Errorf("raw-experiment: packet %d: empty payload", i)
		}
		for _, off := range p.SplitOffsets {
			if off < 0 || off > len(p.Payload) {
				return RawExperimentPlan{}, fmt.Errorf(
					"raw-experiment: packet %d: split offset %d out of [0,%d]",
					i, off, len(p.Payload))
			}
		}
		for _, end := range p.TLSRecordEnds {
			if end < 0 || end > len(p.Payload) {
				return RawExperimentPlan{}, fmt.Errorf(
					"raw-experiment: packet %d: tls record end %d out of [0,%d]",
					i, end, len(p.Payload))
			}
		}
		out[i] = p
		out[i].Payload = append([]byte(nil), p.Payload...)
		out[i].SplitOffsets = append([]int(nil), p.SplitOffsets...)
		out[i].TLSRecordEnds = append([]int(nil), p.TLSRecordEnds...)
	}
	return RawExperimentPlan{ExperimentID: experimentID, Packets: out}, nil
}
