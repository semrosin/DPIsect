package generator

import "fmt"

// ValidSessionPlan is the result of the valid-session path: only
// well-formed traffic a browser could produce. TCP sequence/ack fields
// are advisory — the kernel owns the connection on this path
// (docs/GO_STYLE.md §4).
type ValidSessionPlan struct {
	ExperimentID string              `yaml:"experiment_id"`
	Packets      []PlannedWirePacket `yaml:"packets"`
}

// BuildValidSession builds a single well-formed ClientHello plan.
// Unlike the raw path it rejects malformed inputs instead of sending
// them: invalid SNI or missing experiment id are errors here.
func BuildValidSession(experimentID, sni string, rnd [32]byte) (ValidSessionPlan, error) {
	if experimentID == "" {
		return ValidSessionPlan{}, fmt.Errorf("valid-session: experiment id is required")
	}
	payload, err := BuildClientHello(sni, rnd)
	if err != nil {
		return ValidSessionPlan{}, fmt.Errorf("valid-session: %w", err)
	}
	pkt := PlannedWirePacket{
		Payload:       payload,
		TLSRecordEnds: []int{len(payload)},
		TTL:           64,
	}
	return ValidSessionPlan{
		ExperimentID: experimentID,
		Packets:      []PlannedWirePacket{pkt},
	}, nil
}
