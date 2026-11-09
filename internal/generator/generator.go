// Package generator builds probe packets for DPIsect experiments.
//
// It owns the two experiment modes as distinct code paths
// (docs/GO_STYLE.md §4) and the generator→runner wire contract
// (docs/ARCHITECTURE.md §4). It does not send packets or capture
// traffic.
package generator

import "fmt"

// Mode selects the experiment path with different result types,
// error criteria and tests.
type Mode uint8

const (
	// ValidSession sends only well-formed traffic, as a browser would.
	ValidSession Mode = iota
	// RawExperiment sends deliberately malformed packets; allowed only
	// against lab and helper endpoints (docs/SAFETY.md §1).
	RawExperiment
)

// String returns the canonical mode name used in configs and reports.
func (m Mode) String() string {
	switch m {
	case ValidSession:
		return "valid-session"
	case RawExperiment:
		return "raw-experiment"
	default:
		return fmt.Sprintf("Mode(%d)", m)
	}
}

// ParseMode maps a canonical mode name to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "valid-session":
		return ValidSession, nil
	case "raw-experiment":
		return RawExperiment, nil
	default:
		return 0, fmt.Errorf("unknown mode %q (want valid-session or raw-experiment)", s)
	}
}

// PlannedWirePacket is the generator→runner contract: what will be put
// on the wire, described as logical bytes plus segmentation layout
// (docs/ARCHITECTURE.md §4). SplitOffsets and TLSRecordEnds are
// indexes into Payload; both are required for a full plan, an empty
// slice means "not applicable".
type PlannedWirePacket struct {
	Payload       []byte
	SplitOffsets  []int
	TLSRecordEnds []int
	TTL           uint8
	Seq           uint32
	Ack           uint32
	// Checksum is the TCP checksum to send; zero means "compute the
	// correct one". CorruptChecksum forces an intentionally wrong
	// checksum (question D04) and takes precedence.
	Checksum        uint16
	CorruptChecksum bool
}
