package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
)

// wireSource reads with a bounded timeout and reports cumulative capture drops.
type wireSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Drops() (uint, error)
	Record([]byte, gopacket.CaptureInfo) error
}

// monitorWire is called by the single owner of source and budget. Its caller
// waits for it to return before closing the source or reading final counts.
func monitorWire(ctx context.Context, source wireSource, budget *wireBudget, cancel context.CancelFunc) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		frame, ci, err := source.ReadPacketData()
		if err != nil && !errors.Is(err, afpacket.ErrTimeout) {
			cancel()
			return fmt.Errorf("wire monitor: read: %w", err)
		}
		drops, dropErr := source.Drops()
		if dropErr != nil || drops != 0 {
			cancel()
			return fmt.Errorf("wire monitor: capture drops %d, stats error: %v", drops, dropErr)
		}
		if errors.Is(err, afpacket.ErrTimeout) {
			continue
		}
		if ci.Timestamp.IsZero() {
			cancel()
			return errors.New("wire monitor: capture timestamp is missing")
		}
		var gso wireGSO
		if len(ci.AncillaryData) != 0 {
			gso, _ = ci.AncillaryData[0].(wireGSO)
		}
		budgetErr := budget.observe(frame, ci.Length, ci.Timestamp, gso)
		if budget.lastMatching {
			if err := source.Record(frame, ci); err != nil {
				cancel()
				return fmt.Errorf("wire monitor: write capture: %w", err)
			}
		}
		if budgetErr != nil {
			cancel()
			return budgetErr
		}
	}
}
