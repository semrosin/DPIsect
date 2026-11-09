// Package capture records wire traffic to PCAP files at the two
// vantage points (client and helper server). It only stores bytes;
// interpretation belongs to the analyzer (docs/ARCHITECTURE.md §1).
package capture

import "context"

// Point names a capture vantage point.
type Point string

const (
	// PointClient captures on the prober host.
	PointClient Point = "client"
	// PointServer captures on the helper host.
	PointServer Point = "server"
)

// Capture is one PCAP recording at a single vantage point. Writing
// happens in a dedicated goroutine that must not block the network
// cycle (docs/GO_STYLE.md §4).
type Capture interface {
	// Start begins recording; it returns once the writer is running.
	Start(ctx context.Context) error
	// Stop flushes and closes the PCAP file.
	Stop(ctx context.Context) error
	// Path returns the PCAP file path outside git (docs/SAFETY.md §5).
	Path() string
	// Point returns the vantage point of this capture.
	Point() Point
}
