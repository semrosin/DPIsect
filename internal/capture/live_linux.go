//go:build linux

package capture

import (
	"time"

	"github.com/google/gopacket/afpacket"
)

// NewLive creates a capture reading from iface via AF_PACKET
// (requires CAP_NET_RAW at runtime; docs/SAFETY.md §4) and writing to
// path. Linux-only: AF_PACKET is the supported live source.
func NewLive(point Point, iface, path string) *Live {
	return newLive(point, iface, path, func() (packetSource, error) {
		// Poll timeout keeps the writer goroutine responsive to
		// ctx cancellation even on an idle interface.
		return afpacket.NewTPacket(
			afpacket.OptInterface(iface),
			afpacket.OptPollTimeout(200*time.Millisecond),
		)
	})
}
