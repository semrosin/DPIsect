// Package sender puts planned packets on the wire: the normal path
// uses OS TCP, the raw path is gated by the runner behind an explicit
// flag and confirmation (docs/ARCHITECTURE.md §1, §4).
package sender

import (
	"context"
	"errors"

	"github.com/semrosin/DPIsect/internal/generator"
)

// ErrNotImplemented is returned by send paths that exist as contracts
// only; stage-1 code lands per docs/DEVELOPMENT.md.
var ErrNotImplemented = errors.New("sender: not implemented yet (stage 1, docs/DEVELOPMENT.md)")

// Sender transmits one planned packet. Budget, rate limits and the
// kill switch stay on the runner side (docs/SAFETY.md §3); sender
// must not dial arbitrary targets on its own.
type Sender interface {
	// Send transmits p, honoring SendAfterMS pacing semantics as
	// defined by the plan contract.
	Send(ctx context.Context, p generator.PlannedWirePacket) error
}
