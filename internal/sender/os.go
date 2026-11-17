package sender

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/semrosin/DPIsect/internal/generator"
)

// OS is the normal-path sender: it keeps one OS TCP connection to a
// fixed endpoint and writes planned payloads with the plan's pacing.
// The address comes from the runner, never from a packet itself.
type OS struct {
	addr string
	// dial is a field so tests can substitute net.Pipe
	// (docs/GO_STYLE.md §6).
	dial func(ctx context.Context, addr string) (net.Conn, error)
	conn net.Conn
}

// NewOS returns a sender for addr ("host:port"); the connection is
// dialed lazily on the first Send so that Close is safe to defer.
func NewOS(addr string) *OS {
	return &OS{
		addr: addr,
		dial: func(ctx context.Context, a string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "tcp", a)
		},
	}
}

// Send writes p over the connection. SplitOffsets become separate
// writes, SendAfterMS delays the packet relative to the previous one
// (plan contract); an out-of-range offset is an error rather than a
// silently truncated write.
func (s *OS) Send(ctx context.Context, p generator.PlannedWirePacket) error {
	chunks, err := splitPayload(p.Payload, p.SplitOffsets)
	if err != nil {
		return fmt.Errorf("sender: %w", err)
	}
	if p.SendAfterMS > 0 {
		timer := time.NewTimer(time.Duration(p.SendAfterMS) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return fmt.Errorf("sender: pacing wait: %w", ctx.Err())
		case <-timer.C:
		}
	}
	if s.conn == nil {
		conn, err := s.dial(ctx, s.addr)
		if err != nil {
			return fmt.Errorf("sender: dial %s: %w", s.addr, err)
		}
		s.conn = conn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.conn.SetWriteDeadline(deadline)
	}
	for _, chunk := range chunks {
		// net.Conn.Write writes the whole chunk or returns an error.
		if _, err := s.conn.Write(chunk); err != nil {
			return fmt.Errorf("sender: write %d bytes: %w", len(chunk), err)
		}
	}
	return nil
}

// Close tears down the connection; closing a sender that never
// dialed is a no-op.
func (s *OS) Close() error {
	if s.conn == nil {
		return nil
	}
	conn := s.conn
	s.conn = nil
	if err := conn.Close(); err != nil {
		return fmt.Errorf("sender: close: %w", err)
	}
	return nil
}

// splitPayload cuts payload at sorted unique offsets; offset 0 and
// duplicates are no-ops, an offset beyond the payload is an error.
func splitPayload(payload []byte, offsets []int) ([][]byte, error) {
	offs := append([]int(nil), offsets...)
	sort.Ints(offs)
	var out [][]byte
	prev := 0
	for _, off := range offs {
		if off > len(payload) {
			return nil, fmt.Errorf("split offset %d out of [0,%d]", off, len(payload))
		}
		if off <= prev {
			continue
		}
		out = append(out, payload[prev:off])
		prev = off
	}
	return append(out, payload[prev:]), nil
}
