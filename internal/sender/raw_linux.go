//go:build linux

package sender

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Raw sends complete IPv4 packets through an IPPROTO_RAW socket. It
// is only constructed by the runner after the raw-experiment
// confirmation gate and lab/helper endpoint check (docs/SAFETY.md §1).
type Raw struct {
	fd int
}

// NewRaw opens the raw IPv4 sender. It requires CAP_NET_RAW.
func NewRaw() (*Raw, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("sender: raw socket: %w", err)
	}
	return &Raw{fd: fd}, nil
}

// SendIPv4 transmits one already-serialized IPv4 packet to dst.
func (r *Raw) SendIPv4(ctx context.Context, packet []byte, dst net.IP) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("sender: raw send canceled: %w", err)
	}
	dst4 := dst.To4()
	if dst4 == nil {
		return fmt.Errorf("sender: raw destination %q is not IPv4", dst)
	}
	var addr [4]byte
	copy(addr[:], dst4)
	if err := unix.Sendto(r.fd, packet, 0, &unix.SockaddrInet4{Addr: addr}); err != nil {
		return fmt.Errorf("sender: raw sendto %s: %w", dst, err)
	}
	return nil
}

// Close releases the raw socket.
func (r *Raw) Close() error {
	if r.fd < 0 {
		return nil
	}
	fd := r.fd
	r.fd = -1
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("sender: close raw socket: %w", err)
	}
	return nil
}
