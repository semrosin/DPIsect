//go:build linux

package runner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// PACKET_VNET_HDR adds a Linux virtio_net_hdr before the Ethernet bytes.
const vnetHeaderLen = 10

type afpacketWireSource struct {
	fd      int
	frame   []byte
	control []byte
	dropped uint
	file    *os.File
	writer  *pcapgo.Writer
}

func openWireSocket(ifc *net.Interface) (fd int, err error) {
	fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fd, err
	}
	defer func() {
		if err != nil {
			// The setup error takes precedence over closing the unused socket.
			_ = unix.Close(fd)
		}
	}()
	if err = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VNET_HDR, 1); err != nil {
		return fd, fmt.Errorf("enable packet segmentation metadata: %w", err)
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS_NEW, 1); err != nil {
		return fd, fmt.Errorf("enable packet timestamps: %w", err)
	}
	timeout := unix.NsecToTimeval(int64(100 * time.Millisecond))
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return fd, fmt.Errorf("set packet read timeout: %w", err)
	}
	if ifc.Flags&net.FlagLoopback != 0 {
		if err = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); err != nil {
			return fd, fmt.Errorf("filter loopback duplicates: %w", err)
		}
	}
	if err = filterWireIPv4TCP(fd); err != nil {
		return fd, fmt.Errorf("filter IPv4 TCP: %w", err)
	}
	protocol := binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL})
	err = unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: ifc.Index})
	return fd, err
}

// Filter out unrelated protocols before recvmsg translates their offload
// metadata. Accept plain IPv4/TCP and IPv4/TCP within one VLAN tag.
func filterWireIPv4TCP(fd int) error {
	filter, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeIPv4), SkipTrue: 6},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeDot1Q), SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeQinQ), SkipFalse: 6},
		bpf.LoadAbsolute{Off: 16, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.EthernetTypeIPv4), SkipFalse: 4},
		bpf.LoadAbsolute{Off: 27, Size: 1},
		bpf.Jump{Skip: 1},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(layers.IPProtocolTCP), SkipTrue: 1},
		bpf.RetConstant{Val: 0},
		bpf.RetConstant{Val: ^uint32(0)},
	})
	if err != nil {
		return err
	}
	var instructions []unix.SockFilter
	for _, op := range filter {
		instructions = append(instructions, unix.SockFilter{Code: op.Op, Jt: op.Jt, Jf: op.Jf, K: op.K})
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
		Len: uint16(len(instructions)), Filter: &instructions[0],
	})
}

func newAFPacketWireSource(iface, path string) (*afpacketWireSource, error) {
	if iface == "" || path == "" {
		return nil, fmt.Errorf("wire monitor: interface and capture path are required")
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("wire monitor: inspect interface: %w", err)
	}
	fd, err := openWireSocket(ifc)
	if err != nil {
		return nil, fmt.Errorf("wire monitor: open interface: %w", err)
	}
	source, err := newWireCaptureFile(fd, path)
	if err != nil {
		// The file setup error takes precedence over closing the unused socket.
		_ = unix.Close(fd)
		return nil, err
	}
	return source, nil
}

func newWireCaptureFile(fd int, path string) (*afpacketWireSource, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("wire monitor: create capture directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("wire monitor: create capture: %w", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		// Return the error from writing the header.
		_ = f.Close()
		return nil, fmt.Errorf("wire monitor: write capture header: %w", err)
	}
	return &afpacketWireSource{
		fd: fd, file: f, writer: w,
		frame: make([]byte, vnetHeaderLen+65535), control: make([]byte, unix.CmsgSpace(16)),
	}, nil
}

func (s *afpacketWireSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var ci gopacket.CaptureInfo
	n, controlLen, flags, _, err := unix.Recvmsg(s.fd, s.frame, s.control, 0)
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
		return nil, ci, afpacket.ErrTimeout
	}
	if err != nil {
		return nil, ci, err
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n < vnetHeaderLen {
		return nil, ci, errors.New("truncated packet or capture metadata")
	}
	messages, err := unix.ParseSocketControlMessage(s.control[:controlLen])
	if err != nil {
		return nil, ci, fmt.Errorf("decode capture metadata: %w", err)
	}
	for _, msg := range messages {
		if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SO_TIMESTAMPNS_NEW && len(msg.Data) == 16 {
			sec := int64(binary.NativeEndian.Uint64(msg.Data[:8]))
			nsec := int64(binary.NativeEndian.Uint64(msg.Data[8:]))
			ci.Timestamp = time.Unix(sec, nsec)
			break
		}
	}
	// The kernel writes the legacy virtio header in its native byte order.
	gso := wireGSO{kind: s.frame[1], payloadSize: int(binary.NativeEndian.Uint16(s.frame[4:6]))}
	if gso != (wireGSO{}) {
		ci.AncillaryData = []any{gso}
	}
	frame := s.frame[vnetHeaderLen:n]
	ci.Length, ci.CaptureLength = len(frame), len(frame)
	return frame, ci, nil
}

func (s *afpacketWireSource) Record(frame []byte, ci gopacket.CaptureInfo) error {
	return s.writer.WritePacket(ci, frame)
}

func (s *afpacketWireSource) stop() error {
	return errors.Join(unix.Close(s.fd), s.file.Close())
}

func (s *afpacketWireSource) Drops() (uint, error) {
	stats, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, err
	}
	// Reading PACKET_STATISTICS resets the kernel counter.
	s.dropped += uint(stats.Drops)
	return s.dropped, nil
}
