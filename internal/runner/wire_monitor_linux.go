//go:build linux

package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type afpacketWireSource struct {
	*afpacket.TPacket
	file   *os.File
	writer *pcapgo.Writer
}

func newAFPacketWireSource(iface, path string) (*afpacketWireSource, error) {
	if iface == "" || path == "" {
		return nil, fmt.Errorf("wire monitor: interface and capture path are required")
	}
	p, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion2),
		afpacket.OptPollTimeout(100*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("wire monitor: open interface: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		p.Close()
		return nil, fmt.Errorf("wire monitor: create capture directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		p.Close()
		return nil, fmt.Errorf("wire monitor: create capture: %w", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		p.Close()
		_ = f.Close()
		return nil, fmt.Errorf("wire monitor: write capture header: %w", err)
	}
	return &afpacketWireSource{TPacket: p, file: f, writer: w}, nil
}

func (s *afpacketWireSource) Record(frame []byte, ci gopacket.CaptureInfo) error {
	return s.writer.WritePacket(ci, frame)
}

func (s *afpacketWireSource) stop() error {
	s.TPacket.Close()
	return s.file.Close()
}

func (s *afpacketWireSource) Drops() (uint, error) {
	v2, v3, err := s.SocketStats()
	if err != nil {
		return 0, err
	}
	return v2.Drops() + v3.Drops(), nil
}
