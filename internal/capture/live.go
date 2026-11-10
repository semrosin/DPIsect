package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// DefaultSnapLen is the snapshot length of produced PCAP files.
const DefaultSnapLen = 65535

// linkType is always Ethernet: AF_PACKET raw sockets hand out full
// frames, including the 14-byte pseudo-header on loopback.
const linkType = layers.LinkTypeEthernet

// flushEveryPCAPPackets bounds how many packets may sit in the buffer.
const flushEveryPCAPPackets = 64

// packetSource yields raw frames. Reads must return periodically with
// afpacket.ErrTimeout so the reader can stop before the source is closed.
type packetSource interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
	Close()
}

// Live is one PCAP recording at a single vantage point. Start spawns
// the dedicated writer goroutine; Stop waits for it, flushes and closes
// the file. Start and Stop must be called serially — the runner owns
// that ordering (docs/ARCHITECTURE.md §1).
type Live struct {
	point Point
	iface string
	path  string
	open  func() (packetSource, error)

	mu       sync.Mutex
	running  bool
	firstErr error
	stop     chan struct{}
	done     chan struct{}
	src      packetSource
	f        *os.File
	bw       *bufio.Writer
	pw       *pcapgo.Writer
}

// newLive builds a Live with an injectable source factory.
func newLive(point Point, iface, path string, open func() (packetSource, error)) *Live {
	return &Live{point: point, iface: iface, path: path, open: open}
}

// Path returns the PCAP file path outside git (docs/SAFETY.md §5).
func (l *Live) Path() string { return l.path }

// Point returns the vantage point of this capture.
func (l *Live) Point() Point { return l.point }

// Start prepares the PCAP file (dir 0700, file 0600), opens the packet
// source and spawns the writer goroutine; it returns once the writer
// is running. The goroutine stops reading when ctx is done or Stop is
// called; the file stays open until Stop.
func (l *Live) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("capture %s: already running", l.point)
	}

	dir := filepath.Dir(l.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("capture %s: create dir: %w", l.point, err)
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("capture %s: open file: %w", l.point, err)
	}
	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(DefaultSnapLen, linkType); err != nil {
		_ = f.Close()
		return fmt.Errorf("capture %s: write pcap header: %w", l.point, err)
	}

	src, err := l.open()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("capture %s: open source: %w", l.point, err)
	}

	l.running = true
	l.firstErr = nil
	l.stop = make(chan struct{})
	l.done = make(chan struct{})
	l.src = src
	l.f = f
	l.bw = bufio.NewWriter(f)
	l.pw = pw

	go l.run(ctx)
	return nil
}

// Stop waits for the bounded read to return, closes the source, flushes the buffer
// and closes the file. It returns the first error observed by the
// writer, if any. Stopping a non-running capture is a no-op.
func (l *Live) Stop(_ context.Context) error {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return nil
	}
	l.running = false
	stop, done, src := l.stop, l.done, l.src
	l.mu.Unlock()

	close(stop)
	<-done
	src.Close()

	l.mu.Lock()
	defer l.mu.Unlock()

	var err error
	if l.firstErr != nil {
		err = fmt.Errorf("capture %s: %w", l.point, l.firstErr)
	}
	if ferr := l.bw.Flush(); ferr != nil && err == nil {
		err = fmt.Errorf("capture %s: flush: %w", l.point, ferr)
	}
	if cerr := l.f.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("capture %s: close: %w", l.point, cerr)
	}
	return err
}

// run is the dedicated writer goroutine: it must not be reached from
// the network cycle (docs/GO_STYLE.md §4).
func (l *Live) run(ctx context.Context) {
	defer close(l.done)

	n := 0
	for {
		select {
		case <-l.stop:
			return
		case <-ctx.Done():
			return
		default:
		}

		data, ci, err := l.src.ReadPacketData()
		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				continue
			}
			select {
			case <-l.stop:
				return
			default:
			}
			// Any non-timeout error before shutdown is a real failure.
			l.mu.Lock()
			l.firstErr = fmt.Errorf("read packet: %w", err)
			l.mu.Unlock()
			return
		}
		if err := l.pw.WritePacket(ci, data); err != nil {
			l.mu.Lock()
			l.firstErr = fmt.Errorf("write packet: %w", err)
			l.mu.Unlock()
			return
		}
		n++
		if n%flushEveryPCAPPackets == 0 {
			_ = l.bw.Flush()
		}
	}
}
