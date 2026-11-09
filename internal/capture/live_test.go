package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// fakeSource hands out a fixed list of frames, then blocks until
// Close unblocks it with an error.
type fakeSource struct {
	mu        sync.Mutex
	frames    [][]byte
	infos     []gopacket.CaptureInfo
	i         int
	closed    chan struct{}
	closeOnce sync.Once
	drained   chan struct{}
}

func newFakeSource(frames [][]byte, infos []gopacket.CaptureInfo) *fakeSource {
	return &fakeSource{
		frames:  frames,
		infos:   infos,
		closed:  make(chan struct{}),
		drained: make(chan struct{}),
	}
}

func (f *fakeSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	f.mu.Lock()
	if f.i < len(f.frames) {
		data := f.frames[f.i]
		ci := f.infos[f.i]
		f.i++
		drained := f.i == len(f.frames)
		f.mu.Unlock()
		if drained {
			close(f.drained)
		}
		return data, ci, nil
	}
	f.mu.Unlock()

	select {
	case <-f.closed:
		return nil, gopacket.CaptureInfo{}, errors.New("source closed")
	}
}

func (f *fakeSource) Close() {
	f.closeOnce.Do(func() { close(f.closed) })
}

func testFrames() ([][]byte, []gopacket.CaptureInfo) {
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	frames := [][]byte{
		{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03},
		{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00},
	}
	infos := []gopacket.CaptureInfo{
		{Timestamp: now, CaptureLength: len(frames[0]), Length: len(frames[0])},
		{Timestamp: now.Add(time.Second), CaptureLength: len(frames[1]), Length: len(frames[1])},
	}
	return frames, infos
}

func TestLiveRecordsPacketsToPCAP(t *testing.T) {
	t.Parallel()

	frames, infos := testFrames()
	src := newFakeSource(frames, infos)
	path := filepath.Join(t.TempDir(), "artifacts", "b01-test-2026-11", "client.pcap")
	l := newLive(PointClient, "lo", path, func() (packetSource, error) { return src, nil })

	if l.Path() != path {
		t.Errorf("Path = %q, want %q", l.Path(), path)
	}
	if l.Point() != PointClient {
		t.Errorf("Point = %q, want client", l.Point())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-src.drained:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for frames to be read")
	}
	if err := l.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pcap: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("pcap mode = %o, want 600 (docs/SAFETY.md §5)", perm)
	}
	d, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := d.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir mode = %o, want 700 (docs/SAFETY.md §5)", perm)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	if r.Snaplen() != DefaultSnapLen {
		t.Errorf("snaplen = %d, want %d", r.Snaplen(), DefaultSnapLen)
	}
	if r.LinkType() != linkType {
		t.Errorf("link type = %v, want %v", r.LinkType(), linkType)
	}
	for i, want := range frames {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			t.Fatalf("read packet %d: %v", i, err)
		}
		if string(data) != string(want) {
			t.Errorf("packet %d = % 02x, want % 02x", i, data, want)
		}
		if ci.CaptureLength != len(want) {
			t.Errorf("packet %d capture length = %d, want %d", i, ci.CaptureLength, len(want))
		}
	}
}

func TestLiveStartTwiceFails(t *testing.T) {
	t.Parallel()

	frames, infos := testFrames()
	src := newFakeSource(frames, infos)
	l := newLive(PointServer, "lo", filepath.Join(t.TempDir(), "s.pcap"),
		func() (packetSource, error) { return src, nil })

	ctx := context.Background()
	if err := l.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := l.Start(ctx); err == nil {
		t.Fatal("second Start: want error, got nil")
	}
	if err := l.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestLiveStopWithoutStartIsNoop(t *testing.T) {
	t.Parallel()

	l := newLive(PointClient, "lo", filepath.Join(t.TempDir(), "x.pcap"),
		func() (packetSource, error) {
			t.Fatal("open must not be called")
			return nil, nil
		})
	if err := l.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

func TestLiveStopUnblocksReader(t *testing.T) {
	t.Parallel()

	// The source blocks after its frames; Stop must close it and the
	// resulting read error must not be reported as a failure.
	frames, infos := testFrames()
	src := newFakeSource(frames, infos)
	l := newLive(PointClient, "lo", filepath.Join(t.TempDir(), "b.pcap"),
		func() (packetSource, error) { return src, nil })

	if err := l.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := l.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

type failingSource struct{}

func (failingSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, errors.New("disk exploded")
}

func (failingSource) Close() {}

func TestLiveSurfacesReadError(t *testing.T) {
	t.Parallel()

	l := newLive(PointClient, "lo", filepath.Join(t.TempDir(), "e.pcap"),
		func() (packetSource, error) { return failingSource{}, nil })

	if err := l.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wait until the goroutine observes the error and exits.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		done := l.done != nil && l.firstErr != nil
		l.mu.Unlock()
		if done {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := l.Stop(context.Background()); err == nil {
		t.Fatal("Stop: want read error, got nil")
	}
}
