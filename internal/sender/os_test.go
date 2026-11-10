package sender

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/generator"
)

// pipePair dials into an in-memory connection and returns the peer
// side for assertions.
func pipePair(t *testing.T, s *OS) net.Conn {
	t.Helper()

	client, server := net.Pipe()
	s.dial = func(context.Context, string) (net.Conn, error) { return client, nil }
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func TestOSSendsPayloadInOrder(t *testing.T) {
	t.Parallel()

	s := NewOS("example.test:443")
	peer := pipePair(t, s)
	defer func() { _ = s.Close() }()

	payload := []byte("hello dpi world")
	got := make(chan []byte, 1)
	go func() {
		buf, _ := io.ReadAll(peer)
		got <- buf
	}()

	if err := s.Send(t.Context(), generator.PlannedWirePacket{Payload: payload}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	_ = s.Close()

	if string(<-got) != string(payload) {
		t.Error("peer received different bytes")
	}
}

func TestOSSplitOffsetsBecomeSeparateWrites(t *testing.T) {
	t.Parallel()

	s := NewOS("example.test:443")
	peer := pipePair(t, s)
	defer func() { _ = s.Close() }()

	payload := []byte("0123456789")
	// Two writes of 4 and 6 bytes, asserted by exact-size reads.
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		if _, err := io.ReadFull(peer, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "0123" {
			errc <- errors.New("first chunk = " + string(buf))
			return
		}
		buf = make([]byte, 6)
		if _, err := io.ReadFull(peer, buf); err != nil {
			errc <- err
			return
		}
		if string(buf) != "456789" {
			errc <- errors.New("second chunk = " + string(buf))
			return
		}
		errc <- nil
	}()

	err := s.Send(t.Context(), generator.PlannedWirePacket{
		Payload:      payload,
		SplitOffsets: []int{4},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := <-errc; err != nil {
		t.Errorf("peer: %v", err)
	}
}

func TestOSDialsLazilyOnFirstSend(t *testing.T) {
	t.Parallel()

	s := NewOS("example.test:443")
	dials := 0
	s.dial = func(context.Context, string) (net.Conn, error) {
		dials++
		return discardConn{}, nil
	}

	if dials != 0 {
		t.Fatalf("dials before Send = %d, want 0", dials)
	}
	if err := s.Send(t.Context(), generator.PlannedWirePacket{Payload: []byte("x")}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if dials != 1 {
		t.Errorf("dials after Send = %d, want 1", dials)
	}
}

func TestOSSendAfterMSPaces(t *testing.T) {
	t.Parallel()

	s := NewOS("example.test:443")
	s.dial = func(context.Context, string) (net.Conn, error) { return discardConn{}, nil }
	defer func() { _ = s.Close() }()

	start := time.Now()
	err := s.Send(t.Context(), generator.PlannedWirePacket{
		Payload:     []byte("x"),
		SendAfterMS: 50,
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("Send returned after %s, want >= 50ms pacing", elapsed)
	}
}

// discardConn swallows writes so a pacing test needs no peer reader.
type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }
func (discardConn) Close() error                { return nil }

func TestOSPacingHonorsContextCancel(t *testing.T) {
	t.Parallel()

	s := NewOS("example.test:443")
	s.dial = func(context.Context, string) (net.Conn, error) {
		t.Error("dial must not happen after canceled pacing")
		return nil, errors.New("unreachable")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := s.Send(ctx, generator.PlannedWirePacket{Payload: []byte("x"), SendAfterMS: 10_000})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestOSSendRejectsOutOfRangeSplit(t *testing.T) {
	t.Parallel()

	s := NewOS("example.test:443")
	err := s.Send(t.Context(), generator.PlannedWirePacket{
		Payload:      []byte("abc"),
		SplitOffsets: []int{9},
	})
	if err == nil {
		t.Fatal("want error for out-of-range split offset, got nil")
	}
}

func TestOSCloseWithoutDialIsNoop(t *testing.T) {
	t.Parallel()

	if err := NewOS("example.test:443").Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
