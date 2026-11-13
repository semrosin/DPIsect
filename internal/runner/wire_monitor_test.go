package runner

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/semrosin/DPIsect/internal/sender"
)

type fakeWireSource struct {
	frames     [][]byte
	recorded   [][]byte
	timestamps []time.Time
	drops      uint
	err        error
	recordErr  error
}

type idleWireSource struct {
	cancel context.CancelFunc
}

func (s idleWireSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	s.cancel()
	return nil, gopacket.CaptureInfo{}, afpacket.ErrTimeout
}

func (idleWireSource) Drops() (uint, error)                      { return 0, nil }
func (idleWireSource) Record([]byte, gopacket.CaptureInfo) error { return nil }

func TestMonitorWireStopsAfterIdleCancellation(t *testing.T) {
	t.Parallel()

	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 10, MaxBytes: 1000, MaxRatePPS: 10})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := monitorWire(ctx, idleWireSource{cancel: cancel}, budget, cancel); err != nil {
		t.Fatalf("idle cancellation: %v", err)
	}
}

func (s *fakeWireSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if s.err != nil {
		return nil, gopacket.CaptureInfo{}, s.err
	}
	if len(s.frames) == 0 {
		return nil, gopacket.CaptureInfo{}, errors.New("unexpected read")
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	timestamp := time.Now()
	if len(s.timestamps) > 0 {
		timestamp = s.timestamps[0]
		s.timestamps = s.timestamps[1:]
	}
	return f, gopacket.CaptureInfo{Timestamp: timestamp, Length: len(f), CaptureLength: len(f)}, nil
}

func (s *fakeWireSource) Drops() (uint, error) { return s.drops, nil }

func (s *fakeWireSource) Record(frame []byte, _ gopacket.CaptureInfo) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	s.recorded = append(s.recorded, append([]byte(nil), frame...))
	return nil
}

func TestMonitorWireCancelsOnLimitOrCaptureLoss(t *testing.T) {
	t.Parallel()

	frame := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	for _, tc := range []struct {
		name   string
		source fakeWireSource
	}{
		{name: "packet limit", source: fakeWireSource{frames: [][]byte{frame}}},
		{name: "capture drops", source: fakeWireSource{frames: [][]byte{frame}, drops: 1}},
		{name: "read error", source: fakeWireSource{err: errors.New("capture failed")}},
		{name: "write error", source: fakeWireSource{frames: [][]byte{frame}, recordErr: errors.New("disk full")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 1, MaxBytes: 1000, MaxRatePPS: 10})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if err := monitorWire(ctx, &tc.source, budget, cancel); err == nil {
				t.Fatal("want error for unsafe capture or budget")
			}
			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("monitor did not cancel the series")
			}
		})
	}
}

type channelWireSource struct {
	frames chan []byte
}

func (s channelWireSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	select {
	case f := <-s.frames:
		return f, gopacket.CaptureInfo{Timestamp: time.Now(), Length: len(f), CaptureLength: len(f)}, nil
	case <-time.After(10 * time.Millisecond):
		return nil, gopacket.CaptureInfo{}, afpacket.ErrTimeout
	}
}

func TestMonitorWireUsesPacketTimestampsForRate(t *testing.T) {
	t.Parallel()

	frame := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	now := time.Unix(100, 0)
	source := &fakeWireSource{
		frames: [][]byte{frame, frame}, timestamps: []time.Time{now, now.Add(time.Millisecond)},
	}
	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 3})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = monitorWire(ctx, source, budget, cancel)
	if err == nil || !strings.Contains(err.Error(), "packets in one second") || budget.packets != 2 {
		t.Fatalf("monitor error = %v, packets = %d; want capture-time rate limit", err, budget.packets)
	}
}

func (channelWireSource) Drops() (uint, error)                      { return 0, nil }
func (channelWireSource) Record([]byte, gopacket.CaptureInfo) error { return nil }

func TestMonitorWireRecordsOnlyMatchingFrames(t *testing.T) {
	t.Parallel()

	unrelated := testTCPFrame(t, "192.0.2.1", "192.0.2.11", 50000, 443)
	matching := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	source := &fakeWireSource{frames: [][]byte{unrelated, matching}}
	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 1, MaxBytes: 1000, MaxRatePPS: 10})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := monitorWire(ctx, source, budget, cancel); err == nil {
		t.Fatal("expected budget stop")
	}
	if len(source.recorded) != 1 || !bytes.Equal(source.recorded[0], matching) {
		t.Fatalf("saved %d frames, want the matching one only", len(source.recorded))
	}
}

func TestMonitoredSNITrialsStopAfterBudget(t *testing.T) {
	t.Parallel()

	frame := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	source := channelWireSource{frames: make(chan []byte, 1)}
	budget, err := newWireBudget("192.0.2.10", 443, Budget{MaxPackets: 1, MaxBytes: 1000, MaxRatePPS: 10})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	probe := func(ctx context.Context, _, _ string) sender.TLSObservation {
		calls++
		source.frames <- frame
		<-ctx.Done()
		return sender.TLSObservation{Stage: "tcp", Error: ctx.Err().Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	trials, err := runMonitoredSNITrials(ctx, "192.0.2.10:443", []string{"a.example", "b.example"}, time.Second, 0, probe, source, budget)
	if err == nil || calls != 1 || len(trials) != 1 || budget.packets != 1 {
		t.Fatalf("error = %v, calls = %d, trials = %d, packets = %d", err, calls, len(trials), budget.packets)
	}
}

func TestMonitoredSNITrialsStopOnSYNRetry(t *testing.T) {
	t.Parallel()

	frame := testTCPFrame(t, "192.0.2.1", "192.0.2.10", 50000, 443)
	source := channelWireSource{frames: make(chan []byte, 2)}
	limit := 1
	budget, err := newWireBudget("192.0.2.10", 443, Budget{
		MaxPackets: 100, MaxBytes: 10000, MaxRatePPS: 10, MaxSYNRetransmissions: &limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	probe := func(ctx context.Context, _, _ string) sender.TLSObservation {
		calls++
		source.frames <- frame
		source.frames <- frame
		<-ctx.Done()
		return sender.TLSObservation{Stage: "tcp", Error: ctx.Err().Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	trials, err := runMonitoredSNITrials(ctx, "192.0.2.10:443", []string{"a.example", "b.example"}, time.Second, 0, probe, source, budget)
	if err == nil || !strings.Contains(err.Error(), "SYN retransmission") || calls != 1 || len(trials) != 1 || budget.synRetransmissions != 1 {
		t.Fatalf("error = %v, calls = %d, trials = %d, retransmissions = %d", err, calls, len(trials), budget.synRetransmissions)
	}
}
