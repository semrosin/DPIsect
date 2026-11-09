package analyzer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/semrosin/DPIsect/internal/tlsparse"
)

func TestClassifyPCAPMissingFile(t *testing.T) {
	t.Parallel()

	if _, err := ClassifyPCAP(t.Context(), filepath.Join(t.TempDir(), "nope.pcap")); err == nil {
		t.Fatal("want error for missing file, got nil")
	}
}

func TestClassifyPCAPUnsupportedLinkType(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "raw.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeRaw); err != nil {
		t.Fatalf("header: %v", err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: 4,
		Length:        4,
	}, []byte{0x45, 0, 0, 0}); err != nil {
		t.Fatalf("packet: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	obs, err := ClassifyPCAP(t.Context(), path)
	if err != nil {
		t.Fatalf("ClassifyPCAP: %v", err)
	}
	if obs.Cause != CauseInconclusive {
		t.Errorf("cause = %s, want inconclusive", obs.Cause)
	}
	if obs.Reason == "" {
		t.Error("reason must explain the inconclusive result")
	}
}

func TestClassifyPCAPNoSYN(t *testing.T) {
	t.Parallel()

	// A single TCP packet without a SYN: no flow identity.
	path := filepath.Join(t.TempDir(), "nosyn.pcap")
	if err := writeSingleTCPPacket(path, 0x10); err != nil { // ACK only
		t.Fatalf("write: %v", err)
	}

	obs, err := ClassifyPCAP(t.Context(), path)
	if err != nil {
		t.Fatalf("ClassifyPCAP: %v", err)
	}
	if obs.Cause != CauseInconclusive || obs.Reason != "no SYN in capture" {
		t.Errorf("obs = %+v, want inconclusive (no SYN)", obs)
	}
}

func TestClassifyPCAPDropsBrokenStream(t *testing.T) {
	t.Parallel()

	// SYN, SYN-ACK, ACK, ClientHello — then the server starts a
	// ServerHello that never finishes: a stream gap must not be
	// classified as drop.
	path := filepath.Join(t.TempDir(), "gap.pcap")
	if err := writeFlowWithServerGap(path); err != nil {
		t.Fatalf("write: %v", err)
	}

	obs, err := ClassifyPCAP(t.Context(), path)
	if err != nil {
		t.Fatalf("ClassifyPCAP: %v", err)
	}
	if obs.Cause != CauseInconclusive {
		t.Errorf("cause = %s (%s), want inconclusive on stream gap",
			obs.Cause, obs.Reason)
	}
}

// openFlowWriter starts a pcap file with the deterministic flow
// parameters; callers close the file (double close is ignored).
func openFlowWriter(path string) (*os.File, *genFlow, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, newGenFlow(w, time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)), nil
}

func writeSingleTCPPacket(path string, flags uint8) error {
	f, g, err := openFlowWriter(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	g.clientSend(flags, nil)
	return f.Close()
}

func writeFlowWithServerGap(path string) error {
	f, g, err := openFlowWriter(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	g.handshakeUpToCH()
	rec := tlsRecord(tlsparse.TypeHandshake, serverHelloBody(0x1301))
	g.serverSend(flagPSH|flagACK, rec[:10])
	// Skip bytes 10..15: the reassembly sees a sequence gap.
	g.sSeq += 5
	g.serverSend(flagPSH|flagACK, rec[15:])
	return f.Close()
}
