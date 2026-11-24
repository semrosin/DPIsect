package analyzer

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/semrosin/DPIsect/internal/generator"
)

func TestValidateRawPCAP(t *testing.T) {
	t.Parallel()

	fakePayload := []byte("fake-client-hello")
	realPayload := []byte("real-client-hello")
	pu := generator.RawFlow{
		SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.IPv4(10, 0, 0, 2),
		SrcPort: 40000, DstPort: 8443, SndNxt: 1000, RcvNxt: 2000, Window: 65535,
	}
	server := generator.RawFlow{
		SrcIP: pu.DstIP, DstIP: pu.SrcIP,
		SrcPort: pu.DstPort, DstPort: pu.SrcPort, SndNxt: 2000, RcvNxt: 1000, Window: 65535,
	}
	fake, err := generator.BuildRawIPv4TCP(generator.PlannedWirePacket{
		Payload: fakePayload, TTL: 1, Seq: 1000, Ack: 2000,
	}, pu)
	if err != nil {
		t.Fatalf("build fake: %v", err)
	}
	real, err := generator.BuildRawIPv4TCP(generator.PlannedWirePacket{
		Payload: realPayload, TTL: 64, Seq: 1000, Ack: 2000,
	}, pu)
	if err != nil {
		t.Fatalf("build real: %v", err)
	}
	ack, err := generator.BuildRawIPv4TCP(generator.PlannedWirePacket{
		Payload: []byte{1}, TTL: 64, Seq: 2000, Ack: 1000 + uint32(len(fakePayload)),
	}, server)
	if err != nil {
		t.Fatalf("build ack: %v", err)
	}

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "client.pcap")
	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("create pcap: %v", err)
	}
	pw := pcapgo.NewWriter(f)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("pcap header: %v", err)
	}
	for _, raw := range [][]byte{fake, ack, real} {
		frame := ethernetFrame(raw)
		if err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp: time.Now(), CaptureLength: len(frame), Length: len(frame),
		}, frame); err != nil {
			t.Fatalf("write packet: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close pcap: %v", err)
	}

	obs := rawObservationFile{
		ExperimentID: "d02-test-2026-11",
		Trials: []rawTrial{{
			Repetition:        1,
			FakeSent:          true,
			FakePayloadSHA256: payloadSHA256(fakePayload),
			FakeTTL:           1,
			FakeSeq:           1000,
			FakeAck:           2000,
			FakeChecksum:      uint16(fake[36])<<8 | uint16(fake[37]),
			FakeChecksumMode:  "correct",
			Flow:              pu,
			RealPayloadSHA256: payloadSHA256(realPayload),
			RealWritten:       true,
		}},
	}
	obsPath := filepath.Join(dir, "raw-observations.json")
	data, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("marshal observations: %v", err)
	}
	if err := os.WriteFile(obsPath, data, 0o600); err != nil {
		t.Fatalf("write observations: %v", err)
	}

	got, err := ValidateRawPCAP(context.Background(), pcapPath, pcapPath, obsPath)
	if err != nil {
		t.Fatalf("ValidateRawPCAP: %v", err)
	}
	if len(got.Trials) != 1 {
		t.Fatalf("trials = %d, want 1", len(got.Trials))
	}
	tv := got.Trials[0]
	if !tv.FakeSeen || !tv.RealClientHelloSeen || !tv.ServerACK {
		t.Errorf("validation = %+v", tv)
	}
	if tv.FakeTTL != 1 || !tv.FakeChecksumOK {
		t.Errorf("fake fields = ttl %d checksum_ok %v", tv.FakeTTL, tv.FakeChecksumOK)
	}
	if tv.EndpointBehavior != "accepted" {
		t.Errorf("endpoint behavior = %q, want accepted", tv.EndpointBehavior)
	}
}

func ethernetFrame(ip []byte) []byte {
	frame := make([]byte, 14+len(ip))
	frame[12], frame[13] = 0x08, 0x00
	copy(frame[14:], ip)
	return frame
}
