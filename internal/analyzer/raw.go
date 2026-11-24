package analyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/semrosin/DPIsect/internal/generator"
)

// RawActualValidation is the offline planned-vs-actual check required
// by docs/DEVELOPMENT.md stage 4. It never turns DPI behavior into a
// verdict; it records what the client PCAP proves about the endpoint.
type RawActualValidation struct {
	ExperimentID string               `json:"experiment_id"`
	Trials       []RawTrialValidation `json:"trials"`
	Notes        []string             `json:"notes,omitempty"`
}

// RawTrialValidation is one fake-probe / real-ClientHello pair.
type RawTrialValidation struct {
	Repetition          int      `json:"repetition"`
	FakeSent            bool     `json:"fake_sent"`
	FakeSeen            bool     `json:"fake_seen_client"`
	FakeSeenServer      bool     `json:"fake_seen_server"`
	FakeTTL             int      `json:"fake_ttl"`
	FakeTTLExpected     int      `json:"fake_ttl_expected"`
	FakeSeq             uint32   `json:"fake_seq"`
	FakeAck             uint32   `json:"fake_ack"`
	FakeChecksum        uint16   `json:"fake_checksum"`
	FakeChecksumExpect  uint16   `json:"fake_checksum_expected"`
	FakeChecksumOK      bool     `json:"fake_checksum_ok"`
	ServerACK           bool     `json:"server_ack"`
	ServerRST           bool     `json:"server_rst"`
	RealClientHelloSeen bool     `json:"real_client_hello_seen"`
	EndpointBehavior    string   `json:"endpoint_behavior"`
	Notes               []string `json:"notes,omitempty"`
}

type rawObservationFile struct {
	ExperimentID string     `json:"experiment_id"`
	Trials       []rawTrial `json:"trials"`
}

type rawTrial struct {
	Repetition        int               `json:"repetition"`
	FakeSent          bool              `json:"fake_sent"`
	FakePayloadSHA256 string            `json:"fake_payload_sha256"`
	FakeTTL           uint8             `json:"fake_ttl"`
	FakeSeq           uint32            `json:"fake_seq"`
	FakeAck           uint32            `json:"fake_ack"`
	FakeChecksum      uint16            `json:"fake_checksum"`
	FakeChecksumMode  string            `json:"fake_checksum_mode"`
	Flow              generator.RawFlow `json:"flow"`
	RealPayloadSHA256 string            `json:"real_payload_sha256"`
	RealWritten       bool              `json:"real_client_hello_written"`
}

// ValidateRawPCAP checks each observation against the client capture:
// the fake packet is present with the planned TTL/SEQ/ACK/checksum,
// the real ClientHello follows, and the endpoint answers (or does not)
// in a way that distinguishes delivered from dropped probes.
func ValidateRawPCAP(ctx context.Context, clientPCAP, serverPCAP, observationsPath string) (RawActualValidation, error) {
	data, err := os.ReadFile(observationsPath)
	if err != nil {
		return RawActualValidation{}, fmt.Errorf("read raw observations: %w", err)
	}
	var obs rawObservationFile
	if err := json.Unmarshal(data, &obs); err != nil {
		return RawActualValidation{}, fmt.Errorf("decode raw observations: %w", err)
	}

	clientPkts, err := readRawPCAP(ctx, clientPCAP)
	if err != nil {
		return RawActualValidation{}, err
	}
	var serverPkts []tcpPacket
	var notes []string
	if serverPCAP != "" {
		serverPkts, err = readRawPCAP(ctx, serverPCAP)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return RawActualValidation{}, err
			}
			notes = append(notes, "server PCAP is missing; endpoint delivery is client-side only")
		}
	}

	out := RawActualValidation{ExperimentID: obs.ExperimentID, Notes: notes}
	for _, trial := range obs.Trials {
		out.Trials = append(out.Trials, validateRawTrial(trial, clientPkts, serverPkts))
	}
	return out, nil
}

func readRawPCAP(ctx context.Context, path string) ([]tcpPacket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("read pcap header %s: %w", path, err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		return nil, fmt.Errorf("unsupported link type %s in %s", r.LinkType(), path)
	}
	return readTCPPackets(ctx, r)
}

func validateRawTrial(trial rawTrial, clientPkts, serverPkts []tcpPacket) RawTrialValidation {
	v := RawTrialValidation{
		Repetition:         trial.Repetition,
		FakeSent:           trial.FakeSent,
		FakeTTLExpected:    int(trial.FakeTTL),
		FakeSeq:            trial.FakeSeq,
		FakeAck:            trial.FakeAck,
		FakeChecksumExpect: trial.FakeChecksum,
		EndpointBehavior:   "unknown",
	}
	src4 := trial.Flow.SrcIP.To4()
	dst4 := trial.Flow.DstIP.To4()

	var fake, real *tcpPacket
	for i := range clientPkts {
		p := &clientPkts[i]
		if src4 == nil || dst4 == nil {
			continue
		}
		if !ip4Equal(p.srcIP, src4) || !ip4Equal(p.dstIP, dst4) ||
			p.srcPort != trial.Flow.SrcPort || p.dstPort != trial.Flow.DstPort {
			continue
		}
		if trial.FakePayloadSHA256 != "" && payloadSHA256(p.payload) == trial.FakePayloadSHA256 &&
			p.seq == trial.FakeSeq && p.ack == trial.FakeAck {
			fake = p
			break
		}
	}
	for i := range clientPkts {
		p := &clientPkts[i]
		if trial.RealPayloadSHA256 != "" && payloadSHA256(p.payload) == trial.RealPayloadSHA256 {
			real = p
			break
		}
	}
	if fake == nil && trial.FakeSent {
		v.Notes = append(v.Notes, "fake probe was sent but not found in capture")
	}
	if fake != nil {
		v.FakeSeen = true
		v.FakeTTL = int(fake.ttl)
		v.FakeSeq = fake.seq
		v.FakeAck = fake.ack
		v.FakeChecksum = fake.checksum
		v.FakeChecksumOK = fake.checksum == trial.FakeChecksum
		if fake.ttl != trial.FakeTTL {
			v.Notes = append(v.Notes, "observed TTL differs from plan")
		}
		if fake.seq != trial.FakeSeq || fake.ack != trial.FakeAck {
			v.Notes = append(v.Notes, "observed SEQ/ACK differs from plan")
		}
		if !v.FakeChecksumOK {
			v.Notes = append(v.Notes, "observed TCP checksum differs from plan (offload?)")
		}
	}

	v.RealClientHelloSeen = real != nil
	if fake == nil {
		if trial.RealWritten && !v.RealClientHelloSeen {
			v.Notes = append(v.Notes, "real ClientHello was written but not found in capture")
		}
		return v
	}

	// Server capture is the authority for delivery: a TTL=1 packet
	// reaches the client veth but not the server veth.
	for i := range serverPkts {
		p := &serverPkts[i]
		if trial.FakePayloadSHA256 != "" && payloadSHA256(p.payload) == trial.FakePayloadSHA256 &&
			p.seq == trial.FakeSeq && p.ack == trial.FakeAck {
			v.FakeSeenServer = true
			break
		}
	}

	// Only server answers between the fake and the real ClientHello
	// can belong to the fake; later ACKs may acknowledge the real one.
	end := fake.ts.Add(2 * time.Second)
	if real != nil && real.ts.After(fake.ts) {
		end = real.ts
	}
	for i := range clientPkts {
		p := &clientPkts[i]
		if !ip4Equal(p.srcIP, dst4) || !ip4Equal(p.dstIP, src4) ||
			p.srcPort != trial.Flow.DstPort || p.dstPort != trial.Flow.SrcPort {
			continue
		}
		if p.ts.Before(fake.ts) || !p.ts.Before(end) {
			continue
		}
		if p.flags&flagRST != 0 {
			v.ServerRST = true
		}
		if p.flags&flagACK != 0 {
			v.ServerACK = true
			if p.ack == fake.seq+uint32(len(fake.payload)) {
				v.EndpointBehavior = "accepted"
			}
		}
	}
	if v.EndpointBehavior == "unknown" {
		switch {
		case v.ServerRST:
			v.EndpointBehavior = "rejected_rst"
		case !v.FakeSeenServer:
			v.EndpointBehavior = "not_delivered"
		case v.ServerACK:
			v.EndpointBehavior = "not_accepted"
		default:
			v.EndpointBehavior = "rejected"
		}
	}
	if !v.FakeSeenServer {
		v.Notes = append(v.Notes, "fake probe was not present at the server capture point")
	}
	if trial.RealWritten && !v.RealClientHelloSeen {
		v.Notes = append(v.Notes, "real ClientHello was written but not found in capture")
	}
	return v
}

func ip4Equal(a [4]byte, b []byte) bool {
	return len(b) == 4 && a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

func payloadSHA256(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
