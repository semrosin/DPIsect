package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/semrosin/DPIsect/internal/tlsparse"
)

// Cause is one of the known H01 causes the analyzer distinguishes on
// reference traces. It is a measurement, not an experiment verdict —
// the verdict is set by the operator/agent (docs/EXPERIMENTS.md §7).
type Cause string

const (
	// CauseNone: no interference observed; the flow completed.
	CauseNone Cause = "none"
	// CauseDrop: the client spoke, the server never did.
	CauseDrop Cause = "drop"
	// CauseRSTInjection: a server-side RST arrived mid-handshake.
	CauseRSTInjection Cause = "rst_injection"
	// CauseTLSAlert: the server answered with a TLS alert.
	CauseTLSAlert Cause = "tls_alert"
	// CauseModification: the ServerHello selects a cipher the client
	// never offered.
	CauseModification Cause = "modification"
	// CauseThrottling: server segments are separated by gaps above
	// ThrottleGapThreshold.
	CauseThrottling Cause = "throttling"
	// CauseInconclusive: the trace does not support any single cause.
	CauseInconclusive Cause = "inconclusive"
)

// ThrottleGapThreshold separates throttling from ordinary latency in
// the fixtures. Real experiments must tune it to the network
// (documentation sits next to each fixture in testdata/).
const ThrottleGapThreshold = 50 * time.Millisecond

// CauseObservation is the measurement for one client-side PCAP.
type CauseObservation struct {
	Cause  Cause
	Reason string // short; required when Cause is CauseInconclusive

	ClientAddr       string
	ServerAddr       string
	Packets          int
	SawClientHello   bool
	SawServerHello   bool
	SelectedCipher   string // hex, e.g. "0x1301"; empty without ServerHello
	ServerAlert      bool
	AlertLevel       int
	AlertDescription int
	ServerRST        bool
	CompletedHTTP    bool
	// MaxServerGap is the largest inter-arrival gap between
	// consecutive server data segments.
	MaxServerGap time.Duration
	// StreamGap reports a TCP reassembly discontinuity (loss,
	// retransmission or out-of-order capture): classification must not
	// claim drop on such a trace.
	StreamGap bool
}

// ClassifyPCAP reads a client-side PCAP and reports which known cause
// the trace exhibits. A returned error means the file itself is
// unreadable; classification doubt is CauseInconclusive with a reason.
// Context cancellation aborts the scan (docs/GO_STYLE.md §4).
func ClassifyPCAP(ctx context.Context, path string) (CauseObservation, error) {
	f, err := os.Open(path)
	if err != nil {
		return CauseObservation{}, fmt.Errorf("open pcap: %w", err)
	}
	defer func() { _ = f.Close() }()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		return CauseObservation{}, fmt.Errorf("read pcap header: %w", err)
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		return CauseObservation{
			Cause:  CauseInconclusive,
			Reason: fmt.Sprintf("unsupported link type %s", r.LinkType()),
		}, nil
	}

	pkts, err := readTCPPackets(ctx, r)
	if err != nil {
		return CauseObservation{}, err
	}
	return classifyFlow(pkts), nil
}

// maxPackets bounds the in-memory scan of one capture.
const maxPackets = 1_000_000

const (
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

type tcpPacket struct {
	ts      time.Time
	srcIP   [4]byte
	dstIP   [4]byte
	srcPort uint16
	dstPort uint16
	seq     uint32
	flags   uint8
	payload []byte
}

func readTCPPackets(ctx context.Context, r *pcapgo.Reader) ([]tcpPacket, error) {
	var out []tcpPacket
	for {
		if len(out)%1024 == 0 && ctx.Err() != nil {
			return nil, fmt.Errorf("scan canceled: %w", ctx.Err())
		}
		if len(out) >= maxPackets {
			return nil, fmt.Errorf("capture exceeds %d packets", maxPackets)
		}
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read packet: %w", err)
		}
		p, ok := parseEthernetTCP(data)
		if !ok {
			continue
		}
		p.ts = ci.Timestamp
		out = append(out, p)
	}
}

// parseEthernetTCP extracts an IPv4/TCP packet; false for everything
// else (ARP, IPv6, UDP, fragments).
func parseEthernetTCP(frame []byte) (tcpPacket, bool) {
	var p tcpPacket
	if len(frame) < 14 {
		return p, false
	}
	if uint16(frame[12])<<8|uint16(frame[13]) != 0x0800 {
		return p, false
	}
	ip := frame[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return p, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return p, false
	}
	if ip[9] != 6 { // TCP
		return p, false
	}
	if frag := uint16(ip[6])<<8 | uint16(ip[7]); frag&0x3fff != 0 {
		return p, false
	}
	copy(p.srcIP[:], ip[12:16])
	copy(p.dstIP[:], ip[16:20])

	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return p, false
	}
	p.srcPort = uint16(tcp[0])<<8 | uint16(tcp[1])
	p.dstPort = uint16(tcp[2])<<8 | uint16(tcp[3])
	p.seq = uint32(tcp[4])<<24 | uint32(tcp[5])<<16 | uint32(tcp[6])<<8 | uint32(tcp[7])
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		return p, false
	}
	p.flags = tcp[13]
	p.payload = tcp[dataOff:]
	return p, true
}

// dirStream reassembles one direction in sequence order.
type dirStream struct {
	data    []byte
	nextSeq uint32
	haveSeq bool
}

func (d *dirStream) push(seq uint32, payload []byte) (gap bool) {
	if len(payload) == 0 {
		return false
	}
	if !d.haveSeq {
		d.haveSeq, d.nextSeq = true, seq
	}
	switch {
	case seq == d.nextSeq:
		d.data = append(d.data, payload...)
		d.nextSeq += uint32(len(payload))
	case seq < d.nextSeq:
		overlap := d.nextSeq - seq
		if overlap >= uint32(len(payload)) {
			return false // full retransmission
		}
		d.data = append(d.data, payload[overlap:]...)
		d.nextSeq += uint32(len(payload)) - overlap
	default:
		return true // missing bytes: cannot reassemble past this point
	}
	return false
}

// flowAddr is one side of the connection.
type flowAddr struct {
	ip   [4]byte
	port uint16
}

func (a flowAddr) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", a.ip[0], a.ip[1], a.ip[2], a.ip[3], a.port)
}

// classifyFlow applies the ordered decision ladder of H01: transport
// evidence (RST) first, then protocol answers (alert, bad
// ServerHello), then timing, then absence, then completion.
func classifyFlow(pkts []tcpPacket) CauseObservation {
	obs := CauseObservation{Packets: len(pkts)}

	var client, server flowAddr
	foundSYN := false
	for i := range pkts {
		if pkts[i].flags&flagSYN != 0 && pkts[i].flags&flagACK == 0 {
			client = flowAddr{ip: pkts[i].srcIP, port: pkts[i].srcPort}
			server = flowAddr{ip: pkts[i].dstIP, port: pkts[i].dstPort}
			foundSYN = true
			break
		}
	}
	if !foundSYN {
		obs.Cause, obs.Reason = CauseInconclusive, "no SYN in capture"
		return obs
	}
	obs.ClientAddr, obs.ServerAddr = client.String(), server.String()

	fromServer := func(p tcpPacket) bool {
		return flowAddr{ip: p.srcIP, port: p.srcPort} == server
	}
	fromClient := func(p tcpPacket) bool {
		return flowAddr{ip: p.srcIP, port: p.srcPort} == client
	}

	var (
		cStream, sStream dirStream
		lastServerData   time.Time
	)
	for i := range pkts {
		p := pkts[i]
		if p.flags&flagRST != 0 && fromServer(p) {
			obs.ServerRST = true
		}
		if len(p.payload) == 0 {
			continue
		}
		if fromServer(p) {
			if sStream.push(p.seq, p.payload) {
				obs.StreamGap = true
			}
			if !lastServerData.IsZero() {
				if gap := p.ts.Sub(lastServerData); gap > obs.MaxServerGap {
					obs.MaxServerGap = gap
				}
			}
			lastServerData = p.ts
		} else if fromClient(p) {
			if cStream.push(p.seq, p.payload) {
				obs.StreamGap = true
			}
		}
	}

	// Client side: the ClientHello defines the offered cipher suites.
	for _, rec := range walkTLS(cStream.data) {
		if rec.Type != tlsparse.TypeHandshake || len(rec.Payload) == 0 || rec.Payload[0] != 0x01 {
			continue
		}
		ch, err := tlsparse.ParseClientHello(rec.Payload)
		if err != nil {
			continue
		}
		obs.SawClientHello = true
		offer := make(map[uint16]bool, len(ch.CipherSuiteList))
		for _, cs := range ch.CipherSuiteList {
			offer[cs] = true
		}
		return classifyServerEvidence(obs, walkTLS(sStream.data), offer)
	}
	obs.Cause, obs.Reason = CauseInconclusive, "no parseable ClientHello"
	return obs
}

// classifyServerEvidence runs the server-side decision ladder.
func classifyServerEvidence(obs CauseObservation, serverRecs []tlsparse.Record, offer map[uint16]bool) CauseObservation {
	var (
		alertRec  *tlsparse.Record
		shCipher  uint16
		sawSH     bool
		completed bool
	)
	for i, rec := range serverRecs {
		switch {
		case rec.Type == tlsparse.TypeAlert && alertRec == nil:
			alertRec = &serverRecs[i]
		case rec.Type == tlsparse.TypeHandshake && len(rec.Payload) > 0 &&
			rec.Payload[0] == 0x02 && !sawSH:
			if cipher, err := tlsparse.ParseServerHello(rec.Payload); err == nil {
				sawSH, shCipher = true, cipher
			}
		case rec.Type == tlsparse.TypeApplicationData && !completed:
			if bytes.Contains(rec.Payload, []byte("HTTP/1.")) {
				completed = true
			}
		}
	}

	obs.SawServerHello = sawSH
	obs.CompletedHTTP = completed
	if alertRec != nil {
		if level, desc, err := alertRec.Alert(); err == nil {
			obs.ServerAlert = true
			obs.AlertLevel, obs.AlertDescription = int(level), int(desc)
		}
	}
	if sawSH {
		obs.SelectedCipher = fmt.Sprintf("0x%04x", shCipher)
	}

	switch {
	case obs.ServerRST:
		obs.Cause = CauseRSTInjection
		obs.Reason = "server-side RST after ClientHello"
	case obs.ServerAlert:
		obs.Cause = CauseTLSAlert
		obs.Reason = "TLS alert record from server"
	case sawSH && !offer[shCipher]:
		obs.Cause = CauseModification
		obs.Reason = fmt.Sprintf("ServerHello cipher %s not in client offer", obs.SelectedCipher)
	case sawSH && obs.MaxServerGap >= ThrottleGapThreshold:
		obs.Cause = CauseThrottling
		obs.Reason = fmt.Sprintf("server segment gap %s exceeds %s",
			obs.MaxServerGap, ThrottleGapThreshold)
	case !sawSH && !obs.StreamGap:
		obs.Cause = CauseDrop
		obs.Reason = "no ServerHello after ClientHello"
	case !sawSH && obs.StreamGap:
		obs.Cause, obs.Reason = CauseInconclusive, "server stream has gaps; drop not provable"
	case completed && obs.MaxServerGap < ThrottleGapThreshold:
		obs.Cause, obs.Reason = CauseNone, "handshake and HTTP completed without anomalies"
	default:
		obs.Cause = CauseInconclusive
		obs.Reason = "incomplete flow without a distinguishing signature"
	}
	return obs
}

// walkTLS parses consecutive TLS records from a reassembled stream;
// the first malformed or truncated record stops the walk.
func walkTLS(stream []byte) []tlsparse.Record {
	var out []tlsparse.Record
	rest := stream
	for len(rest) >= 5 {
		length := int(rest[3])<<8 | int(rest[4])
		if length > tlsparse.MaxRecordPayload || 5+length > len(rest) {
			break
		}
		rec, err := tlsparse.ReadRecord(bytes.NewReader(rest[:5+length]))
		if err != nil {
			break
		}
		out = append(out, rec)
		rest = rest[5+length:]
	}
	return out
}
