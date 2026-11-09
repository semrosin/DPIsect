package analyzer

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/semrosin/DPIsect/internal/generator"
	"github.com/semrosin/DPIsect/internal/tlsparse"
)

// fixture describes one reference trace: where it lives and what the
// classifier must report for it (question H01). The annotation and
// applicability bounds sit next to the trace as <name>.md.
type fixture struct {
	dir   string
	name  string
	want  Cause
	build func(g *genFlow)
}

// regenEnv gates fixture regeneration so normal test runs stay read-only.
const regenEnv = "DPISECT_REGEN_FIXTURES"

var fixtures = []fixture{
	{
		dir:  "control",
		name: "complete_handshake",
		want: CauseNone,
		build: func(g *genFlow) {
			g.handshakeUpToCH()
			g.serverTLS(serverHelloBody(0x1301))
			g.serverTLS(serverCertificateBody())
			g.serverTLS(serverHelloDoneBody())
			g.clientRecord(tlsparse.TypeApplicationData, clientGetBody())
			g.serverRecord(tlsparse.TypeApplicationData, serverHTTPBody())
			g.closeFlow()
		},
	},
	{
		dir:  "drop",
		name: "client_hello_dropped",
		want: CauseDrop,
		build: func(g *genFlow) {
			// The ClientHello was dropped: the server never answers.
			g.handshakeUpToCH()
		},
	},
	{
		dir:  "rst_injection",
		name: "rst_after_client_hello",
		want: CauseRSTInjection,
		build: func(g *genFlow) {
			g.handshakeUpToCH()
			g.serverRST()
		},
	},
	{
		dir:  "tls_alert",
		name: "handshake_failure_alert",
		want: CauseTLSAlert,
		build: func(g *genFlow) {
			g.handshakeUpToCH()
			g.serverRecord(tlsparse.TypeAlert, alertHandshakeFailureBody())
		},
	},
	{
		dir:  "modification",
		name: "server_cipher_not_offered",
		want: CauseModification,
		build: func(g *genFlow) {
			g.handshakeUpToCH()
			g.serverTLS(serverHelloBody(0x9999)) // not in the client offer
			g.clientRST()
		},
	},
	{
		dir:  "throttling",
		name: "split_server_hello",
		want: CauseThrottling,
		build: func(g *genFlow) {
			g.handshakeUpToCH()
			// ServerHello deliberately split into three segments with
			// 80 ms gaps between them; the rest proceeds normally.
			rec := tlsRecord(tlsparse.TypeHandshake, serverHelloBody(0x1301))
			cut1, cut2 := 10, 25
			g.serverTLSSegment(rec[:cut1], 80*time.Millisecond)
			g.serverTLSSegment(rec[cut1:cut2], 80*time.Millisecond)
			g.serverTLSSegment(rec[cut2:], 0)
			g.serverTLS(serverCertificateBody())
			g.serverTLS(serverHelloDoneBody())
			g.clientRecord(tlsparse.TypeApplicationData, clientGetBody())
			g.serverRecord(tlsparse.TypeApplicationData, serverHTTPBody())
			g.closeFlow()
		},
	},
}

// TestH01_RegenerateFixtures rewrites the testdata traces. Run
// explicitly:
//
//	DPISECT_REGEN_FIXTURES=1 go test ./internal/analyzer -run TestH01_RegenerateFixtures
//
// The <name>.md annotations are authored by hand and never rewritten.
func TestH01_RegenerateFixtures(t *testing.T) {
	if os.Getenv(regenEnv) != "1" {
		t.Skipf("set %s=1 to regenerate fixtures", regenEnv)
	}

	root := filepath.Join("..", "..", "testdata")
	base := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	for _, fx := range fixtures {
		t.Run(fx.dir+"/"+fx.name, func(t *testing.T) {
			dir := filepath.Join(root, fx.dir)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			pcapPath := filepath.Join(dir, fx.name+".pcap")
			if err := writeFixturePCAP(pcapPath, base, fx.build); err != nil {
				t.Fatalf("write pcap: %v", err)
			}
		})
	}
}

// TestH01_ClassifyFixtures checks the classifier against every
// reference trace with a known cause.
func TestH01_ClassifyFixtures(t *testing.T) {
	t.Parallel()

	for _, fx := range fixtures {
		t.Run(fx.dir+"/"+fx.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join("..", "..", "testdata", fx.dir, fx.name+".pcap")
			obs, err := ClassifyPCAP(t.Context(), path)
			if err != nil {
				t.Fatalf("ClassifyPCAP: %v", err)
			}
			if obs.Cause != fx.want {
				t.Errorf("cause = %s (%s), want %s",
					obs.Cause, obs.Reason, fx.want)
			}
			if obs.Reason == "" {
				t.Error("reason must always be filled")
			}
			if !obs.SawClientHello {
				t.Error("every fixture must contain a parseable ClientHello")
			}
		})
	}
}

// --- fixture construction -------------------------------------------------

// genFlow writes one deterministic TCP flow into a PCAP writer.
type genFlow struct {
	t     *pcapgo.Writer
	ts    time.Time
	cSeq  uint32
	sSeq  uint32
	cPort uint16
	sPort uint16
	cIP   [4]byte
	sIP   [4]byte
	cMAC  [6]byte
	sMAC  [6]byte
}

func writeFixturePCAP(path string, base time.Time, build func(*genFlow)) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	build(newGenFlow(w, base))
	return nil
}

// newGenFlow builds the deterministic TEST-NET flow parameters.
func newGenFlow(w *pcapgo.Writer, base time.Time) *genFlow {
	return &genFlow{
		t:     w,
		ts:    base,
		cSeq:  1_000_000,
		sSeq:  7_000_000,
		cPort: 51_000,
		sPort: 8_443,
		cIP:   [4]byte{192, 0, 2, 10}, // TEST-NET-1 client
		sIP:   [4]byte{192, 0, 2, 200},
		cMAC:  [6]byte{0x02, 0, 0, 0, 0, 0x0a},
		sMAC:  [6]byte{0x02, 0, 0, 0, 0, 0x0b},
	}
}

// handshakeUpToCH drives SYN, SYN-ACK, ACK and the ClientHello.
func (g *genFlow) handshakeUpToCH() {
	g.clientSend(flagSYN, nil)
	g.serverSend(flagSYN|flagACK, nil)
	g.clientSend(flagACK, nil)
	hello, err := generator.BuildClientHello("fixture.example", [32]byte{7})
	if err != nil {
		panic(err) // fixed inputs cannot fail
	}
	g.clientSend(flagPSH|flagACK, hello)
}

// serverTLS emits one handshake record from the server side.
func (g *genFlow) serverTLS(hsBody []byte) {
	g.serverRecord(tlsparse.TypeHandshake, hsBody)
}

// serverRecord emits one TLS record (any content type) from the server.
func (g *genFlow) serverRecord(typ byte, payload []byte) {
	g.serverSend(flagPSH|flagACK, tlsRecord(typ, payload))
}

// clientRecord emits one TLS record (any content type) from the client.
func (g *genFlow) clientRecord(typ byte, payload []byte) {
	g.clientSend(flagPSH|flagACK, tlsRecord(typ, payload))
}

// serverTLSSegment emits raw bytes (a partial record) from the server
// after an optional injected gap.
func (g *genFlow) serverTLSSegment(chunk []byte, gap time.Duration) {
	if gap > 0 {
		g.ts = g.ts.Add(gap)
	}
	g.serverSend(flagPSH|flagACK, chunk)
}

func (g *genFlow) serverRST() { g.serverSend(flagRST|flagACK, nil) }
func (g *genFlow) clientRST() { g.clientSend(flagRST|flagACK, nil) }

func (g *genFlow) closeFlow() {
	g.clientSend(flagFIN|flagACK, nil)
	g.serverSend(flagFIN|flagACK, nil)
	g.clientSend(flagACK, nil)
}

func (g *genFlow) clientSend(flags uint8, payload []byte) {
	g.emit(true, flags, payload)
	if flags&flagSYN != 0 {
		g.cSeq++
	}
	g.cSeq += uint32(len(payload))
	if flags&flagFIN != 0 {
		g.cSeq++
	}
}

func (g *genFlow) serverSend(flags uint8, payload []byte) {
	g.emit(false, flags, payload)
	if flags&flagSYN != 0 {
		g.sSeq++
	}
	g.sSeq += uint32(len(payload))
	if flags&flagFIN != 0 {
		g.sSeq++
	}
}

const (
	flagFIN = 0x01
	flagPSH = 0x08
)

// emit builds and writes one Ethernet/IPv4/TCP frame; every packet
// advances the timeline by 1 ms unless a gap was injected before.
func (g *genFlow) emit(fromClient bool, flags uint8, payload []byte) {
	var (
		srcMAC, dstMAC [6]byte
		srcIP, dstIP   [4]byte
		srcPort        uint16
		seq, ack       uint32
		dstPort        uint16
	)
	if fromClient {
		srcMAC, dstMAC = g.cMAC, g.sMAC
		srcIP, dstIP = g.cIP, g.sIP
		srcPort, dstPort = g.cPort, g.sPort
		seq, ack = g.cSeq, g.sSeq
	} else {
		srcMAC, dstMAC = g.sMAC, g.cMAC
		srcIP, dstIP = g.sIP, g.cIP
		srcPort, dstPort = g.sPort, g.cPort
		seq, ack = g.sSeq, g.cSeq
	}

	tcpLen := 20 + len(payload)
	tcp := make([]byte, tcpLen)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset, 20 bytes
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64_000) // window
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP, dstIP, tcp))

	ip := make([]byte, 20)
	ip[0] = 4<<4 | 5 // version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+tcpLen))
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip))

	frame := make([]byte, 0, 14+20+tcpLen)
	frame = append(frame, dstMAC[:]...)
	frame = append(frame, srcMAC[:]...)
	frame = append(frame, 0x08, 0x00) // IPv4
	frame = append(frame, ip...)
	frame = append(frame, tcp...)

	if err := g.t.WritePacket(gopacket.CaptureInfo{
		Timestamp:     g.ts,
		CaptureLength: len(frame),
		Length:        len(frame),
	}, frame); err != nil {
		panic(err)
	}
	g.ts = g.ts.Add(time.Millisecond)
}

func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 | uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP [4]byte, tcp []byte) uint16 {
	var sum uint32
	pseudo := append(append([]byte{}, srcIP[:]...), dstIP[:]...)
	pseudo = append(pseudo, 0, 6)
	pseudo = append(pseudo, byte(len(tcp)>>8), byte(len(tcp)))
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(pseudo[i])<<8 | uint32(pseudo[i+1])
	}
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// --- TLS record builders --------------------------------------------------

func tlsRecord(typ byte, payload []byte) []byte {
	rec := []byte{typ, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}
	return append(rec, payload...)
}

func handshakeMsg(typ byte, body []byte) []byte {
	hs := []byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hs, body...)
}

func serverHelloBody(cipher uint16) []byte {
	body := []byte{0x03, 0x03}               // version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session id length 0
	body = append(body, byte(cipher>>8), byte(cipher))
	body = append(body, 0x00) // compression null
	return handshakeMsg(0x02, body)
}

func serverCertificateBody() []byte {
	leaf := make([]byte, 64) // dummy DER; the classifier ignores certs
	certs := []byte{byte(len(leaf) >> 16), byte(len(leaf) >> 8), byte(len(leaf))}
	certs = append(certs, leaf...)
	body := []byte{byte(len(certs) >> 16), byte(len(certs) >> 8), byte(len(certs))}
	body = append(body, certs...)
	return handshakeMsg(0x0b, body)
}

func serverHelloDoneBody() []byte { return handshakeMsg(0x0e, nil) }

// alertHandshakeFailureBody returns the alert body (level + description).
func alertHandshakeFailureBody() []byte {
	return []byte{tlsparse.AlertLevelFatal, tlsparse.AlertHandshakeFailure}
}

// clientGetBody returns raw application data (the HTTP request).
func clientGetBody() []byte {
	return []byte("GET / HTTP/1.1\r\nHost: fixture.example\r\n\r\n")
}

// serverHTTPBody returns raw application data (the HTTP response).
func serverHTTPBody() []byte {
	const body = "OK\n"
	return []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body))
}
