//go:build linux && privileged

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/semrosin/DPIsect/internal/generator"
)

func TestC01LoopbackVerifiedTLS(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
	}{
		{name: "C01_TLS_control"},
		{name: "C01_TLS_two_segments", offset: 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testVerifiedTLS(t, tc.offset)
		})
	}
}

func testVerifiedTLS(t *testing.T, offset int) {
	t.Helper()
	ring := openLoopbackRing(t)
	defer ring.Close()

	const body = "loopback TLS"
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body) // The client verifies the complete response.
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.Certificate()
	if len(cert.DNSNames) == 0 {
		t.Fatal("test certificate has no DNS names")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	sni := cert.DNSNames[0]

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp4", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	conn := &firstWriteConn{Conn: raw, offset: offset}
	client := tls.Client(conn, &tls.Config{
		ServerName: sni, RootCAs: roots,
		MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519},
	})
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		t.Fatal("expected a verified TLS handshake")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+sni+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Close = true
	if err := req.Write(client); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(io.LimitReader(client, 4096))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(response, []byte("\r\n\r\n"+body)) {
		t.Fatalf("unexpected HTTP response: %q", response)
	}

	source := raw.LocalAddr().(*net.TCPAddr).AddrPort()
	destination := raw.RemoteAddr().(*net.TCPAddr).AddrPort()
	pcap := readLoopbackCapture(t, ring, source, destination, func(tcp *layers.TCP) bool {
		return tcp.FIN
	})
	var expected []int
	if offset > 0 {
		expected = []int{offset}
	}
	packet := generator.PlannedWirePacket{
		Payload: conn.hello, SplitOffsets: expected, TLSRecordEnds: []int{len(conn.hello)},
	}
	if _, err := validateHello(sni, packet); err != nil {
		t.Fatal(err)
	}
	result, err := inspectCapture(bytes.NewReader(pcap.Bytes()), source, destination, conn.hello)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.TCPSplitOffsets, expected) || result.RepeatedRanges != 0 {
		t.Fatalf("observed splits=%v repeats=%d, want %v and no repeats", result.TCPSplitOffsets, result.RepeatedRanges, expected)
	}
	t.Logf("verified TLS version=%x cipher=%x; HTTP response matched", state.Version, state.CipherSuite)
	recordLoopbackTrial(t, pcap, conn.hello, source, destination, result)
}

// firstWriteConn is confined to the loopback test. It splits one write
// at a fixed stream offset independent of the hostname.
type firstWriteConn struct {
	net.Conn
	offset int
	hello  []byte
}

func (c *firstWriteConn) Write(data []byte) (int, error) {
	if c.hello != nil {
		return c.Conn.Write(data)
	}
	c.hello = bytes.Clone(data)
	if c.offset == 0 {
		return c.Conn.Write(data)
	}
	if c.offset >= len(data) {
		return 0, io.ErrShortWrite
	}
	n, err := c.Conn.Write(data[:c.offset])
	if err != nil {
		return n, err
	}
	if n != c.offset {
		return n, io.ErrShortWrite
	}
	m, err := c.Conn.Write(data[c.offset:])
	return n + m, err
}
