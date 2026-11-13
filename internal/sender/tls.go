package sender

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
)

// ConnectionObservation reports the furthest stage reached by a TCP or TLS probe.
// For a TCP-only probe, complete means TCP connected; TLS was not attempted.
type ConnectionObservation struct {
	Stage       string `json:"stage"`
	Error       string `json:"error,omitempty"`
	Version     uint16 `json:"tls_version,omitempty"`
	CipherSuite uint16 `json:"cipher_suite,omitempty"`
}

// TLSObservation preserves the existing TLS sender interface.
type TLSObservation = ConnectionObservation

// TLSProbe connects to addr and verifies the server certificate against sni.
// A nil roots uses the system trust store. The caller controls the deadline.
func TLSProbe(ctx context.Context, addr, sni string, roots *x509.CertPool) TLSObservation {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSObservation{Stage: "tcp", Error: err.Error()}
	}
	defer func() { _ = conn.Close() }()

	tlsConn := tls.Client(conn, &tls.Config{ServerName: sni, RootCAs: roots})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return TLSObservation{Stage: "tls", Error: err.Error()}
	}
	state := tlsConn.ConnectionState()
	return TLSObservation{Stage: "complete", Version: state.Version, CipherSuite: state.CipherSuite}
}
