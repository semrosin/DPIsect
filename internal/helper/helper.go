// Package helper is the controlled server side of an experiment: it
// accepts probe connections, journals server events and serves in an
// accepting or rejecting profile (docs/ARCHITECTURE.md §1).
//
// Each journal entry is one slog record: the stable event name (accept,
// client_hello, tls_alert, cert_served, handshake_done, http_request,
// http_response, conn_closed, …) is carried both in msg and in the
// `event` attribute (docs/GO_STYLE.md §7); other attributes carry the
// fields (questions A07, H07).
package helper

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/semrosin/DPIsect/internal/tlsparse"
)

// Profile selects how the helper treats probes after ClientHello
// (docs/RESEARCH_MATRIX.md A07: both profiles must exist so a normal
// server refusal is not mistaken for filtering).
type Profile string

const (
	ProfileAccepting Profile = "accepting"
	ProfileRejecting Profile = "rejecting"
)

// ParseProfile maps a canonical profile name to a Profile.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileAccepting, ProfileRejecting:
		return Profile(s), nil
	default:
		return "", fmt.Errorf("unknown profile %q (want accepting or rejecting)", s)
	}
}

const (
	defaultReadTimeout      = 10 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
	defaultHTTPTimeout      = 5 * time.Second
	maxHTTPRequestBytes     = 8 << 10
)

// serverAlertRecordPayload is a fatal handshake_failure alert record
// the rejecting profile sends instead of a ServerHello.
var serverAlertRecordPayload = []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

// Config configures a helper Server.
type Config struct {
	Addr    string
	Profile Profile
	Logger  *slog.Logger

	// Zero values select the package defaults; explicit values make
	// tests fast and experiments adjustable.
	ReadTimeout      time.Duration
	HandshakeTimeout time.Duration
	HTTPTimeout      time.Duration
}

// Server is one helper instance: one listener, one profile, one
// self-signed serving certificate.
type Server struct {
	cfg         Config
	cert        tls.Certificate
	certSHA256  string
	ln          net.Listener
	connCounter atomic.Uint64
	wg          sync.WaitGroup
}

// New builds a Server with a freshly generated self-signed certificate
// (no key material from disk; docs/GO_STYLE.md §8).
func New(cfg Config) (*Server, error) {
	profile, err := ParseProfile(string(cfg.Profile))
	if err != nil {
		return nil, err
	}
	cfg.Profile = profile
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = defaultReadTimeout
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}

	cert, fp, err := selfSigned()
	if err != nil {
		return nil, fmt.Errorf("generate certificate: %w", err)
	}
	return &Server{cfg: cfg, cert: cert, certSHA256: fp}, nil
}

// Listen opens the TCP listener; Addr reports the bound address.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("helper: listen %s: %w", s.cfg.Addr, err)
	}
	s.ln = ln
	return nil
}

// Addr returns the bound address, or nil before Listen.
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Serve accepts connections until ctx is done, then waits for
// in-flight handlers; every handler is deadline-bounded so the wait
// terminates (docs/GO_STYLE.md §4). Requires a prior Listen.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return fmt.Errorf("helper: Serve requires Listen first")
	}
	s.cfg.Logger.Info("listening",
		"event", "listening",
		"addr", s.ln.Addr().String(),
		"profile", string(s.cfg.Profile),
		"cert_sha256", s.certSHA256,
	)

	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			return fmt.Errorf("helper: accept: %w", err)
		}
		id := s.connCounter.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn, id)
		}()
	}
}

// handle journals one connection: ClientHello parse, profile action,
// TLS handshake, HTTP exchange — as separate events (A07).
func (s *Server) handle(conn net.Conn, id uint64) {
	defer func() {
		_ = conn.Close()
		s.cfg.Logger.Info("conn_closed", "event", "conn_closed", "conn_id", id)
	}()

	log := s.cfg.Logger.With("conn_id", id, "remote", conn.RemoteAddr().String())
	log.Info("accept", "event", "accept")

	_ = conn.SetDeadline(time.Now().Add(s.cfg.ReadTimeout))
	br := bufio.NewReader(conn)
	rec, err := tlsparse.ReadRecord(br)
	if err != nil {
		log.Info("parse_error", "event", "parse_error", "stage", "record", "error", err.Error())
		return
	}
	if rec.Type != tlsparse.TypeHandshake {
		log.Info("parse_error", "event", "parse_error", "stage", "record_type",
			"record_type", fmt.Sprintf("%#x", rec.Type),
			"prefix", hex.EncodeToString(firstBytes(rec.Payload, 16)))
		return
	}
	ch, err := tlsparse.ParseClientHello(rec.Payload)
	if err != nil {
		log.Info("parse_error", "event", "parse_error", "stage", "client_hello",
			"error", err.Error(),
			"prefix", hex.EncodeToString(firstBytes(rec.Payload, 16)))
		return
	}
	log.Info("client_hello", "event", "client_hello",
		"sni", ch.SNI,
		"version", fmt.Sprintf("%04x", ch.Version),
		"cipher_suites", len(ch.CipherSuiteList),
		"record_version", fmt.Sprintf("%04x", rec.Version),
	)

	if s.cfg.Profile == ProfileRejecting {
		if _, err := conn.Write(serverAlertRecordPayload); err != nil {
			log.Info("tls_alert_error", "event", "tls_alert_error", "error", err.Error())
			return
		}
		log.Info("tls_alert", "event", "tls_alert",
			"direction", "server",
			"level", tlsparse.AlertLevelFatal,
			"description", tlsparse.AlertHandshakeFailure,
		)
		return
	}

	_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	// Replay the consumed ClientHello record: tls.Server must read it
	// from the wire itself, so the parsed bytes are fed back first.
	tc := tls.Server(&bufConn{
		Conn:   conn,
		r:      br,
		prefix: recordBytes(rec),
	}, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tc.Handshake(); err != nil {
		log.Info("handshake_failed", "event", "handshake_failed", "error", err.Error())
		return
	}
	state := tc.ConnectionState()
	log.Info("cert_served", "event", "cert_served", "cert_sha256", s.certSHA256)
	log.Info("handshake_done", "event", "handshake_done",
		"version", tlsVersionName(state.Version),
		"cipher_suite", tls.CipherSuiteName(state.CipherSuite),
		"sni", state.ServerName,
	)

	_ = tc.SetDeadline(time.Now().Add(s.cfg.HTTPTimeout))
	req, err := readHTTPRequest(tc)
	if err != nil && len(req) == 0 {
		log.Info("http_request_error", "event", "http_request_error", "error", err.Error())
		return
	}
	log.Info("http_request", "event", "http_request",
		"bytes", len(req), "first_line", firstLine(req))

	const body = "dpisect helper ok\n"
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	if _, err := io.WriteString(tc, resp); err != nil {
		log.Info("http_response_error", "event", "http_response_error", "error", err.Error())
		return
	}
	log.Info("http_response", "event", "http_response",
		"status", 200, "bytes", len(resp))
}

// bufConn serves the replayed prefix first (the consumed ClientHello
// record), then any bytes already buffered, then the connection.
type bufConn struct {
	net.Conn
	r      *bufio.Reader
	prefix []byte
}

func (c *bufConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.r.Read(p)
}

// recordBytes reconstructs the exact wire bytes of a parsed record.
func recordBytes(rec tlsparse.Record) []byte {
	b := make([]byte, 5+len(rec.Payload))
	b[0] = rec.Type
	binary.BigEndian.PutUint16(b[1:3], rec.Version)
	binary.BigEndian.PutUint16(b[3:5], uint16(len(rec.Payload)))
	copy(b[5:], rec.Payload)
	return b
}

// readHTTPRequest reads until the header terminator or the size cap;
// it never grows without bound (docs/GO_STYLE.md §4).
func readHTTPRequest(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 256)
	for len(buf) < maxHTTPRequestBytes {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if bytes.Contains(buf, []byte("\r\n\r\n")) {
				return buf, nil
			}
		}
		if err != nil {
			return buf, err
		}
	}
	return buf, nil
}

func firstBytes(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(bytes.TrimRight(b[:i], "\r"))
	}
	return string(b)
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("%#04x", v)
	}
}

// selfSigned generates an in-memory ECDSA certificate; its SHA-256 is
// journaled for reproducibility (H07).
func selfSigned() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dpisect-helper"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, hex.EncodeToString(sum[:]), nil
}
