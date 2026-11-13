package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/semrosin/DPIsect/internal/tlsparse"
)

// PreparedTLS holds a TLS handshake whose first record is available before dial.
// Each instance is single-use and must be closed after use.
type PreparedTLS struct {
	conn    *gatedConn
	hello   []byte
	result  chan TLSObservation
	done    chan struct{}
	cancel  context.CancelFunc
	mu      sync.Mutex
	started bool
}

// PrepareTLS constructs a fresh TLS ClientHello without opening a socket.
func PrepareTLS(ctx context.Context, sni string, roots *x509.CertPool) (*PreparedTLS, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	gate := newGatedConn()
	client := tls.Client(gate, &tls.Config{ServerName: sni, RootCAs: roots})
	p := &PreparedTLS{conn: gate, result: make(chan TLSObservation, 1), done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(p.done)
		defer func() {
			if v := recover(); v != nil {
				p.result <- TLSObservation{Stage: "tls", Error: fmt.Sprintf("TLS handshake panic: %v", v)}
			}
		}()
		if err := client.HandshakeContext(ctx); err != nil {
			p.result <- TLSObservation{Stage: "tls", Error: err.Error()}
			return
		}
		state := client.ConnectionState()
		p.result <- TLSObservation{Stage: "complete", Version: state.Version, CipherSuite: state.CipherSuite}
	}()
	select {
	case hello := <-gate.first:
		if err := ctx.Err(); err != nil {
			p.Close()
			return nil, err
		}
		reader := bytes.NewReader(hello)
		record, err := tlsparse.ReadRecord(reader)
		if err == nil && reader.Len() == 0 && record.Type == tlsparse.TypeHandshake {
			_, err = tlsparse.ParseClientHello(record.Payload)
		} else if err == nil {
			err = fmt.Errorf("first write is not one handshake record")
		}
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("prepare TLS ClientHello: %w", err)
		}
		p.hello = hello
		return p, nil
	case result := <-p.result:
		p.Close()
		return nil, fmt.Errorf("prepare TLS ClientHello: %s", result.Error)
	case <-ctx.Done():
		p.Close()
		return nil, ctx.Err()
	}
}

// ClientHello returns a copy of the exact first record to persist before dial.
func (p *PreparedTLS) ClientHello() []byte { return bytes.Clone(p.hello) }

// Start dials one endpoint, releases the saved record and waits for TLS.
func (p *PreparedTLS) Start(ctx context.Context, addr string) TLSObservation {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return TLSObservation{Stage: "tcp", Error: "prepared TLS session already started"}
	}
	p.started = true
	p.mu.Unlock()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSObservation{Stage: "tcp", Error: err.Error()}
	}
	if err := p.conn.attach(conn); err != nil {
		_ = conn.Close()
		return TLSObservation{Stage: "tcp", Error: err.Error()}
	}
	select {
	case result := <-p.result:
		return result
	case <-ctx.Done():
		_ = p.conn.Close()
		return TLSObservation{Stage: "tls", Error: ctx.Err().Error()}
	}
}

// Close stops the handshake, closes its connection and waits for its goroutine.
func (p *PreparedTLS) Close() {
	p.cancel()
	_ = p.conn.Close()
	<-p.done
}

type gatedConn struct {
	first  chan []byte
	ready  chan struct{}
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	conn   net.Conn
	closed bool
}

func newGatedConn() *gatedConn {
	return &gatedConn{first: make(chan []byte, 1), ready: make(chan struct{}), done: make(chan struct{})}
}

func (g *gatedConn) attach(conn net.Conn) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.conn != nil {
		return net.ErrClosed
	}
	g.conn = conn
	close(g.ready)
	return nil
}

func (g *gatedConn) active() (net.Conn, error) {
	select {
	case <-g.ready:
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.closed {
			return nil, net.ErrClosed
		}
		return g.conn, nil
	case <-g.done:
		return nil, net.ErrClosed
	}
}

func (g *gatedConn) Write(b []byte) (int, error) {
	g.once.Do(func() { g.first <- bytes.Clone(b) })
	conn, err := g.active()
	if err != nil {
		return 0, err
	}
	return conn.Write(b)
}

func (g *gatedConn) Read(b []byte) (int, error) {
	conn, err := g.active()
	if err != nil {
		return 0, err
	}
	return conn.Read(b)
}

func (g *gatedConn) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	close(g.done)
	conn := g.conn
	g.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (g *gatedConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (g *gatedConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (g *gatedConn) SetDeadline(t time.Time) error {
	conn, err := g.active()
	if err != nil {
		return err
	}
	return conn.SetDeadline(t)
}
func (g *gatedConn) SetReadDeadline(t time.Time) error {
	conn, err := g.active()
	if err != nil {
		return err
	}
	return conn.SetReadDeadline(t)
}
func (g *gatedConn) SetWriteDeadline(t time.Time) error {
	conn, err := g.active()
	if err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}
