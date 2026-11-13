package sender

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/tlsparse"
)

func TestPreparedTLSClientHelloMatchesSentBytes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prepared, err := PrepareTLS(ctx, "control.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	hello := prepared.ClientHello()
	record, err := tlsparse.ReadRecord(bytes.NewReader(hello))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tlsparse.ParseClientHello(record.Payload)
	if err != nil || parsed.SNI != "control.example" {
		t.Fatalf("parsed ClientHello = %+v, error = %v", parsed, err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		wire := make([]byte, len(hello))
		if _, err := io.ReadFull(conn, wire); err != nil {
			received <- nil
			return
		}
		received <- wire
	}()
	got := prepared.Start(ctx, listener.Addr().String())
	if got.Stage != "tls" || got.Error == "" {
		t.Fatalf("expected peer close during TLS, got %+v", got)
	}
	if wire := <-received; !bytes.Equal(wire, hello) {
		t.Fatal("sent bytes differ from the precomputed ClientHello")
	}
}

func TestPreparedTLSCompletesVerifiedHandshake(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prepared, err := PrepareTLS(ctx, cert.DNSNames[0], roots)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	got := prepared.Start(ctx, server.Listener.Addr().String())
	if got.Stage != "complete" || got.Error != "" || got.Version == 0 {
		t.Fatalf("TLS observation = %+v, want verified session", got)
	}
}

func TestPrepareTLSRejectsCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	prepared, err := PrepareTLS(ctx, "control.example", nil)
	if err == nil {
		prepared.Close()
		t.Fatal("cancelled context must not produce a prepared session")
	}
}
