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

func TestPreparedTLSDelaysClientHelloAfterConnect(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	prepared, err := PrepareTLS(ctx, "control.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan TLSObservation, 1)
	go func() { result <- prepared.StartAfter(ctx, listener.Addr().String(), 250*time.Millisecond) }()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(75 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(prepared.ClientHello()))
	if n, err := conn.Read(buf); n != 0 || err == nil {
		t.Fatalf("ClientHello arrived before the delay: %d bytes, %v", n, err)
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("waiting for ClientHello: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, prepared.ClientHello()) {
		t.Fatal("sent ClientHello differs from plan")
	}
	_ = conn.Close()
	if got := <-result; got.Stage != "tls" {
		t.Fatalf("TLS result = %+v", got)
	}
}

func TestPreparedTLSCancelsBeforeClientHello(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prepared, err := PrepareTLS(ctx, "control.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan TLSObservation, 1)
	go func() { result <- prepared.StartAfter(ctx, listener.Addr().String(), 2*time.Second) }()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if got := <-result; (got.Stage != "tcp" && got.Stage != "tls") || got.Error == "" {
		t.Fatalf("cancel result = %+v", got)
	}
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("unexpected bytes after cancellation: %d, %v", n, err)
	}
}
