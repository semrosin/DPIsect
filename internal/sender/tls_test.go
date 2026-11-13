package sender

import (
	"context"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSProbeCompletesVerifiedHandshake(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)

	cert := server.Certificate()
	if len(cert.DNSNames) == 0 {
		t.Fatal("test certificate has no DNS names")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := TLSProbe(ctx, server.Listener.Addr().String(), cert.DNSNames[0], roots)
	if got.Stage != "complete" || got.Error != "" || got.Version == 0 || got.CipherSuite == 0 {
		t.Fatalf("TLS probe = %+v, want a verified session", got)
	}
}

func TestTLSProbeReportsCertificateError(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := TLSProbe(ctx, server.Listener.Addr().String(), "wrong.invalid", roots)
	if got.Stage != "tls" || got.Error == "" {
		t.Fatalf("TLS probe = %+v, want certificate verification failure", got)
	}
}

func TestTLSProbeReportsTCPError(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got := TLSProbe(ctx, addr, "example.test", nil)
	if got.Stage != "tcp" || got.Error == "" {
		t.Fatalf("TLS probe = %+v, want TCP failure", got)
	}
}
