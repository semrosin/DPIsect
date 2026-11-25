package sender

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSProbeWithConfigNegotiatesVersionAndALPN(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, network, listenAddr string
		maxVersion                uint16
		alpn                      []string
		wantALPN                  string
	}{
		{"ipv4 baseline", "tcp4", "127.0.0.1:0", tls.VersionTLS13, []string{"h2", "http/1.1"}, "h2"},
		{"ipv4 http1", "tcp4", "127.0.0.1:0", tls.VersionTLS13, []string{"http/1.1"}, "http/1.1"},
		{"ipv4 tls12", "tcp4", "127.0.0.1:0", tls.VersionTLS12, []string{"h2", "http/1.1"}, "h2"},
		{"ipv6 baseline", "tcp6", "[::1]:0", tls.VersionTLS13, []string{"h2", "http/1.1"}, "h2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen(tc.network, tc.listenAddr)
			if err != nil {
				if tc.network == "tcp6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(nil)
			if err := server.Listener.Close(); err != nil {
				_ = listener.Close()
				t.Fatal(err)
			}
			server.Listener = listener
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			t.Cleanup(server.Close)

			cert := server.Certificate()
			roots := x509.NewCertPool()
			roots.AddCert(cert)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got := TLSProbeWithConfig(ctx, listener.Addr().String(), &tls.Config{
				ServerName: cert.DNSNames[0], RootCAs: roots,
				MinVersion: tls.VersionTLS12, MaxVersion: tc.maxVersion, NextProtos: tc.alpn,
			})
			if got.Stage != "complete" || got.Error != "" || got.Version != tc.maxVersion || got.NegotiatedProtocol != tc.wantALPN {
				t.Fatalf("TLS probe = %+v, want completed TLS %#x with ALPN %q", got, tc.maxVersion, tc.wantALPN)
			}
		})
	}
}

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
