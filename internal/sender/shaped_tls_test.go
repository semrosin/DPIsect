package sender

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/semrosin/DPIsect/internal/tlsparse"
)

func TestB04B07ShapedTLSIsPlannedAndCompletes(t *testing.T) {
	t.Parallel()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	cert := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	sni := cert.DNSNames[0]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base, err := PrepareShapedTLS(ctx, sni, roots, HelloShape{IgnoredBytes: []byte("blocked.example")})
	if err != nil {
		t.Fatal(err)
	}
	baseHello := base.ClientHello()
	base.Close()
	baseOffset := bytes.Index(baseHello, []byte(sni))
	if baseOffset < 0 {
		t.Fatal("SNI not found")
	}
	shape := HelloShape{RecordLength: len(baseHello) + 100, SNIOffset: baseOffset + 40, IgnoredBytes: []byte("blocked.example")}
	prepared, err := PrepareShapedTLS(ctx, sni, roots, shape)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	wire := prepared.ClientHello()
	if len(wire) != shape.RecordLength || bytes.Index(wire, []byte(sni)) != shape.SNIOffset {
		t.Fatalf("size/offset = %d/%d, want %d/%d", len(wire), bytes.Index(wire, []byte(sni)), shape.RecordLength, shape.SNIOffset)
	}
	record, err := tlsparse.ReadRecord(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := tlsparse.ParseClientHello(record.Payload)
	if err != nil || parsed.SNI != sni {
		t.Fatalf("ClientHello = %+v, %v", parsed, err)
	}
	if got := extensionData(t, wire, 0xffa6); !bytes.Equal(got, shape.IgnoredBytes) {
		t.Fatalf("ignored extension = %q", got)
	}
	if got := prepared.Start(ctx, server.Listener.Addr().String()); got.Stage != "complete" || got.Error != "" {
		t.Fatalf("verified TLS = %+v", got)
	}
}

func TestB07ShapedTLSRejectsImpossibleCoordinates(t *testing.T) {
	t.Parallel()
	for _, shape := range []HelloShape{{RecordLength: 1}, {SNIOffset: 1}, {RecordLength: 16390}, {RecordLength: -1}, {SNIOffset: -1}} {
		p, err := PrepareShapedTLS(context.Background(), "example.com", nil, shape)
		if err == nil {
			p.Close()
			t.Fatalf("accepted invalid shape %+v", shape)
		}
	}
}

func TestB04BothExtensionVariantsCompleteTLS(t *testing.T) {
	t.Parallel()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	variants := []struct{ sni, ignored string }{
		{"a.example.com", "b.example.com"},
		{"b.example.com", "a.example.com"},
	}
	for _, v := range variants {
		p, err := PrepareShapedTLS(ctx, v.sni, roots, HelloShape{RecordLength: 250, SNIOffset: 110, IgnoredBytes: []byte(v.ignored)})
		if err != nil {
			t.Fatal(err)
		}
		wire := p.ClientHello()
		if len(wire) != 250 || bytes.Index(wire, []byte(v.sni)) != 110 || !bytes.Equal(extensionData(t, wire, 0xffa6), []byte(v.ignored)) {
			p.Close()
			t.Fatalf("invalid profile for %s", v.sni)
		}
		result := p.Start(ctx, server.Listener.Addr().String())
		p.Close()
		if result.Stage != "complete" || result.Error != "" {
			t.Fatalf("%s: %+v", v.sni, result)
		}
	}
}

func TestB07SizeAndOffsetChangeIndependently(t *testing.T) {
	t.Parallel()
	server := httptest.NewUnstartedServer(nil)
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const sni = "a.example.com"
	shapes := []HelloShape{
		{RecordLength: 250, SNIOffset: 110},
		{RecordLength: 250, SNIOffset: 130},
		{RecordLength: 280, SNIOffset: 110},
	}
	for _, shape := range shapes {
		p, err := PrepareShapedTLS(ctx, sni, roots, shape)
		if err != nil {
			t.Fatal(err)
		}
		wire := p.ClientHello()
		result := p.Start(ctx, server.Listener.Addr().String())
		p.Close()
		if len(wire) != shape.RecordLength || bytes.Index(wire, []byte(sni)) != shape.SNIOffset {
			t.Fatalf("shape %+v produced length %d, offset %d", shape, len(wire), bytes.Index(wire, []byte(sni)))
		}
		if result.Stage != "complete" || result.Error != "" {
			t.Fatalf("shape %+v: TLS result %+v", shape, result)
		}
	}
}

func extensionData(t *testing.T, record []byte, want uint16) []byte {
	t.Helper()
	body := record[9:]
	off := 34
	off += 1 + int(body[off])
	off += 2 + int(binary.BigEndian.Uint16(body[off:]))
	off += 1 + int(body[off])
	n := int(binary.BigEndian.Uint16(body[off:]))
	exts := body[off+2 : off+2+n]
	for len(exts) >= 4 {
		typ, length := binary.BigEndian.Uint16(exts), int(binary.BigEndian.Uint16(exts[2:]))
		if len(exts) < 4+length {
			t.Fatal("invalid extension length")
		}
		if typ == want {
			return bytes.Clone(exts[4 : 4+length])
		}
		exts = exts[4+length:]
	}
	t.Fatalf("extension %04x missing", want)
	return nil
}
