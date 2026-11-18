package sender

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// HelloShape controls the first TLS record. Zero coordinates select the
// shortest layout. SNIOffset is the byte offset of the first hostname byte.
type HelloShape struct {
	RecordLength int
	SNIOffset    int
	IgnoredBytes []byte
}

// PrepareShapedTLS constructs a TLS 1.2 session with private-use extensions.
// No socket is opened; returned ClientHello is the one used by the handshake.
func PrepareShapedTLS(ctx context.Context, sni string, roots *x509.CertPool, shape HelloShape) (*PreparedTLS, error) {
	if shape.RecordLength < 0 || shape.RecordLength > 5+(1<<14) || shape.SNIOffset < 0 || len(shape.IgnoredBytes) > 253 {
		return nil, fmt.Errorf("shaped TLS: invalid record length, SNI offset or extension length")
	}
	base, err := prepareShapedOnce(ctx, sni, roots, shape.IgnoredBytes, 0, 0)
	if err != nil {
		return nil, err
	}
	baseHello := base.ClientHello()
	base.Close()
	baseOffset, err := clientHelloSNIOffset(baseHello, sni)
	if err != nil {
		return nil, err
	}
	prefix := 0
	if shape.SNIOffset != 0 {
		prefix = shape.SNIOffset - baseOffset
	}
	if prefix < 0 || prefix > 1<<14 {
		return nil, fmt.Errorf("shaped TLS: SNI offset cannot be achieved")
	}
	padding := 0
	if shape.RecordLength != 0 {
		padding = shape.RecordLength - len(baseHello) - prefix
	}
	if padding < 0 || len(baseHello)+prefix+padding > 5+(1<<14) {
		return nil, fmt.Errorf("shaped TLS: record length cannot be achieved")
	}
	p, err := prepareShapedOnce(ctx, sni, roots, shape.IgnoredBytes, prefix, padding)
	if err != nil {
		return nil, err
	}
	hello := p.ClientHello()
	offset, err := clientHelloSNIOffset(hello, sni)
	if err != nil || (shape.SNIOffset != 0 && offset != shape.SNIOffset) || (shape.RecordLength != 0 && len(hello) != shape.RecordLength) {
		p.Close()
		return nil, fmt.Errorf("shaped TLS: generated ClientHello does not match requested coordinates")
	}
	return p, nil
}

func prepareShapedOnce(ctx context.Context, sni string, roots *x509.CertPool, ignored []byte, prefix, padding int) (*PreparedTLS, error) {
	gate := newGatedConn()
	client := utls.UClient(gate, &utls.Config{ServerName: sni, RootCAs: roots, MinVersion: utls.VersionTLS12, MaxVersion: utls.VersionTLS12}, utls.HelloCustom)
	spec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS12, TLSVersMax: utls.VersionTLS12,
		CipherSuites:       []uint16{utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{0},
		Extensions: []utls.TLSExtension{
			&utls.GenericExtension{Id: 0xffa5, Data: make([]byte, prefix)},
			&utls.SNIExtension{ServerName: sni},
			&utls.SupportedCurvesExtension{Curves: []utls.CurveID{utls.X25519, utls.CurveP256}},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256}},
			&utls.ExtendedMasterSecretExtension{},
			&utls.GenericExtension{Id: 0xffa6, Data: bytes.Clone(ignored)},
			&utls.UtlsPaddingExtension{PaddingLen: padding, WillPad: true},
		},
	}
	if err := client.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("shaped TLS: apply preset: %w", err)
	}
	return prepareTLS(ctx, gate, func(ctx context.Context) TLSObservation {
		if err := client.HandshakeContext(ctx); err != nil {
			return TLSObservation{Stage: "tls", Error: err.Error()}
		}
		state := client.ConnectionState()
		return TLSObservation{Stage: "complete", Version: state.Version, CipherSuite: state.CipherSuite}
	})
}

// clientHelloSNIOffset operates on a record already validated by prepareTLS.
func clientHelloSNIOffset(record []byte, sni string) (int, error) {
	if len(record) < 9+35 {
		return 0, fmt.Errorf("shaped TLS: truncated ClientHello")
	}
	body := record[9:]
	off := 34
	off += 1 + int(body[off])
	if off+2 > len(body) {
		return 0, fmt.Errorf("shaped TLS: truncated ciphers")
	}
	off += 2 + int(binary.BigEndian.Uint16(body[off:]))
	if off >= len(body) {
		return 0, fmt.Errorf("shaped TLS: truncated compression")
	}
	off += 1 + int(body[off])
	if off+2 > len(body) {
		return 0, fmt.Errorf("shaped TLS: truncated extensions")
	}
	end := off + 2 + int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if end > len(body) {
		return 0, fmt.Errorf("shaped TLS: invalid extensions")
	}
	for off+4 <= end {
		typ, length := binary.BigEndian.Uint16(body[off:]), int(binary.BigEndian.Uint16(body[off+2:]))
		if off+4+length > end {
			return 0, fmt.Errorf("shaped TLS: invalid extension")
		}
		if typ == 0 && length >= 5 && bytes.Equal(body[off+9:off+4+length], []byte(sni)) {
			return 9 + off + 9, nil
		}
		off += 4 + length
	}
	return 0, fmt.Errorf("shaped TLS: SNI not found")
}
