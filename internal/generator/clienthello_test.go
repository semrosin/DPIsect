package generator

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildClientHelloWellFormed(t *testing.T) {
	t.Parallel()

	rnd := [32]byte{1, 2, 3}
	payload, err := BuildClientHello("example.com", rnd)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if len(payload) < 5 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	if payload[0] != 0x16 || payload[1] != 0x03 || payload[2] != 0x01 {
		t.Errorf("record header = % 02x, want 16 03 01", payload[:3])
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recLen != len(payload)-5 {
		t.Errorf("record length %d, want %d", recLen, len(payload)-5)
	}
	if payload[5] != 0x01 {
		t.Errorf("handshake type = %#x, want 0x01", payload[5])
	}
	hsLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	if hsLen != len(payload)-9 {
		t.Errorf("handshake length %d, want %d", hsLen, len(payload)-9)
	}
	if !bytes.Contains(payload, []byte("example.com")) {
		t.Error("payload does not contain SNI host")
	}
}

func TestBuildClientHelloAdvertisesVersionsAndECDSACiphers(t *testing.T) {
	t.Parallel()

	payload, err := BuildClientHello("example.com", [32]byte{})
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}

	// supported_versions: type 0x002b, len 5, TLS 1.3 and TLS 1.2.
	wantVersions := []byte{0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03}
	if !bytes.Contains(payload, wantVersions) {
		t.Error("payload lacks the supported_versions extension (TLS 1.3 + 1.2)")
	}
	// ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: required for ECDSA
	// server certificates such as the helper's.
	if !bytes.Contains(payload, []byte{0xc0, 0x2b}) {
		t.Error("payload lacks the ECDHE ECDSA cipher 0xc02b")
	}
	// signature_algorithms: type 0x000d, ext length 18 (0x0012),
	// vector length 16 (0x0010) — present for modern servers to
	// choose a signature scheme.
	if !bytes.Contains(payload, []byte{0x00, 0x0d, 0x00, 0x12, 0x00, 0x10}) {
		t.Error("payload lacks the signature_algorithms extension")
	}
}

func TestBuildClientHelloDeterministic(t *testing.T) {
	t.Parallel()

	rnd := [32]byte{9}
	a, err := BuildClientHello("example.com", rnd)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	b, err := BuildClientHello("example.com", rnd)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("same rnd must produce identical payload")
	}
	rnd[0] = 10
	c, err := BuildClientHello("example.com", rnd)
	if err != nil {
		t.Fatalf("BuildClientHello: %v", err)
	}
	if bytes.Equal(a, c) {
		t.Error("different rnd must change payload")
	}
}

func TestBuildClientHelloRejectsBadSNI(t *testing.T) {
	t.Parallel()

	long := make([]byte, maxSNIHostLen+1)
	for i := range long {
		long[i] = 'a'
	}
	tests := []struct {
		name string
		sni  string
	}{
		{name: "empty", sni: ""},
		{name: "too long", sni: string(long)},
		{name: "slash", sni: "a/b.example"},
		{name: "space", sni: "a b.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := BuildClientHello(tt.sni, [32]byte{}); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}
