package generator

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/semrosin/DPIsect/internal/tlsparse"
)

func TestPaddedClientHelloKeepsLengthAndSNI(t *testing.T) {
	t.Parallel()

	const recordLength = 256
	for _, sni := range []string{"short.example", "longer-name.example"} {
		t.Run(sni, func(t *testing.T) {
			t.Parallel()

			wire, err := buildPaddedClientHello(sni, [32]byte{1}, recordLength)
			if err != nil {
				t.Fatalf("build padded ClientHello: %v", err)
			}
			if len(wire) != recordLength {
				t.Fatalf("record length = %d, want %d", len(wire), recordLength)
			}
			reader := bytes.NewReader(wire)
			record, err := tlsparse.ReadRecord(reader)
			if err != nil {
				t.Fatalf("read TLS record: %v", err)
			}
			if reader.Len() != 0 {
				t.Fatalf("unexpected trailing bytes: %d", reader.Len())
			}
			hello, err := tlsparse.ParseClientHello(record.Payload)
			if err != nil {
				t.Fatalf("parse ClientHello: %v", err)
			}
			if hello.SNI != sni {
				t.Errorf("SNI = %q, want %q", hello.SNI, sni)
			}
			body := record.Payload[4:]
			off := 34
			off += 1 + int(body[off])
			cipherBytes := int(binary.BigEndian.Uint16(body[off:]))
			off += 2 + cipherBytes
			off += 1 + int(body[off])
			extBytes := int(binary.BigEndian.Uint16(body[off:]))
			exts := body[off+2:]
			if len(exts) != extBytes {
				t.Fatalf("extensions have %d bytes, want %d", len(exts), extBytes)
			}
			foundPadding := false
			for len(exts) > 0 {
				typ := binary.BigEndian.Uint16(exts[:2])
				length := int(binary.BigEndian.Uint16(exts[2:4]))
				if typ == 0x0015 {
					foundPadding = true
					if !bytes.Equal(exts[4:4+length], make([]byte, length)) {
						t.Error("padding extension contains nonzero bytes")
					}
				}
				exts = exts[4+length:]
			}
			if !foundPadding {
				t.Error("padding extension is missing")
			}
		})
	}
}

func TestPaddedClientHelloRejectsImpossibleLength(t *testing.T) {
	t.Parallel()

	if _, err := buildPaddedClientHello("example.com", [32]byte{}, 1); err == nil {
		t.Fatal("impossible record length: want error")
	}
	if _, err := buildPaddedClientHello("example.com", [32]byte{}, 5+(1<<14)+1); err == nil {
		t.Fatal("oversized record: want error")
	}
}
