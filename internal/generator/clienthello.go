package generator

import (
	"encoding/binary"
	"fmt"
)

// maxSNIHostLen is the DNS name limit for the SNI extension (RFC 6066).
const maxSNIHostLen = 253

// BuildClientHello returns one well-formed ClientHello record with
// an SNI extension, advertised TLS 1.3/1.2 versions and cipher suites
// that cover both ECDSA and RSA server certificates. rnd fills the
// 32-byte random field; callers seed it for reproducibility (H07).
// The function never returns malformed output — that is the contract
// of the valid path.
func BuildClientHello(sni string, rnd [32]byte) ([]byte, error) {
	if err := validateSNI(sni); err != nil {
		return nil, err
	}

	host := []byte(sni)

	// server_name extension data: list length, name type, name length, name.
	sniData := make([]byte, 0, 5+len(host))
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(3+len(host)))
	sniData = append(sniData, 0x00) // host_name
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(len(host)))
	sniData = append(sniData, host...)

	var exts []byte
	exts = appendExt(exts, 0x0000, sniData)
	// supported_groups: x25519, secp256r1, secp384r1.
	exts = appendExt(exts, 0x000a, []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})
	// ec_point_formats: uncompressed.
	exts = appendExt(exts, 0x000b, []byte{0x01, 0x00})
	// signature_algorithms: ECDSA and RSA (PKCS1 and PSS) with
	// SHA-256/384/512.
	exts = appendExt(exts, 0x000d, []byte{
		0x00, 0x10,
		0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
		0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
		0x08, 0x06, 0x06, 0x01,
	})
	// supported_versions: TLS 1.3, TLS 1.2.
	exts = appendExt(exts, 0x002b, []byte{0x04, 0x03, 0x04, 0x03, 0x03})

	// Cipher suites: the TLS 1.3 AES-GCM suites, then ECDHE ECDSA
	// and RSA suites for TLS 1.2.
	ciphers := []byte{
		0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
		0xc0, 0x2b, 0xc0, 0x2c, 0xcc, 0xa9,
		0xc0, 0x2f, 0xc0, 0x30, 0xcc, 0xa8,
	}

	body := make([]byte, 0, 2+32+1+2+len(ciphers)+2+2+len(exts))
	body = append(body, 0x03, 0x03) // client_version TLS 1.2 (legacy)
	body = append(body, rnd[:]...)
	body = append(body, 0x00) // session_id length 0
	body = binary.BigEndian.AppendUint16(body, uint16(len(ciphers)))
	body = append(body, ciphers...)
	body = append(body, 0x01, 0x00) // one compression method: null
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01) // handshake type client_hello
	hs = appendU24(hs, len(body))
	hs = append(hs, body...)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01) // handshake, TLS 1.0 record layer
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec, nil
}

// appendExt appends one extension: type, length, data.
func appendExt(exts []byte, typ uint16, data []byte) []byte {
	exts = binary.BigEndian.AppendUint16(exts, typ)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(data)))
	return append(exts, data...)
}

func validateSNI(sni string) error {
	if sni == "" {
		return fmt.Errorf("sni: host is required")
	}
	if len(sni) > maxSNIHostLen {
		return fmt.Errorf("sni: host length %d exceeds %d", len(sni), maxSNIHostLen)
	}
	for i := 0; i < len(sni); i++ {
		c := sni[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return fmt.Errorf("sni: invalid character %q at %d", c, i)
		}
	}
	return nil
}

func appendU24(b []byte, n int) []byte {
	return append(b, byte(n>>16), byte(n>>8), byte(n))
}
