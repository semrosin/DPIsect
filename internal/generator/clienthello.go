package generator

import (
	"encoding/binary"
	"fmt"
)

// maxSNIHostLen is the DNS name limit for the SNI extension (RFC 6066).
const maxSNIHostLen = 253

// BuildClientHello returns one well-formed TLS 1.2 ClientHello record
// containing an SNI extension. rnd fills the 32-byte random field;
// callers seed it for reproducibility (H07). The function never
// returns malformed output — that is the contract of the valid path.
func BuildClientHello(sni string, rnd [32]byte) ([]byte, error) {
	if err := validateSNI(sni); err != nil {
		return nil, err
	}

	host := []byte(sni)

	// server_name extension data: list length, name type, name length, name.
	extDataLen := 2 + 1 + 2 + len(host)
	extLen := 4 + extDataLen // type + length + data
	exts := make([]byte, 0, 2+extLen)
	exts = binary.BigEndian.AppendUint16(exts, uint16(extLen))
	exts = binary.BigEndian.AppendUint16(exts, 0x0000) // server_name
	exts = binary.BigEndian.AppendUint16(exts, uint16(extDataLen))
	exts = binary.BigEndian.AppendUint16(exts, uint16(1+2+len(host)))
	exts = append(exts, 0x00) // host_name
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(host)))
	exts = append(exts, host...)

	// Cipher suites: TLS_AES_128_GCM_SHA256, ECDHE_RSA_AES_128_GCM_SHA256.
	ciphers := []byte{0x13, 0x01, 0xc0, 0x2f}

	body := make([]byte, 0, 2+32+1+2+len(ciphers)+2+2+len(exts))
	body = append(body, 0x03, 0x03) // client_version TLS 1.2
	body = append(body, rnd[:]...)
	body = append(body, 0x00) // session_id length 0
	body = binary.BigEndian.AppendUint16(body, uint16(len(ciphers)))
	body = append(body, ciphers...)
	body = append(body, 0x01, 0x00) // one compression method: null
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
