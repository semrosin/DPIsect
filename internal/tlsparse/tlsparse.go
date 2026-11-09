// Package tlsparse reads TLS records and ClientHello messages from
// bytes already on hand. The helper journals them as server events
// (question A07); the analyzer will classify them from captures
// (H01). It only parses bounded structures — no unbounded reads
// (docs/GO_STYLE.md §4).
package tlsparse

import (
	"encoding/binary"
	"fmt"
	"io"
)

// TLS record types used by the project.
const (
	TypeChangeCipherSpec = 0x14
	TypeAlert            = 0x15
	TypeHandshake        = 0x16
	TypeApplicationData  = 0x17
)

// Alert levels and the descriptions the helper uses.
const (
	AlertLevelFatal       = 2
	AlertHandshakeFailure = 40
)

// MaxRecordPayload bounds record length: 2^14 plus expansion
// headroom; anything above is rejected without allocating.
const MaxRecordPayload = 18432

// Record is one TLS record.
type Record struct {
	Type    byte
	Version uint16
	Payload []byte
}

// ReadRecord reads exactly one TLS record from r with a hard size
// bound on the payload.
func ReadRecord(r io.Reader) (Record, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Record{}, fmt.Errorf("read record header: %w", err)
	}
	length := int(hdr[3])<<8 | int(hdr[4])
	if length > MaxRecordPayload {
		return Record{}, fmt.Errorf(
			"record length %d exceeds %d", length, MaxRecordPayload)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Record{}, fmt.Errorf("read record payload: %w", err)
	}
	return Record{
		Type:    hdr[0],
		Version: binary.BigEndian.Uint16(hdr[1:3]),
		Payload: payload,
	}, nil
}

// Alert returns level and description of an alert record payload.
func (r Record) Alert() (level, description byte, err error) {
	if r.Type != TypeAlert {
		return 0, 0, fmt.Errorf("record type %#x is not an alert", r.Type)
	}
	if len(r.Payload) < 2 {
		return 0, 0, fmt.Errorf("alert payload too short: %d", len(r.Payload))
	}
	return r.Payload[0], r.Payload[1], nil
}

// ClientHello is the subset of a ClientHello the project journals and
// classifies: version, SNI and cipher suite count.
type ClientHello struct {
	Version         uint16
	SNI             string
	CipherSuiteList []uint16
}

// ParseClientHello parses the handshake payload of a record that must
// contain a single ClientHello message. Truncated or concatenated
// handshakes are rejected instead of guessed.
func ParseClientHello(payload []byte) (ClientHello, error) {
	if len(payload) < 4 {
		return ClientHello{}, fmt.Errorf("handshake too short: %d", len(payload))
	}
	if payload[0] != 0x01 {
		return ClientHello{}, fmt.Errorf("handshake type %#x, want client_hello", payload[0])
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if hsLen > len(body) {
		return ClientHello{}, fmt.Errorf("handshake length %d exceeds payload %d", hsLen, len(body))
	}
	body = body[:hsLen]

	// client_version(2) + random(32)
	if len(body) < 34 {
		return ClientHello{}, fmt.Errorf("client_hello body too short: %d", len(body))
	}
	out := ClientHello{Version: binary.BigEndian.Uint16(body[0:2])}
	off := 34

	// legacy_session_id
	if off >= len(body) {
		return ClientHello{}, fmt.Errorf("client_hello truncated at session id")
	}
	sidLen := int(body[off])
	off += 1 + sidLen
	if off > len(body) {
		return ClientHello{}, fmt.Errorf("client_hello truncated in session id")
	}

	// cipher_suites
	if off+2 > len(body) {
		return ClientHello{}, fmt.Errorf("client_hello truncated at cipher suites")
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if csLen%2 != 0 || off+csLen > len(body) {
		return ClientHello{}, fmt.Errorf("cipher suites length %d invalid", csLen)
	}
	for i := 0; i < csLen; i += 2 {
		out.CipherSuiteList = append(out.CipherSuiteList,
			binary.BigEndian.Uint16(body[off+i:off+i+2]))
	}
	off += csLen

	// legacy_compression_methods
	if off >= len(body) {
		return ClientHello{}, fmt.Errorf("client_hello truncated at compression")
	}
	compLen := int(body[off])
	off += 1 + compLen
	if off > len(body) {
		return ClientHello{}, fmt.Errorf("client_hello truncated in compression")
	}

	// extensions (optional in TLS 1.0-1.2 ClientHello)
	if off == len(body) {
		return out, nil
	}
	if off+2 > len(body) {
		return ClientHello{}, fmt.Errorf("client_hello truncated at extensions")
	}
	extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extTotal > len(body) {
		return ClientHello{}, fmt.Errorf("extensions length %d exceeds body", extTotal)
	}
	exts := body[off : off+extTotal]
	for len(exts) > 0 {
		if len(exts) < 4 {
			return ClientHello{}, fmt.Errorf("extension header truncated")
		}
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+extLen > len(exts) {
			return ClientHello{}, fmt.Errorf("extension %#x length %d exceeds", extType, extLen)
		}
		if extType == 0x0000 { // server_name
			sni, err := parseServerName(exts[4 : 4+extLen])
			if err != nil {
				return ClientHello{}, fmt.Errorf("server_name: %w", err)
			}
			out.SNI = sni
		}
		exts = exts[4+extLen:]
	}
	return out, nil
}

// parseServerName parses the server_name extension data: list length,
// name type, host_name only.
func parseServerName(b []byte) (string, error) {
	if len(b) < 2 {
		return "", fmt.Errorf("extension data too short: %d", len(b))
	}
	listLen := int(binary.BigEndian.Uint16(b[0:2]))
	list := b[2:]
	if listLen > len(list) {
		return "", fmt.Errorf("list length %d exceeds %d", listLen, len(list))
	}
	list = list[:listLen]
	if len(list) < 3 {
		return "", fmt.Errorf("name entry too short: %d", len(list))
	}
	nameType := list[0]
	nameLen := int(binary.BigEndian.Uint16(list[1:3]))
	if 3+nameLen > len(list) {
		return "", fmt.Errorf("name length %d exceeds entry", nameLen)
	}
	if nameType != 0x00 {
		return "", nil // other name types are ignored
	}
	return string(list[3 : 3+nameLen]), nil
}
