package tlsparse

import (
	"bytes"
	"testing"
)

func clientHelloRecord(sni string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)             // version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher suites
	body = append(body, 0x01, 0x00)             // compression
	host := []byte(sni)
	extDataLen := 2 + 1 + 2 + len(host)
	extLen := 4 + extDataLen
	body = append(body, byte(extLen>>8), byte(extLen)) // ext total
	body = append(body, 0x00, 0x00)                    // server_name
	body = append(body, byte(extDataLen>>8), byte(extDataLen))
	body = append(body, byte((1+2+len(host))>>8), byte(1+2+len(host)))
	body = append(body, 0x00)
	body = append(body, byte(len(host)>>8), byte(len(host)))
	body = append(body, host...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func TestReadRecord(t *testing.T) {
	t.Parallel()

	rec, err := ReadRecord(bytes.NewReader(clientHelloRecord("a.example")))
	if err != nil {
		t.Fatalf("ReadRecord: %v", err)
	}
	if rec.Type != TypeHandshake || rec.Version != 0x0303 {
		t.Errorf("type/version = %#x/%#x, want 16/0303", rec.Type, rec.Version)
	}
	ch, err := ParseClientHello(rec.Payload)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.SNI != "a.example" {
		t.Errorf("SNI = %q, want a.example", ch.SNI)
	}
	if len(ch.CipherSuiteList) != 1 || ch.CipherSuiteList[0] != 0x1301 {
		t.Errorf("cipher suites = %v, want [1301]", ch.CipherSuiteList)
	}
}

func TestReadRecordRejectsOversized(t *testing.T) {
	t.Parallel()

	hdr := []byte{0x16, 0x03, 0x03, 0xff, 0xff} // 65535 > MaxRecordPayload
	if _, err := ReadRecord(bytes.NewReader(hdr)); err == nil {
		t.Fatal("want error for oversized record, got nil")
	}
}

func TestParseClientHelloRejectsGarbage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []byte
	}{
		{name: "too short", in: []byte{0x01, 0x00}},
		{name: "not client hello", in: []byte{0x02, 0x00, 0x00, 0x00}},
		{name: "length exceeds", in: []byte{0x01, 0xff, 0xff, 0xff, 0x03, 0x03}},
		{name: "truncated body", in: []byte{0x01, 0x00, 0x00, 0x20, 0x03, 0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseClientHello(tt.in); err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestRecordAlert(t *testing.T) {
	t.Parallel()

	rec := Record{Type: TypeAlert, Payload: []byte{AlertLevelFatal, AlertHandshakeFailure}}
	level, desc, err := rec.Alert()
	if err != nil {
		t.Fatalf("Alert: %v", err)
	}
	if level != AlertLevelFatal || desc != AlertHandshakeFailure {
		t.Errorf("level/desc = %d/%d, want %d/%d",
			level, desc, AlertLevelFatal, AlertHandshakeFailure)
	}
	if _, _, err := (Record{Type: TypeHandshake}).Alert(); err == nil {
		t.Error("want error for non-alert record")
	}
}
