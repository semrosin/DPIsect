package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/semrosin/DPIsect/internal/generator"
	"github.com/semrosin/DPIsect/internal/sender"
	"github.com/semrosin/DPIsect/internal/tlsparse"
)

func TestA02_Resources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resources.txt")
	if err := os.WriteFile(path, []byte("# batch\nExample.com.\napp.example=alt.example # control\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadResources(path, []string{"EXAMPLE.COM", "other.example"})
	want := []resource{{Host: "example.com"}, {Host: "other.example"}, {Host: "app.example", Control: "alt.example"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("loadResources = %v, %v, want %v", got, err, want)
	}
	for _, arg := range []string{"../../out", "https://example.com", "127.0.0.1", "app.example=app.example", "app.example="} {
		if _, err := loadResources("", []string{arg}); err == nil {
			t.Errorf("accepted invalid argument %q", arg)
		}
	}
}

func TestA02_RootedAliasUsesSameWireSNI(t *testing.T) {
	const host = "site.example"
	for _, spelling := range []string{host, host + "."} {
		session, err := sender.PrepareTLS(context.Background(), spelling, nil)
		if err != nil {
			t.Fatal(err)
		}
		record, err := tlsparse.ReadRecord(bytes.NewReader(session.ClientHello()))
		session.Close()
		if err != nil {
			t.Fatal(err)
		}
		hello, err := tlsparse.ParseClientHello(record.Payload)
		if err != nil || hello.SNI != host {
			t.Fatalf("SNI for %q = %q, %v", spelling, hello.SNI, err)
		}
		cert := x509.Certificate{DNSNames: []string{host}}
		if err := cert.VerifyHostname(spelling); err != nil {
			t.Fatal(err)
		}
	}
}

func TestA02_MatchTrialReassemblesClientHello(t *testing.T) {
	const host = "site.example"
	at := time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC)
	attempt := trial{SNI: host, Started: at, Finished: at.Add(time.Second)}
	client := netip.MustParseAddrPort("192.0.2.1:43210")
	other := netip.MustParseAddrPort("192.0.2.1:43211")
	payload, err := generator.BuildClientHello(host, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	chunk := func(seq uint32, data []byte) *layers.TCP {
		tcp := &layers.TCP{Seq: seq, ACK: true}
		tcp.Payload = data
		return tcp
	}
	frames := []frame{
		{at.Add(-time.Second), other, true, &layers.TCP{SYN: true}},
		{at, client, true, &layers.TCP{SYN: true, Seq: 100}},
		{at, client, true, &layers.TCP{SYN: true, Seq: 100}},
		{at, client, false, &layers.TCP{SYN: true, ACK: true, Seq: 42, Ack: 101}},
		{at, client, true, chunk(111, payload[10:])},
		{at, client, true, chunk(101, payload[:12])},
		{at, other, false, &layers.TCP{RST: true}},
		{attempt.Finished.Add(time.Second), client, false, &layers.TCP{RST: true}},
	}
	wire, note := matchTrial(frames, attempt)
	if note != "" || wire.HelloSNI != host || wire.HelloBytes != len(payload) ||
		wire.SYNs != 2 || !wire.SYNACK || !wire.DataRepeat || wire.Reset || wire.ServerData {
		t.Fatalf("matchTrial = %+v, %q", wire, note)
	}
	frames = append(frames, frame{at, other, true, &layers.TCP{SYN: true}})
	if _, note := matchTrial(frames, attempt); note == "" {
		t.Fatal("expected ambiguous trial when multiple connections start in its time window")
	}
}

func TestB02_DiagnosesRequireComparableWireEvidence(t *testing.T) {
	control := trial{SNI: "ctrl.example", Observation: sender.ConnectionObservation{Stage: "complete"},
		Wire: evidence{HelloSNI: "ctrl.example", HelloBytes: 100, SYNACK: true, ServerData: true}}
	target := trial{SNI: "site.example", Observation: sender.ConnectionObservation{Stage: "tls", Error: "context deadline exceeded"},
		Wire: evidence{HelloSNI: "site.example", HelloBytes: 100, SYNACK: true, ClientData: true}}
	cases := []struct {
		name string
		edit func(*trial)
		want string
	}{
		{"same length", func(*trial) {}, "фильтрация или отказ по SNI"},
		{"different length", func(t *trial) { t.Wire.HelloBytes++ }, "отличались SNI и размер ClientHello"},
		{"TCP timeout", func(t *trial) { t.Wire = evidence{SYNs: 2} }, "SYN-ACK не получен"},
		{"unparsed response", func(t *trial) { t.Wire.ServerData = true }, "на начальном этапе TLS"},
		{"TCP reset", func(t *trial) { t.Wire.Reset = true }, "принудительный сброс TCP"},
		{"TLS alert", func(t *trial) { alert := byte(112); t.Wire.ServerData, t.Wire.Alert = true, &alert }, "Alert"},
		{"certificate", func(t *trial) {
			t.Wire.ServerData, t.Observation.Error = true, "tls: failed to verify certificate: x509: expired"
		}, "сертификат не прошёл проверку"},
		{"missing SYN", func(t *trial) { t.WireNote = "no SYN" }, "пакеты попытки не удалось"},
		{"canceled", func(t *trial) { t.Observation.Error = "context canceled" }, "проверка остановлена"},
		{"success", func(t *trial) { t.Observation.Stage = "complete" }, "TLS доступен"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attempt := target
			tc.edit(&attempt)
			r := report{Host: target.SNI, Control: control.SNI}
			r.Runs = []seriesResult{
				{Profile: profiles[0], Trials: []trial{{Observation: sender.ConnectionObservation{Stage: "complete"}}}},
				{Profile: profiles[1], Trials: []trial{control, attempt}},
			}
			if got := r.diagnosis(); !strings.Contains(got, tc.want) {
				t.Errorf("diagnosis = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestA02_DiagnosesDifferentTLSSettings(t *testing.T) {
	connected := trial{Observation: sender.ConnectionObservation{Stage: "complete"}}
	silent := trial{
		Observation: sender.ConnectionObservation{Stage: "tls", Error: context.DeadlineExceeded.Error()},
		Wire:        evidence{SYNACK: true, ClientData: true, HelloBytes: 100},
	}
	r := report{Runs: []seriesResult{
		{Profile: profiles[0], Trials: []trial{connected}},
		{Profile: profiles[1], Trials: []trial{silent}},
		{Profile: profiles[2], Trials: []trial{connected, connected}},
	}}
	if got := r.diagnosis(); !strings.Contains(got, "чувствительность к моменту отправки ClientHello") {
		t.Fatalf("diagnosis = %q", got)
	}
}
