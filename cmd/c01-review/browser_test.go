package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/semrosin/DPIsect/internal/generator"
)

func TestC01BrowserCapture(t *testing.T) {
	t.Parallel()
	const sni = "example.test"
	hello, err := generator.BuildClientHello(sni, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	const cut = 3
	capture := makeCapture(t, []testFrame{
		{seq: 100, syn: true},
		{seq: 101, payload: string(hello[:cut])},
		{seq: 101 + cut, payload: string(hello[cut:])},
		{seq: 101 + cut, payload: string(hello[cut:])},
	})
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "C01_PCAP", data: capture},
		{name: "C01_PCAPNG", data: asPCAPNG(t, capture)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "browser.capture")
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := run([]string{"-browser", path, "-sni", sni}, &output); err != nil {
				t.Fatal(err)
			}
			var result browserReport
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Trials) != 1 {
				t.Fatalf("unexpected trials: %s", output.Bytes())
			}
			trial := result.Trials[0]
			nameStart := bytes.Index(hello, []byte(sni))
			if trial.SNIStart == nil || *trial.SNIStart != nameStart ||
				trial.SNIEnd == nil || *trial.SNIEnd != nameStart+len(sni) ||
				!slices.Equal(trial.TCPSplitOffsets, []int{cut}) ||
				trial.RepeatedRanges != 1 || trial.IncomingAfterHello != 0 ||
				trial.FirstRepeat == nil || trial.FirstRepeat.Frame != 4 ||
				trial.PlanSHA256 != "" || trial.CaptureSHA256 != result.CaptureSHA256 {
				t.Fatalf("unexpected review: %s", output.Bytes())
			}
			other, err := reviewBrowser(path, "other.test")
			if err != nil || len(other.Trials) != 0 {
				t.Fatalf("unexpected match for different SNI: %+v, %v", other, err)
			}
		})
	}
}

func asPCAPNG(t *testing.T, capture []byte) []byte {
	t.Helper()
	reader, err := pcapgo.NewReader(bytes.NewReader(capture))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer, err := pcapgo.NewNgWriter(&out, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for {
		frame, info, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WritePacket(info, frame); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
