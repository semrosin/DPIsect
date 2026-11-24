package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
)

const maxSeriesManifestSize = 64 << 10

type manifestTrial struct {
	Label  string `json:"label"`
	Plan   string `json:"plan"`
	PCAP   string `json:"pcap"`
	Trial  int    `json:"trial"`
	Source string `json:"source"`
}

type seriesTrial struct {
	Label string `json:"label"`
	review
}

type seriesReview struct {
	SameEndpoint       bool          `json:"same_endpoint"`
	SameSNI            bool          `json:"same_sni"`
	SameClientIP       bool          `json:"same_client_ip"`
	SameHelloBytes     bool          `json:"same_client_hello_bytes"`
	SameTLSRecords     bool          `json:"same_tls_record_boundaries"`
	DifferentTCPSplits bool          `json:"different_observed_tcp_split_offsets"`
	Trials             []seriesTrial `json:"trials"`
}

type captureFlow struct {
	hash           string
	client, server netip.AddrPort
}

func reviewSeries(path string) (seriesReview, error) {
	var result seriesReview
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSeriesManifestSize+1))
	if err != nil {
		return result, err
	}
	if len(data) > maxSeriesManifestSize {
		return result, errors.New("series manifest is too large")
	}
	var entries []manifestTrial
	if err := json.Unmarshal(data, &entries); err != nil {
		return result, fmt.Errorf("decode series manifest: %w", err)
	}
	if len(entries) < 2 {
		return result, errors.New("series requires at least two trials")
	}
	result = seriesReview{
		SameEndpoint: true, SameSNI: true, SameClientIP: true,
		SameHelloBytes: true, SameTLSRecords: true,
	}
	labels := make(map[string]bool, len(entries))
	flows := make(map[captureFlow]bool, len(entries))
	directory := filepath.Dir(path)
	for i, entry := range entries {
		if entry.Label == "" || labels[entry.Label] {
			return result, fmt.Errorf("entry %d: expected a unique nonempty label", i+1)
		}
		labels[entry.Label] = true
		trial, err := reviewTrial(resolvePath(directory, entry.Plan), resolvePath(directory, entry.PCAP), entry.Trial, entry.Source)
		if err != nil {
			return result, fmt.Errorf("trial %q: %w", entry.Label, err)
		}
		key := captureFlow{hash: trial.CaptureSHA256, client: trial.Client, server: trial.Server}
		if flows[key] {
			return result, fmt.Errorf("trial %q repeats a flow from the same capture", entry.Label)
		}
		flows[key] = true
		if len(result.Trials) > 0 {
			first := result.Trials[0]
			result.SameEndpoint = result.SameEndpoint && trial.Server == first.Server
			result.SameSNI = result.SameSNI && trial.SNI == first.SNI
			result.SameClientIP = result.SameClientIP && trial.Client.Addr() == first.Client.Addr()
			result.SameHelloBytes = result.SameHelloBytes && trial.HelloSHA256 == first.HelloSHA256
			result.SameTLSRecords = result.SameTLSRecords && slices.Equal(trial.TLSRecordEnds, first.TLSRecordEnds)
			result.DifferentTCPSplits = result.DifferentTCPSplits || !slices.Equal(trial.TCPSplitOffsets, first.TCPSplitOffsets)
		}
		result.Trials = append(result.Trials, seriesTrial{Label: entry.Label, review: trial})
	}
	return result, nil
}

func resolvePath(directory, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(directory, path)
}
