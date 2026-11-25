package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"slices"
	"testing"
)

func TestPreviewProfiles(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(context.Background(), []string{"Example.INVALID."}, &output, &output); err != nil {
		t.Fatal(err)
	}
	var plan report
	if err := json.Unmarshal(output.Bytes(), &plan); err != nil {
		t.Fatal(err)
	}
	if plan.Host != "example.invalid" || plan.Port != "443" || len(plan.Trials) != 0 || len(plan.DNS) != 0 {
		t.Fatalf("unexpected preview: %+v", plan)
	}
	want := []struct {
		name   string
		family string
		alpn   []string
		max    uint16
	}{
		{"baseline-ipv4", "ip4", []string{"h2", "http/1.1"}, tls.VersionTLS13},
		{"http1-alpn", "ip4", []string{"http/1.1"}, tls.VersionTLS13},
		{"tls12", "ip4", []string{"h2", "http/1.1"}, tls.VersionTLS12},
		{"baseline-ipv6", "ip6", []string{"h2", "http/1.1"}, tls.VersionTLS13},
	}
	if len(plan.Profiles) != len(want) {
		t.Fatalf("got %d profiles, want %d", len(plan.Profiles), len(want))
	}
	for i, expected := range want {
		p := plan.Profiles[i]
		config := p.tlsConfig(plan.Host)
		if p.Name != expected.name || p.Family != expected.family ||
			config.ServerName != plan.Host || config.MinVersion != tls.VersionTLS12 ||
			config.MaxVersion != expected.max || !slices.Equal(config.NextProtos, expected.alpn) ||
			config.InsecureSkipVerify {
			t.Errorf("unexpected profile: %+v", p)
		}
	}
}

func TestRejectMismatchedConfirmation(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := run(context.Background(), []string{"-confirm-target", "other.invalid", "example.invalid"}, &output, &output); err == nil {
		t.Fatal("expected mismatched confirmation to fail")
	}
	if output.Len() != 0 {
		t.Fatalf("confirmation failure produced a report: %s", &output)
	}
}
