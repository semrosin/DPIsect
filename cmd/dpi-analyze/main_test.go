package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPairedCaptureIsNotClassifiedAsSingleFlow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	config := `question_id: B02
experiment_id: b02-pair-2026-11
mode: valid-session
sni: control.example
paired_sni: web.telegram.org
endpoint: {role: target, ip: 192.0.2.10, port: 443}
schedule: {repetitions: 1}
capture: {client: /nonexistent/client.pcap}
runner_log: /nonexistent/runner.log
classification_rule: planned
`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-config", path})
	if err == nil || !strings.Contains(err.Error(), "paired") {
		t.Fatalf("error = %v, want explicit paired capture refusal", err)
	}
}
