package runner

import (
	"context"
	"strings"
	"testing"
)

func TestRunRefusesRawWithoutConfirmation(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeConfig(t, `question_id: D01
experiment_id: d01-test-2026-11
mode: raw-experiment
endpoint:
  role: helper
  ip: 192.0.2.10
  port: 443
schedule:
  repetitions: 1
  seed: 1
capture:
  client: artifacts/x/client.pcap
  server: artifacts/x/server.pcap
runner_log: artifacts/x/runner.log
classification_rule: probe delivered
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	err = Run(context.Background(), cfg, Options{AllowRaw: false})
	if err == nil {
		t.Fatal("Run without AllowRaw: want error, got nil")
	}
	if !strings.Contains(err.Error(), "-allow-raw") {
		t.Errorf("Run error %q must be the raw-confirmation refusal", err)
	}
}
