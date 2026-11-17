package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestPrepareSNIWirePlanPersistsExactClientHellosWithoutDial(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := runConfigYAML("192.0.2.10", 443, 2, 100, dir) + "paired_sni: web.telegram.org\npaired_client_hello_delay_ms: 1100\npaired_close_delay_ms: 1100\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	plan, sessions, err := prepareSNIWirePlan(ctx, cfg, configPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, session := range sessions {
			session.Close()
		}
	}()
	if len(plan.Trials) != 4 || len(sessions) != 4 {
		t.Fatalf("trials = %d, sessions = %d; want 4 of each", len(plan.Trials), len(sessions))
	}
	data, err := os.ReadFile(filepath.Join(dir, "plan.yaml"))
	if err != nil {
		t.Fatalf("read wire plan: %v", err)
	}
	var saved sniWirePlan
	if err := yaml.Unmarshal(data, &saved); err != nil {
		t.Fatalf("decode wire plan: %v", err)
	}
	if len(saved.Trials) != len(sessions) {
		t.Fatalf("saved trials = %d, want %d", len(saved.Trials), len(sessions))
	}
	if saved.CloseDelayMS != 1100 {
		t.Fatalf("saved close delay = %d", saved.CloseDelayMS)
	}
	if saved.ClientHelloDelayMS != 1100 {
		t.Fatalf("saved delay = %d", saved.ClientHelloDelayMS)
	}
	for i, trial := range saved.Trials {
		if !bytes.Equal(trial.Packet.Payload, sessions[i].ClientHello()) {
			t.Errorf("trial %d: saved bytes differ from held TLS handshake", i)
		}
	}
	if _, _, err := prepareSNIWirePlan(ctx, cfg, configPath); err == nil {
		t.Fatal("must not replace an existing plan with new random TLS bytes")
	}
}
