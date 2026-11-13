package runner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPrepareSNIComparisonWritesOfflineSchedule(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := runConfigYAML("192.0.2.10", 443, 2, 100, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if err := PrepareSNIComparison(cfg, configPath); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "sni-schedule.yaml"))
	if err != nil {
		t.Fatalf("read schedule: %v", err)
	}
	var got struct {
		Endpoint Endpoint `yaml:"endpoint"`
		Names    []string `yaml:"sni_schedule"`
	}
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode schedule: %v", err)
	}
	if got.Endpoint.IP != "192.0.2.10" || got.Endpoint.Port != 443 {
		t.Errorf("endpoint = %+v", got.Endpoint)
	}
	want := "control.example,web.telegram.org,web.telegram.org,control.example"
	if strings.Join(got.Names, ",") != want {
		t.Errorf("schedule = %v, want %s", got.Names, want)
	}
	if err := PrepareSNIComparison(cfg, configPath); err != nil {
		t.Fatalf("repeat identical preparation: %v", err)
	}
	cfg.PairedSNI = "different.example"
	if err := PrepareSNIComparison(cfg, configPath); err == nil {
		t.Fatal("preparation must not overwrite an existing different schedule")
	}
	after, err := os.ReadFile(filepath.Join(dir, "sni-schedule.yaml"))
	if err != nil || string(after) != string(data) {
		t.Fatal("existing schedule was changed")
	}
}

func TestRunRefusesSNIComparisonWithoutCapture(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := runConfigYAML("192.0.2.10", 443, 1, 100, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	err = Run(context.Background(), cfg, Options{ConfigPath: configPath})
	if err == nil || !strings.Contains(err.Error(), "capture interface") {
		t.Fatalf("run error = %v, want refusal before sending", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "runner.log")); !os.IsNotExist(err) {
		t.Fatalf("runner log stat = %v, want no execution", err)
	}
}

func TestPairedConfigRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	content := runConfigYAML("192.0.2.10", 443, 1, 100, dir) + "paired_sni: web.telegram.org\n"
	configPath := writeRunConfig(t, dir, content)
	valid, err := Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"invalid treatment", func(c *Config) { c.PairedSNI = "bad/name" }},
		{"invalid control", func(c *Config) { c.SNI = "bad/name" }},
		{"negative gap", func(c *Config) { c.Schedule.InterTrialGapMS = -1 }},
		{"unsupported state reset", func(c *Config) { c.Schedule.StateReset = "flush" }},
		{"IPv6 endpoint", func(c *Config) { c.Endpoint.IP = "2001:db8::1" }},
		{"timeout exceeds budget", func(c *Config) { c.PairedTimeoutMS = 61000 }},
		{"invalid SYN retry limit", func(c *Config) { n := 0; c.Budget.MaxSYNRetransmissions = &n }},
		{"ignored preflight", func(c *Config) {
			c.Preflight.Enabled = true
			c.Preflight.Host = "example.com"
			c.Preflight.IndependentResolver = "192.0.2.53:53"
		}},
		{"ignored lab profile", func(c *Config) { c.Lab.Enabled = true; c.Lab.ConfigID = "test" }},
		{"target packet budget", func(c *Config) { c.Endpoint.Role = RoleTarget; c.Budget.MaxPackets = 101 }},
		{"target byte budget", func(c *Config) { c.Endpoint.Role = RoleTarget; c.Budget.MaxBytes = 102401 }},
		{"target rate budget", func(c *Config) { c.Endpoint.Role = RoleTarget; c.Budget.MaxRatePPS = 11 }},
		{"target duration budget", func(c *Config) { c.Endpoint.Role = RoleTarget; c.Budget.MaxDurationS = 61 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.modify(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid paired config was accepted")
			}
		})
	}
}
