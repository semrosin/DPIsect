package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/semrosin/DPIsect/internal/generator"
)

const validConfig = `question_id: B01
experiment_id: b01-test-2026-11
mode: valid-session
sni: example.test
endpoint:
  role: helper
  ip: 192.0.2.10
  port: 443
schedule:
  repetitions: 1
  seed: 42
capture:
  client: artifacts/b01-test-2026-11/client.pcap
  server: artifacts/b01-test-2026-11/server.pcap
runner_log: artifacts/b01-test-2026-11/runner.log
classification_rule: control succeeds and treatment is blocked
`

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadValidWithBudgetDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := cfg.Budget
	want := DefaultBudget()
	if got.MaxPackets != want.MaxPackets ||
		got.MaxBytes != want.MaxBytes ||
		got.MaxRatePPS != want.MaxRatePPS ||
		got.MaxDurationS != want.MaxDurationS {
		t.Errorf("budget = %+v, want defaults %+v", got, want)
	}
	mode, err := cfg.GeneratorMode()
	if err != nil {
		t.Fatalf("GeneratorMode: %v", err)
	}
	if mode != generator.ValidSession {
		t.Errorf("mode = %v, want valid-session", mode)
	}
}

func TestLoadRejectsInvalidConfigs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "raw experiment against target",
			mutate: func(s string) string {
				s = strings.Replace(s, "mode: valid-session", "mode: raw-experiment", 1)
				return strings.Replace(s, "role: helper", "role: target", 1)
			},
			wantErr: "raw-experiment against target is forbidden",
		},
		{
			name: "missing classification rule",
			mutate: func(s string) string {
				return strings.Replace(s,
					"classification_rule: control succeeds and treatment is blocked\n",
					"", 1)
			},
			wantErr: "classification_rule",
		},
		{
			name: "unknown field",
			mutate: func(s string) string {
				return "bogus_field: 1\n" + s
			},
			wantErr: "bogus_field",
		},
		{
			name: "experiment id without question prefix",
			mutate: func(s string) string {
				return strings.Replace(s,
					"experiment_id: b01-test-2026-11",
					"experiment_id: test-2026-11", 1)
			},
			wantErr: "must start with",
		},
		{
			name: "valid session without sni",
			mutate: func(s string) string {
				return strings.Replace(s, "sni: example.test\n", "", 1)
			},
			wantErr: "sni is required",
		},
		{
			name: "missing repetitions",
			mutate: func(s string) string {
				return strings.Replace(s, "  repetitions: 1\n", "", 1)
			},
			wantErr: "repetitions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(writeConfig(t, tt.mutate(validConfig)))
			if err == nil {
				t.Fatal("Load: want error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadPreflightAndLab(t *testing.T) {
	t.Parallel()

	content := validConfig + `preflight:
  enabled: true
  host: blocked.example
  independent_resolver: 8.8.8.8:53
lab:
  enabled: true
  config_id: netem-loss10-2026-11
  loss_percent: 10.0
  delay_ms: 5
`
	cfg, err := Load(writeConfig(t, content))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Preflight.Enabled || cfg.Preflight.Host != "blocked.example" ||
		cfg.Preflight.IndependentResolver != "8.8.8.8:53" {
		t.Errorf("preflight = %+v, want enabled with host and resolver", cfg.Preflight)
	}
	if !cfg.Lab.Enabled || cfg.Lab.ConfigID != "netem-loss10-2026-11" ||
		cfg.Lab.LossPercent != 10.0 || cfg.Lab.DelayMS != 5 {
		t.Errorf("lab = %+v, want enabled with config_id", cfg.Lab)
	}
}

func TestLoadRejectsInvalidPreflightAndLab(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "preflight enabled without host",
			mutate: func(s string) string {
				return s + "preflight:\n  enabled: true\n  independent_resolver: 8.8.8.8:53\n"
			},
			wantErr: "preflight.host",
		},
		{
			name: "preflight enabled without resolver",
			mutate: func(s string) string {
				return s + "preflight:\n  enabled: true\n  host: blocked.example\n"
			},
			wantErr: "preflight.independent_resolver",
		},
		{
			name: "lab enabled without config id",
			mutate: func(s string) string {
				return s + "lab:\n  enabled: true\n  loss_percent: 10.0\n"
			},
			wantErr: "lab.config_id",
		},
		{
			name: "lab loss out of range",
			mutate: func(s string) string {
				return s + "lab:\n  enabled: false\n  config_id: x\n  loss_percent: 150.0\n"
			},
			wantErr: "loss_percent",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(writeConfig(t, tt.mutate(validConfig)))
			if err == nil {
				t.Fatal("Load: want error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultBudgetMatchesSafetyLimits(t *testing.T) {
	t.Parallel()

	// Starting limits of docs/SAFETY.md §3.
	b := DefaultBudget()
	if b.MaxPackets != 100 {
		t.Errorf("MaxPackets = %d, want 100", b.MaxPackets)
	}
	if b.MaxBytes != 100*1024 {
		t.Errorf("MaxBytes = %d, want %d", b.MaxBytes, 100*1024)
	}
	if b.MaxRatePPS != 10 {
		t.Errorf("MaxRatePPS = %d, want 10", b.MaxRatePPS)
	}
	if b.MaxDurationS != 60 {
		t.Errorf("MaxDurationS = %d, want 60", b.MaxDurationS)
	}
}
