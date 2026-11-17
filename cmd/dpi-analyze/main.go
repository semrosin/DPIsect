// Command dpi-analyze classifies a completed run offline: it reads
// saved observations and the classification rule, and produces the
// results block of the report (docs/ARCHITECTURE.md §1, §4).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/semrosin/DPIsect/internal/analyzer"
	"github.com/semrosin/DPIsect/internal/runner"
)

// Set via -ldflags "-X main.version=… -X main.commit=…".
var (
	version = "dev"
	commit  = "unknown"
)

// analysisResult is the stdout document: the fixed classification
// rule next to the measurements, so the operator can paste it into
// the report (docs/EXPERIMENTS.md §7 — the verdict stays theirs).
type analysisResult struct {
	ClassificationRule string                    `json:"classification_rule"`
	ClientPCAP         string                    `json:"client_pcap"`
	Observation        analyzer.CauseObservation `json:"observation"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dpi-analyze:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("dpi-analyze", flag.ContinueOnError)
	configPath := fs.String("config", "",
		"path to the run's config.yaml (classification_rule and observation paths)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("dpi-analyze %s (%s)\n", version, commit)
		return nil
	}
	if *configPath == "" {
		return fmt.Errorf("-config is required")
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	slog.Info("start", "binary", "dpi-analyze", "version", version, "commit", commit)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := runner.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	obs, err := analyzer.ClassifyPCAP(ctx, cfg.Capture.Client)
	if err != nil {
		return fmt.Errorf("classify %s: %w", cfg.Capture.Client, err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(analysisResult{
		ClassificationRule: cfg.ClassificationRule,
		ClientPCAP:         cfg.Capture.Client,
		Observation:        obs,
	})
}
