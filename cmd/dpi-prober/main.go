// Command dpi-prober runs DPIsect experiments from the client side:
// it loads an experiment config and orchestrates probe generation,
// sending and capture (docs/ARCHITECTURE.md §1).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/semrosin/DPIsect/internal/runner"
)

// Set via -ldflags "-X main.version=… -X main.commit=…"
// (docs/GO_STYLE.md §8); reported for reproducibility (H07).
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "dpi-prober:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("dpi-prober", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to experiment config.yaml")
	allowRaw := fs.Bool("allow-raw", false,
		"explicit confirmation for a raw-experiment run (docs/SAFETY.md §1)")
	operator := fs.String("operator", "",
		"operator name recorded in run.json (H07)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("dpi-prober %s (%s)\n", version, commit)
		return nil
	}
	if *configPath == "" {
		return errors.New("-config is required")
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	slog.Info("start", "binary", "dpi-prober", "version", version, "commit", commit)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := runner.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	return runner.Run(ctx, cfg, runner.Options{
		AllowRaw:    *allowRaw,
		Operator:    *operator,
		ToolVersion: version,
		ToolCommit:  commit,
	})
}
