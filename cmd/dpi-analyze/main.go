// Command dpi-analyze classifies a completed run offline: it reads
// saved observations and the classification rule, and produces the
// results block of the report (docs/ARCHITECTURE.md §1, §4).
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
)

// Set via -ldflags "-X main.version=… -X main.commit=…"
// (docs/GO_STYLE.md §8).
var (
	version = "dev"
	commit  = "unknown"
)

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
		return errors.New("-config is required")
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	slog.Info("start", "binary", "dpi-analyze", "version", version, "commit", commit)

	// TODO(someone): load observations, apply the classification
	// rule, emit confirmed/refuted/inconclusive
	// (docs/ARCHITECTURE.md §4; stage 1, substep 8).
	return errors.New("dpi-analyze: not implemented yet (stage 1, docs/DEVELOPMENT.md)")
}
