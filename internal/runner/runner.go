package runner

import (
	"context"
	"errors"
	"fmt"

	"github.com/semrosin/DPIsect/internal/generator"
)

// Options are run-time gates and metadata that must not live in the
// config file.
type Options struct {
	// AllowRaw confirms a raw-experiment run. The flag is the
	// explicit confirmation required by docs/GO_STYLE.md §4; without
	// it Run refuses even a valid raw config.
	AllowRaw bool
	// Operator, ToolVersion and ToolCommit are recorded in run.json
	// (H07; docs/ARCHITECTURE.md §4).
	Operator    string
	ToolVersion string
	ToolCommit  string
}

// Run executes one experiment according to cfg. Safety gates run
// first; the orchestration itself lands per stage 1
// (docs/DEVELOPMENT.md).
func Run(ctx context.Context, cfg Config, opts Options) error {
	mode, err := cfg.GeneratorMode()
	if err != nil {
		return fmt.Errorf("resolve mode: %w", err)
	}
	if mode == generator.RawExperiment && !opts.AllowRaw {
		return errors.New(
			"raw-experiment requires explicit confirmation: pass -allow-raw (docs/SAFETY.md §1)")
	}

	// TODO(semrosin): preflight (dnsprobe), plan.yaml persistence,
	// generator → sender → capture orchestration and run.json write
	// per docs/ARCHITECTURE.md §2 (stage 1, substeps 4-5).
	return fmt.Errorf("orchestrate run: %w", ErrNotImplemented)
}
