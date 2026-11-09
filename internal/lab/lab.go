//go:build linux

// Package lab manages the isolated test stand: link-level impairment
// profiles (drop, reorder, delay, MTU) applied with tc/netem and
// network namespaces (docs/ARCHITECTURE.md §1). It is driven by the
// runner and tests, never by the prober or helper binaries.
package lab

import (
	"context"
	"errors"
	"fmt"
)

// Profile is one impairment configuration for a lab link.
type Profile struct {
	// Name identifies the profile in logs and reports.
	Name string
	// LossPercent is the tc netem loss probability, 0..100.
	LossPercent float64
	// ReorderPercent is the tc netem reorder probability, 0..100.
	// tc rejects reorder without a non-zero delay, so Validate
	// requires DelayMS > 0 whenever it is set (question H02).
	ReorderPercent float64
	// DelayMS is the fixed netem delay in milliseconds.
	DelayMS int
	// MTU overrides the link MTU; zero leaves it unchanged.
	MTU int
}

// Validate checks the profile against what tc/netem accepts and
// against the safety of the stand.
func (p Profile) Validate() error {
	var errs []error
	if p.LossPercent < 0 || p.LossPercent > 100 {
		errs = append(errs, fmt.Errorf("loss %g out of 0..100", p.LossPercent))
	}
	if p.ReorderPercent < 0 || p.ReorderPercent > 100 {
		errs = append(errs, fmt.Errorf("reorder %g out of 0..100", p.ReorderPercent))
	}
	if p.DelayMS < 0 {
		errs = append(errs, fmt.Errorf("delay %d must not be negative", p.DelayMS))
	}
	if p.MTU < 0 {
		errs = append(errs, fmt.Errorf("mtu %d must not be negative", p.MTU))
	}
	if p.ReorderPercent > 0 && p.DelayMS == 0 {
		errs = append(errs, fmt.Errorf(
			"reorder %g requires a non-zero delay (tc netem)", p.ReorderPercent))
	}
	return errors.Join(errs...)
}

// Controller applies and removes profiles on the stand.
type Controller interface {
	// Apply sets the impairment profile; it must be idempotent.
	Apply(ctx context.Context, p Profile) error
	// Reset removes all impairments from the stand.
	Reset(ctx context.Context) error
}
