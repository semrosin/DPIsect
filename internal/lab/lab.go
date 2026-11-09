//go:build linux

// Package lab manages the isolated test stand: link-level impairment
// profiles (drop, reorder, delay, MTU) applied with tc/netem and
// network namespaces (docs/ARCHITECTURE.md §1). It is driven by the
// runner and tests, never by the prober or helper binaries.
package lab

import "context"

// Profile is one impairment configuration for a lab link.
type Profile struct {
	// Name identifies the profile in logs and reports.
	Name string
	// LossPercent is the tc netem loss probability, 0..100.
	LossPercent float64
	// ReorderPercent is the tc netem reorder probability, 0..100.
	ReorderPercent float64
	// DelayMS is the fixed netem delay in milliseconds.
	DelayMS int
	// MTU overrides the link MTU; zero leaves it unchanged.
	MTU int
}

// Controller applies and removes profiles on the stand.
type Controller interface {
	// Apply sets the impairment profile; it must be idempotent.
	Apply(ctx context.Context, p Profile) error
	// Reset removes all impairments from the stand.
	Reset(ctx context.Context) error
}
