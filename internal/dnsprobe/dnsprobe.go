// Package dnsprobe performs preflight availability checks before a
// series: system resolver vs an independent source (G01) and TCP
// reachability (G02). Results go into observations as dns_log
// (docs/ARCHITECTURE.md §1, §4).
package dnsprobe

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned by preflight paths that exist as
// contracts only; stage-1 code lands per docs/DEVELOPMENT.md.
var ErrNotImplemented = errors.New("dnsprobe: not implemented yet (stage 1, docs/DEVELOPMENT.md)")

// Report is one preflight check result.
type Report struct {
	// Host is the name that was resolved.
	Host string `yaml:"host"`
	// SystemAddrs are addresses returned by the system resolver.
	SystemAddrs []string `yaml:"system_addrs"`
	// IndependentAddrs are addresses from the independent source.
	IndependentAddrs []string `yaml:"independent_addrs"`
	// AddrsMatch reports whether both sources agree (G01).
	AddrsMatch bool `yaml:"addrs_match"`
	// TCPReachable reports whether a TCP connect to the endpoint
	// succeeded before the series (G02).
	TCPReachable bool `yaml:"tcp_reachable"`
}

// Checker runs preflight checks for one host and endpoint.
type Checker interface {
	// Check resolves host via both sources and probes TCP
	// reachability of endpoint host:port.
	Check(ctx context.Context, host string, endpointHost string, endpointPort int) (Report, error)
}
