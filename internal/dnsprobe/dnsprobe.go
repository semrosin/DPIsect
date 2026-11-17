// Package dnsprobe performs preflight availability checks before a
// series: system resolver vs an independent source (G01) and TCP
// reachability (G02). Results go into observations as dns_log
// (docs/ARCHITECTURE.md §1, §4).
package dnsprobe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"
)

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

// New returns the production checker: the OS-configured resolver
// versus the independent DNS server at serverAddr ("ip:port", G01),
// and a plain TCP connect to the endpoint (G02).
func New(serverAddr string) Checker {
	return &checker{
		system: systemAddrs,
		independent: func(ctx context.Context, host string) ([]string, error) {
			return independentAddrs(ctx, serverAddr, host)
		},
		dialTCP: func(ctx context.Context, addr string) bool {
			d := net.Dialer{Timeout: 5 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		},
	}
}

// checker is injectable in tests: the functions replace real network
// calls (docs/GO_STYLE.md §6).
type checker struct {
	system      func(ctx context.Context, host string) ([]string, error)
	independent func(ctx context.Context, host string) ([]string, error)
	dialTCP     func(ctx context.Context, addr string) bool
}

// systemAddrs resolves host through the OS-configured resolver.
func systemAddrs(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("system resolver: %w", err)
	}
	return addrs, nil
}

// independentAddrs resolves host through serverAddr ("ip:port") only,
// bypassing the OS resolver configuration (G01).
func independentAddrs(ctx context.Context, serverAddr, host string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(dctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(dctx, network, serverAddr)
		},
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("independent resolver %s: %w", serverAddr, err)
	}
	return addrs, nil
}

// Check resolves host via both sources, then probes TCP
// reachability of the endpoint. A failing lookup is an error (there
// is no result to record); an unreachable endpoint is data, not an
// error — G02 answers with the bool.
func (c *checker) Check(
	ctx context.Context, host string, endpointHost string, endpointPort int,
) (Report, error) {
	if host == "" {
		return Report{}, fmt.Errorf("preflight host is required")
	}
	if c.independent == nil {
		return Report{}, fmt.Errorf("independent resolver is not configured")
	}
	sys, err := c.system(ctx, host)
	if err != nil {
		return Report{}, err
	}
	indep, err := c.independent(ctx, host)
	if err != nil {
		return Report{}, err
	}
	sort.Strings(sys)
	sort.Strings(indep)

	return Report{
		Host:             host,
		SystemAddrs:      sys,
		IndependentAddrs: indep,
		AddrsMatch:       equalAddrs(sys, indep),
		TCPReachable: c.dialTCP(ctx, net.JoinHostPort(
			endpointHost, strconv.Itoa(endpointPort))),
	}, nil
}

func equalAddrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
