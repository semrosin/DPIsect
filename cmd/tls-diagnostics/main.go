// Command tls-diagnostics compares ordinary, certificate-verified HTTPS handshakes.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/semrosin/DPIsect/internal/sender"
)

const attemptTimeout = 4 * time.Second

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type profile struct {
	Name       string   `json:"profile"`
	Family     string   `json:"family"`
	ALPN       []string `json:"offered_alpn"`
	MinVersion string   `json:"min_tls"`
	MaxVersion string   `json:"max_tls"`
}

var profiles = []profile{
	{"baseline-ipv4", "ip4", []string{"h2", "http/1.1"}, "TLS 1.2", "TLS 1.3"},
	{"http1-alpn", "ip4", []string{"http/1.1"}, "TLS 1.2", "TLS 1.3"},
	{"tls12", "ip4", []string{"h2", "http/1.1"}, "TLS 1.2", "TLS 1.2"},
	{"baseline-ipv6", "ip6", []string{"h2", "http/1.1"}, "TLS 1.2", "TLS 1.3"},
}

func (p profile) tlsConfig(host string) *tls.Config {
	maxVersion := uint16(tls.VersionTLS13)
	if p.MaxVersion == "TLS 1.2" {
		maxVersion = tls.VersionTLS12
	}
	return &tls.Config{
		ServerName: host,
		NextProtos: p.ALPN,
		MinVersion: tls.VersionTLS12,
		MaxVersion: maxVersion,
	}
}

type endpoint struct {
	Address string `json:"address,omitempty"`
	Error   string `json:"dns_error,omitempty"`
}

type trial struct {
	profile
	Address     string                        `json:"address,omitempty"`
	Observation *sender.ConnectionObservation `json:"observation,omitempty"`
	Skipped     string                        `json:"skipped,omitempty"`
}

type report struct {
	Host     string              `json:"host"`
	Port     string              `json:"port"`
	Profiles []profile           `json:"profiles,omitempty"`
	DNS      map[string]endpoint `json:"dns,omitempty"`
	Trials   []trial             `json:"trials,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tls-diagnostics:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("tls-diagnostics", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	confirm := flags.String("confirm-target", "", "confirm the hostname and run the displayed plan")
	flags.Usage = func() {
		fmt.Fprintln(diagnostics, "Usage: tls-diagnostics [-confirm-target HOST] HOST")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	host := strings.TrimSuffix(strings.ToLower(flags.Arg(0)), ".")
	if flags.NArg() != 1 || !validHostname(host) {
		return errors.New("specify one DNS hostname")
	}

	result := report{Host: host, Port: "443", Profiles: profiles}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if *confirm == "" {
		return encoder.Encode(result)
	}
	if strings.TrimSuffix(strings.ToLower(*confirm), ".") != host {
		return errors.New("confirmed hostname must match the target hostname")
	}
	result.Profiles = nil
	result.DNS = make(map[string]endpoint, 2)
	for _, family := range []string{"ip4", "ip6"} {
		result.DNS[family] = resolve(ctx, family, host)
	}
	for _, p := range profiles {
		selected := result.DNS[p.Family]
		current := trial{profile: p, Address: selected.Address}
		switch {
		case ctx.Err() != nil:
			current.Skipped = ctx.Err().Error()
		case selected.Address == "":
			current.Skipped = "no resolved address for this family"
		default:
			attempt, cancel := context.WithTimeout(ctx, attemptTimeout)
			observation := sender.TLSProbeWithConfig(attempt, net.JoinHostPort(selected.Address, result.Port), p.tlsConfig(host))
			cancel()
			current.Observation = &observation
		}
		result.Trials = append(result.Trials, current)
	}
	return errors.Join(encoder.Encode(result), ctx.Err())
}

func resolve(ctx context.Context, family, host string) endpoint {
	attempt, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(attempt, family, host+".")
	if err != nil {
		return endpoint{Error: err.Error()}
	}
	for _, addr := range addrs {
		addr = addr.Unmap()
		if (family == "ip4" && addr.Is4()) || (family == "ip6" && addr.Is6()) {
			return endpoint{Address: addr.String()}
		}
	}
	return endpoint{Error: "no addresses for this family"}
}

func validHostname(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}
