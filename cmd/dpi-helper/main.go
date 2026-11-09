// Command dpi-helper is the controlled server side of an experiment:
// it accepts probe connections, journals server events and writes the
// server PCAP, in an accepting or rejecting profile
// (docs/ARCHITECTURE.md §1).
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
		fmt.Fprintln(os.Stderr, "dpi-helper:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("dpi-helper", flag.ContinueOnError)
	addr := fs.String("addr", ":8443", "listen address")
	profile := fs.String("profile", "accepting",
		"server profile: accepting | rejecting")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("dpi-helper %s (%s)\n", version, commit)
		return nil
	}
	switch *profile {
	case "accepting", "rejecting":
	default:
		return fmt.Errorf("-profile %q must be accepting or rejecting", *profile)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	slog.Info("start", "binary", "dpi-helper", "version", version, "commit", commit,
		"addr", *addr, "profile", *profile)

	// TODO(someone): accept connections, journal ClientHello/TLS
	// Alert/HTTP events and write the server PCAP
	// (docs/ARCHITECTURE.md §1; stage 1, substep 6).
	return errors.New("dpi-helper: not implemented yet (stage 1, docs/DEVELOPMENT.md)")
}
