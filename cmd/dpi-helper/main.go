// Command dpi-helper is the controlled server side of an experiment:
// it accepts probe connections, journals server events and writes the
// server PCAP, in an accepting or rejecting profile
// (docs/ARCHITECTURE.md §1).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/semrosin/DPIsect/internal/capture"
	"github.com/semrosin/DPIsect/internal/helper"
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
	logPath := fs.String("log", "",
		"helper_log path (JSON lines, outside git; empty: stderr)")
	captureIface := fs.String("capture-iface", "",
		"interface for the server PCAP (requires CAP_NET_RAW; empty: no capture)")
	capturePath := fs.String("capture-pcap", "",
		"server PCAP path (outside git; required with -capture-iface)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("dpi-helper %s (%s)\n", version, commit)
		return nil
	}
	if _, err := helper.ParseProfile(*profile); err != nil {
		return err
	}
	if (*captureIface == "") != (*capturePath == "") {
		return fmt.Errorf("-capture-iface and -capture-pcap must be set together")
	}

	logFile, logger, err := newLogger(*logPath)
	if err != nil {
		return err
	}
	if logFile != nil {
		defer func() { _ = logFile.Close() }()
	}
	slog.SetDefault(logger)

	srv, err := helper.New(helper.Config{
		Addr:    *addr,
		Profile: helper.Profile(*profile),
		Logger:  logger,
	})
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var live *capture.Live
	if *captureIface != "" {
		live = capture.NewLive(capture.PointServer, *captureIface, *capturePath)
		if err := live.Start(ctx); err != nil {
			return err
		}
	}

	logger.Info("start", "event", "start",
		"binary", "dpi-helper", "version", version, "commit", commit,
		"addr", srv.Addr().String(), "profile", *profile)

	serveErr := srv.Serve(ctx)

	if live != nil {
		if err := live.Stop(context.Background()); err != nil && serveErr == nil {
			serveErr = err
		}
	}
	return serveErr
}

// newLogger builds a JSON slog logger: to a0600 file outside git
// (docs/SAFETY.md §5), or to stderr when no path is given.
func newLogger(path string) (*os.File, *slog.Logger, error) {
	if path == "" {
		return nil, slog.New(slog.NewJSONHandler(os.Stderr, nil)), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open helper_log: %w", err)
	}
	return f, slog.New(slog.NewJSONHandler(f, nil)), nil
}
