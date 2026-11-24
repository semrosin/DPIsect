// Command batch runs ordinary, observed TLS connection checks for A02/B02.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/semrosin/DPIsect/internal/runner"
	"gopkg.in/yaml.v3"
)

const rule = "Record the last observed DNS/TCP/TLS stage. A same-IP control completing TLS while the target times out or retransmits " +
	"its equal-size ClientHello without a TLS response is a likely SNI-dependent difference; its source remains undetermined. " +
	"TLS alerts, certificate failures and TCP failures are reported at their observed stage. This batch does not assign a formal research verdict."

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type resource struct {
	Host    string `json:"host"`
	Control string `json:"control,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "batch:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("batch", flag.ContinueOnError)
	list := fs.String("file", "", "one HOST or HOST=CONTROL per line, # for comments")
	iface := fs.String("iface", "", "client capture interface")
	operator := fs.String("operator", "", "operator name for the audit log")
	prober := fs.String("prober", "bin/dpi-prober", "path to dpi-prober with CAP_NET_RAW for a live run")
	confirm := fs.Bool("confirm-targets", false, "perform the listed checks after reviewing the target plan")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: experiments/batch/run.sh [options] [HOST[=CONTROL] ...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	targets, err := loadResources(*list, fs.Args())
	if err != nil {
		return err
	}
	if !*confirm {
		for _, target := range targets {
			profile := "two ordinary attempts with the resource name"
			if target.Control != "" {
				profile = "ordinary SNI comparison with " + target.Control + " if DNS returns a common IPv4"
			}
			fmt.Printf("%s:443 — %s\n", target.Host, profile)
		}
		return nil
	}
	if os.Geteuid() == 0 || *iface == "" || strings.TrimSpace(*operator) == "" {
		return errors.New("run as a regular user and specify -iface and -operator")
	}
	if _, err := net.InterfaceByName(*iface); err != nil {
		return fmt.Errorf("capture interface: %w", err)
	}
	bin, err := filepath.Abs(*prober)
	if err != nil {
		return err
	}
	if output, err := exec.CommandContext(ctx, bin, "-version").CombinedOutput(); err != nil {
		return fmt.Errorf("check prober: %w %s", err, strings.TrimSpace(string(output)))
	}
	const base = "artifacts/batch-diagnostics"
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	root, err := os.MkdirTemp(base, "batch-")
	if err != nil {
		return err
	}
	audit := struct {
		Operator string     `json:"operator"`
		UTC      time.Time  `json:"confirmed_utc"`
		Targets  []resource `json:"targets"`
	}{*operator, time.Now().UTC(), targets}
	if err := writeJSON(filepath.Join(root, "confirmation.json"), audit); err != nil {
		return err
	}
	fmt.Println(root)
	var failed []error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		fmt.Println(target.Host)
		if err := checkResource(ctx, root, bin, *iface, *operator, target); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", target.Host, err))
		}
	}
	return errors.Join(ctx.Err(), errors.Join(failed...))
}

func loadResources(path string, args []string) ([]resource, error) {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line, _, _ := strings.Cut(scanner.Text(), "#")
			if line = strings.TrimSpace(line); line != "" {
				args = append(args, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	var targets []resource
	seen := make(map[string]string)
	for _, arg := range args {
		name, control, paired := strings.Cut(strings.ToLower(arg), "=")
		name, control = strings.TrimSuffix(name, "."), strings.TrimSuffix(control, ".")
		if !validHostname(name) || paired && (!validHostname(control) || name == control) {
			return nil, fmt.Errorf("invalid resource %q; use HOST or HOST=CONTROL", arg)
		}
		if previous, ok := seen[name]; ok {
			if previous != control {
				return nil, fmt.Errorf("conflicting controls for %s", name)
			}
			continue
		}
		seen[name] = control
		targets = append(targets, resource{Host: name, Control: control})
	}
	if len(targets) == 0 {
		return nil, errors.New("specify at least one hostname, as an argument or with -file")
	}
	return targets, nil
}

func validHostname(host string) bool {
	if len(host) > 252 || !strings.Contains(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !hostnameLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func lookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host+".")
	if err == nil && len(addrs) == 0 {
		err = errors.New("no IPv4 addresses")
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, err
}

func checkResource(ctx context.Context, root, bin, iface, operator string, target resource) error {
	dir := filepath.Join(root, target.Host)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}

	// The rooted spelling is accepted as a second input name by the paired runner.
	// Go TLS uses the same wire SNI and verifies the same DNS name for both forms.
	first, second := target.Host, target.Host+"."
	var diagnostic report
	diagnostic.Host = target.Host
	diagnostic.RequestedControl = target.Control
	addrs, dnsErr := lookupIPv4(ctx, target.Host)
	diagnostic.IPv4 = addrs
	if dnsErr != nil {
		diagnostic.DNSError = dnsErr.Error()
		return diagnostic.save(dir)
	}
	ip := addrs[0]
	if target.Control != "" {
		controlIPs, err := lookupIPv4(ctx, target.Control)
		diagnostic.ControlIPv4 = controlIPs
		for _, addr := range addrs {
			if slices.Contains(controlIPs, addr) {
				first, second = target.Control, target.Host
				ip = addr
				break
			}
		}
		if err != nil {
			diagnostic.ControlDNSError = err.Error()
		}
	}
	diagnostic.IP, diagnostic.Interface = ip, iface
	if err := ctx.Err(); err != nil {
		return errors.Join(err, diagnostic.save(dir))
	}

	question := "A02"
	if first != target.Host {
		question = "B02"
		diagnostic.Control = first
	}
	pcap := filepath.Join(dir, "client.pcap")
	limit := 1
	budget := runner.DefaultBudget()
	budget.MaxDurationS = 14
	budget.MaxSYNRetransmissions = &limit
	budget.StopConditions = []string{"first repeated SYN, data or FIN", "budget threshold", "capture error or drops", "SIGINT"}
	config := runner.Config{
		ExperimentID: strings.ToLower(question) + "-batch-" + strings.ReplaceAll(target.Host, ".", "-") +
			"-" + strings.TrimPrefix(filepath.Base(root), "batch-") + "-" + time.Now().UTC().Format("2006-01"),
		QuestionID: question, Mode: "valid-session", SNI: first, PairedSNI: second, PairedTimeoutMS: 4000,
		Endpoint: runner.Endpoint{Role: runner.RoleTarget, IP: ip.String(), Port: 443},
		Budget:   budget, Schedule: runner.Schedule{Repetitions: 1, InterTrialGapMS: 3000, StateReset: "none"},
		Capture: runner.CapturePaths{Client: pcap}, RunnerLog: filepath.Join(dir, "runner.log"),
		ClassificationRule: rule,
	}
	configPath := filepath.Join(dir, "config.yaml")
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return err
	}
	probeLog := filepath.Join(dir, "prober.log")
	logFile, err := os.OpenFile(probeLog, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, bin, "-config", configPath, "-capture-iface", iface, "-operator", operator)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 3 * time.Second
	probeErr := cmd.Run()
	closeErr := logFile.Close()

	obsErr := readJSON(filepath.Join(dir, "sni-observations.json"), &diagnostic.Series)
	if obsErr == nil {
		diagnostic.CaptureError = readCapture(pcap, ip, diagnostic.Series.Trials)
		if diagnostic.Series.CaptureDrops > 0 {
			diagnostic.CaptureError = fmt.Errorf("capture dropped %d packets", diagnostic.Series.CaptureDrops)
		}
		if probeErr != nil && diagnostic.Series.StopReason == "" {
			diagnostic.Series.StopReason = probeErr.Error()
			diagnostic.CaptureError = errors.Join(diagnostic.CaptureError, probeErr)
		}
	} else {
		diagnostic.CaptureError = obsErr
		if probeErr != nil {
			diagnostic.Series.StopReason = probeErr.Error()
		}
	}
	if diagnostic.CaptureError != nil {
		for i := range diagnostic.Series.Trials {
			diagnostic.Series.Trials[i].Wire = evidence{}
			diagnostic.Series.Trials[i].WireNote = "Захват недоступен для вывода по пакетам."
		}
	}
	// A normal policy stop can still leave enough packet evidence for a report.
	return errors.Join(closeErr, diagnostic.CaptureError, diagnostic.save(dir))
}

func readJSON(path string, output any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(output)
}

func writeJSON(path string, input any) error {
	data, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
