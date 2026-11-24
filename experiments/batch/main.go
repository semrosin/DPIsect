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

const rule = "Record the last observed DNS/TCP/TLS stage. Compare immediate and delayed ClientHello on the same IPv4 after TCP connects. " +
	"A same-IP control completing TLS while the target times out or retransmits " +
	"its equal-size ClientHello without a TLS response is a likely SNI-dependent difference; its source remains undetermined. " +
	"TLS alerts, certificate failures and TCP failures are reported at their observed stage. This batch does not assign a formal research verdict."

var hostnameLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type resource struct {
	Host    string
	Control string
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
		var settings []string
		for _, profile := range profiles {
			settings = append(settings, profile.label+" ("+profile.settings()+")")
		}
		plan := strings.Join(settings, " · ")
		for _, target := range targets {
			comparison := ""
			if target.Control != "" {
				comparison = " · контроль SNI " + target.Control + " при общем IPv4"
			}
			fmt.Printf("%s:443 — %s%s\n", target.Host, plan, comparison)
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

func checkResource(ctx context.Context, root, bin, iface, operator string, target resource) (result error) {
	diagnostic := report{Host: target.Host, Operator: operator, Started: time.Now().UTC()}
	defer func() {
		if result != nil && diagnostic.DNSError == "" && len(diagnostic.Runs) == 0 {
			diagnostic.SetupError = result
		}
		result = errors.Join(result, diagnostic.save(root))
	}()

	// The rooted spelling is accepted as a second input name by the paired runner.
	// Go TLS uses the same wire SNI and verifies the same DNS name for both forms.
	first, second := target.Host, target.Host+"."
	diagnostic.RequestedControl = target.Control
	addrs, dnsErr := lookupIPv4(ctx, target.Host)
	if dnsErr != nil {
		diagnostic.DNSError = dnsErr.Error()
		return ctx.Err()
	}
	ip := addrs[0]
	if target.Control != "" {
		controlIPs, err := lookupIPv4(ctx, target.Control)
		for _, addr := range addrs {
			if slices.Contains(controlIPs, addr) {
				first, second = target.Control, target.Host
				ip = addr
				break
			}
		}
		diagnostic.ControlDNSFailed = err != nil
	}
	diagnostic.IP = ip
	if err := ctx.Err(); err != nil {
		return err
	}

	if first != target.Host {
		diagnostic.Control = first
	}
	diagnostic.BatchID = filepath.Base(root)
	for _, profile := range profiles {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		run := probeProfile(ctx, bin, iface, diagnostic, profile, first, second)
		diagnostic.Runs = append(diagnostic.Runs, run)
		if run.Err != nil {
			return errors.Join(result, run.Err)
		}
		if profile.tcpOnly && !run.connected() {
			break
		}
	}
	return result
}

type probeProfileSpec struct {
	name, label string
	tcpOnly     bool
	helloMS     int
	closeMS     int
}

const (
	trialTimeoutMS  = 4000
	interTrialGapMS = 3000
)

var profiles = [...]probeProfileSpec{
	{name: "tcp", label: "Только TCP", tcpOnly: true},
	{name: "tls", label: "TLS сразу"},
	{name: "tls-delay", label: "TLS с задержкой ClientHello", helloMS: 500},
	{name: "tls-hold", label: "TLS с удержанием соединения", closeMS: 1000},
}

func (p probeProfileSpec) timeoutMS() int {
	return trialTimeoutMS + p.helloMS + p.closeMS
}

func (p probeProfileSpec) settings() string {
	if p.tcpOnly {
		return fmt.Sprintf("без TLS, таймаут %d мс", p.timeoutMS())
	}
	return fmt.Sprintf("ClientHello через %d мс после TCP, закрытие через %d мс после TLS, таймаут %d мс",
		p.helloMS, p.closeMS, p.timeoutMS())
}

func probeProfile(ctx context.Context, bin, iface string, r report, profile probeProfileSpec, first, second string) (run seriesResult) {
	run.Profile = profile
	dir, err := os.MkdirTemp("", "dpisect-batch-")
	if err != nil {
		run.Err = err
		return run
	}
	defer func() { run.Err = errors.Join(run.Err, os.RemoveAll(dir)) }()

	question := "A02"
	if !profile.tcpOnly && r.Control != "" {
		question = "B02"
	}
	pcap := filepath.Join(dir, "client.pcap")
	limit := 1
	budget := runner.DefaultBudget()
	budget.MaxDurationS = 15
	budget.MaxSYNRetransmissions = &limit
	budget.StopConditions = []string{"first repeated SYN, data or FIN", "budget threshold", "capture error or drops", "SIGINT"}
	config := runner.Config{
		ExperimentID: strings.ToLower(question) + "-" + profile.name + "-" + strings.ReplaceAll(r.Host, ".", "-") +
			"-" + r.BatchID + "-" + r.Started.Format("2006-01"),
		QuestionID: question, Mode: "valid-session",
		Endpoint: runner.Endpoint{Role: runner.RoleTarget, IP: r.IP.String(), Port: 443},
		Budget:   budget, Schedule: runner.Schedule{Repetitions: 1, InterTrialGapMS: interTrialGapMS, StateReset: "none"},
		Capture: runner.CapturePaths{Client: pcap}, RunnerLog: filepath.Join(dir, "runner.log"),
		ClassificationRule: rule,
	}
	observations := "sni-observations.json"
	if profile.tcpOnly {
		config.TCPOnly, config.TCPTimeoutMS = true, profile.timeoutMS()
		observations = "tcp-observations.json"
	} else {
		config.SNI, config.PairedSNI = first, second
		config.PairedClientHelloDelayMS = profile.helloMS
		config.PairedCloseDelayMS = profile.closeMS
		config.PairedTimeoutMS = profile.timeoutMS()
	}
	data, err := yaml.Marshal(config)
	if err != nil {
		run.Err = err
		return run
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		run.Err = err
		return run
	}
	run.Budget = budget
	cmd := exec.CommandContext(ctx, bin, "-config", configPath, "-capture-iface", iface, "-operator", r.Operator)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 3 * time.Second
	_, probeErr := cmd.Output()

	if err := readJSON(filepath.Join(dir, observations), &run); err != nil {
		run.Err = errors.New("probe observations unavailable")
		if probeErr != nil {
			run.Err = probeErr
		}
		var exitErr *exec.ExitError
		if errors.As(probeErr, &exitErr) {
			_, detail, ok := strings.Cut("\n"+string(exitErr.Stderr), "\ndpi-prober: ")
			if ok {
				detail, _, _ = strings.Cut(detail, "\n")
				run.Err = errors.New(strings.ReplaceAll(detail, dir+string(os.PathSeparator), ""))
			}
		}
		return run
	}
	run.Err = readCapture(pcap, r.IP, run.Trials)
	if run.CaptureDrops > 0 {
		run.Err = fmt.Errorf("capture dropped %d packets", run.CaptureDrops)
	}
	if probeErr != nil && run.StopReason == "" {
		run.Err = errors.Join(run.Err, probeErr)
	}
	return run
}

func readJSON(path string, output any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return json.NewDecoder(io.LimitReader(f, 1<<20)).Decode(output)
}
