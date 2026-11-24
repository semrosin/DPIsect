// Command review verifies the first TLS ClientHello against an offline capture.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"

	"github.com/semrosin/DPIsect/internal/generator"
	"github.com/semrosin/DPIsect/internal/tlsparse"
	"gopkg.in/yaml.v3"
)

const maxPlanSize = 16 << 20

type wirePlan struct {
	Endpoint struct {
		IP   netip.Addr `yaml:"ip"`
		Port uint16     `yaml:"port"`
	} `yaml:"endpoint"`
	Trials []struct {
		SNI    string                      `yaml:"sni"`
		Packet generator.PlannedWirePacket `yaml:"packet"`
	} `yaml:"trials"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "c01 review:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("review", flag.ContinueOnError)
	planPath := flags.String("plan", "", "local plan.yaml")
	pcapPath := flags.String("pcap", "", "local Ethernet PCAP")
	trialNumber := flags.Int("trial", 0, "one-based trial index in the plan")
	source := flags.String("source", "", "client IPv4:port as seen in the capture")
	seriesPath := flags.String("series", "", "local JSON manifest listing saved trials")
	browser := flags.String("browser", "", "saved browser Ethernet capture")
	sni := flags.String("sni", "", "visible TLS server name to select in a browser capture")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	if *browser != "" || *sni != "" {
		if *browser == "" || *sni == "" || flags.NFlag() != 2 {
			return errors.New("expected -browser and -sni without other flags")
		}
		result, err := reviewBrowser(*browser, *sni)
		if err != nil {
			return err
		}
		return encoder.Encode(result)
	}
	if *seriesPath != "" {
		if flags.NFlag() != 1 {
			return errors.New("-series cannot be combined with single-trial flags")
		}
		series, err := reviewSeries(*seriesPath)
		if err != nil {
			return err
		}
		return encoder.Encode(series)
	}
	result, err := reviewTrial(*planPath, *pcapPath, *trialNumber, *source)
	if err != nil {
		return err
	}
	return encoder.Encode(result)
}

func reviewTrial(planPath, pcapPath string, trialNumber int, source string) (review, error) {
	if planPath == "" || pcapPath == "" || trialNumber < 1 {
		return review{}, errors.New("expected -plan, -pcap, -trial and -source")
	}
	client, err := netip.ParseAddrPort(source)
	if err != nil || !client.Addr().Is4() || client.Port() == 0 {
		return review{}, errors.New("source must be a numeric IPv4 address and nonzero port")
	}

	planFile, err := os.Open(planPath)
	if err != nil {
		return review{}, err
	}
	defer planFile.Close()
	data, err := io.ReadAll(io.LimitReader(planFile, maxPlanSize+1))
	if err != nil {
		return review{}, fmt.Errorf("read plan: %w", err)
	}
	if len(data) > maxPlanSize {
		return review{}, errors.New("plan is too large")
	}
	var plan wirePlan
	if err := yaml.Unmarshal(data, &plan); err != nil {
		return review{}, fmt.Errorf("decode plan: %w", err)
	}
	if trialNumber > len(plan.Trials) || !plan.Endpoint.IP.Is4() || plan.Endpoint.Port == 0 {
		return review{}, errors.New("invalid trial index or plan endpoint")
	}
	server := netip.AddrPortFrom(plan.Endpoint.IP, plan.Endpoint.Port)
	if client == server {
		return review{}, errors.New("client and server address and port must differ")
	}
	trial := plan.Trials[trialNumber-1]
	recordEnds, err := validateHello(trial.SNI, trial.Packet)
	if err != nil {
		return review{}, fmt.Errorf("invalid trial %d: %w", trialNumber, err)
	}

	capture, err := os.Open(pcapPath)
	if err != nil {
		return review{}, err
	}
	defer capture.Close()
	hash := sha256.New()
	result, err := inspectCapture(io.TeeReader(capture, hash), client, server, trial.Packet.Payload)
	if err != nil {
		return review{}, err
	}
	result.Client = client
	result.Server = server
	result.Trial = trialNumber
	result.SNI = trial.SNI
	result.PlanSHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	result.CaptureSHA256 = fmt.Sprintf("%x", hash.Sum(nil))
	result.HelloSHA256 = fmt.Sprintf("%x", sha256.Sum256(trial.Packet.Payload))
	result.TLSRecordEnds = recordEnds
	if trial.Packet.SplitOffsets != nil {
		match := slices.Equal(result.TCPSplitOffsets, trial.Packet.SplitOffsets)
		result.SplitOffsetsMatch = &match
	}
	return result, nil
}

func validateHello(sni string, plan generator.PlannedWirePacket) ([]int, error) {
	if len(plan.Payload) > (1<<16)-1 {
		return nil, errors.New("planned ClientHello is too large")
	}
	previous := 0
	for _, offset := range plan.SplitOffsets {
		if offset <= previous || offset >= len(plan.Payload) {
			return nil, errors.New("invalid planned TCP split offsets")
		}
		previous = offset
	}
	reader := bytes.NewReader(plan.Payload)
	var handshake []byte
	var ends []int
	for reader.Len() > 0 {
		record, err := tlsparse.ReadRecord(reader)
		if err != nil {
			return nil, err
		}
		if record.Type != tlsparse.TypeHandshake || len(record.Payload) == 0 {
			return nil, errors.New("expected nonempty TLS handshake records")
		}
		handshake = append(handshake, record.Payload...)
		ends = append(ends, len(plan.Payload)-reader.Len())
	}
	if len(handshake) < 4 || int(handshake[1])<<16|int(handshake[2])<<8|int(handshake[3]) != len(handshake)-4 {
		return nil, errors.New("expected exactly one complete ClientHello")
	}
	hello, err := tlsparse.ParseClientHello(handshake)
	if err != nil {
		return nil, err
	}
	if sni == "" || hello.SNI != sni {
		return nil, errors.New("ClientHello SNI differs from plan")
	}
	if !slices.Equal(ends, plan.TLSRecordEnds) {
		return nil, errors.New("TLS record boundaries differ from plan")
	}
	return ends, nil
}
