// Command review checks saved paired TLS experiments without opening sockets.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"gopkg.in/yaml.v3"
)

type endpoint struct {
	IP   string `yaml:"ip" json:"ip"`
	Port uint16 `yaml:"port" json:"port"`
}

type wirePlan struct {
	ExperimentID string   `yaml:"experiment_id"`
	Endpoint     endpoint `yaml:"endpoint"`
	Trials       []struct {
		SNI    string `yaml:"sni"`
		Packet struct {
			Payload []byte `yaml:"payload"`
		} `yaml:"packet"`
	} `yaml:"trials"`
}

type observation struct {
	Trials []struct {
		SNI         string `json:"sni"`
		Observation struct {
			Stage      string `json:"stage"`
			TLSVersion uint16 `json:"tls_version"`
		} `json:"observation"`
	} `json:"trials"`
	Packets    int    `json:"observed_packets"`
	Bytes      int    `json:"observed_ethernet_bytes"`
	Drops      uint   `json:"capture_drops"`
	StopReason string `json:"stop_reason"`
}

type trialReview struct {
	SNI                     string  `json:"sni"`
	ClientPort              uint16  `json:"client_port"`
	TCPHandshakeObserved    bool    `json:"tcp_handshake_observed"`
	Stage                   string  `json:"stage"`
	TLSVersion              uint16  `json:"tls_version,omitempty"`
	HelloLength             int     `json:"hello_length"`
	PlanMatches             bool    `json:"plan_matches"`
	IncomingAfterHello      int     `json:"incoming_frames_after_hello"`
	IdenticalHelloRepeats   int     `json:"identical_hello_repeats"`
	FirstHelloRepeatDelayMS float64 `json:"first_hello_repeat_delay_ms,omitempty"`
}

type review struct {
	ExperimentID    string        `json:"experiment_id"`
	StartedUTC      string        `json:"started_utc"`
	Endpoint        endpoint      `json:"endpoint"`
	VerifiedHashes  int           `json:"verified_artifact_hashes"`
	PlanSHA256      string        `json:"plan_sha256"`
	RunSHA256       string        `json:"run_sha256"`
	PlannedAttempts int           `json:"planned_attempts"`
	Unstarted       int           `json:"unstarted_attempts"`
	Packets         int           `json:"pcap_frames"`
	Bytes           int           `json:"pcap_ethernet_bytes"`
	CaptureDrops    uint          `json:"reported_capture_drops"`
	StopReason      string        `json:"stop_reason,omitempty"`
	Trials          []trialReview `json:"trials"`
}

type frame struct {
	time     time.Time
	seq      uint32
	ack      uint32
	syn      bool
	ackFlag  bool
	fin      bool
	incoming bool
	payload  []byte
}

type flow struct {
	clientIP string
	port     uint16
	frames   []frame
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "review:", err)
		os.Exit(1)
	}
}

func run(directories []string, out io.Writer) error {
	if len(directories) == 0 {
		return errors.New("usage: review EXPERIMENT_DIRECTORY [...]; reads local files only")
	}
	var reviews []review
	for _, directory := range directories {
		result, err := reviewDirectory(directory)
		if err != nil {
			return fmt.Errorf("%s: %w", directory, err)
		}
		reviews = append(reviews, result)
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(reviews)
}

func readJSON(path string, value any) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return data, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func reviewDirectory(directory string) (review, error) {
	var result review
	var record struct {
		ExperimentID string            `json:"experiment_id"`
		StartedUTC   string            `json:"started_utc"`
		Artifacts    map[string]string `json:"artifacts"`
	}
	runBytes, err := readJSON(filepath.Join(directory, "run.json"), &record)
	if err != nil {
		return result, err
	}
	var config struct {
		ExperimentID string `yaml:"experiment_id"`
		Capture      struct {
			Client string `yaml:"client"`
		} `yaml:"capture"`
		RunnerLog string `yaml:"runner_log"`
	}
	configBytes, err := os.ReadFile(filepath.Join(directory, "config.yaml"))
	if err != nil {
		return result, err
	}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return result, err
	}
	for path, expected := range record.Artifacts {
		data, err := os.ReadFile(path)
		if err != nil {
			return result, err
		}
		if digest(data) != expected {
			return result, fmt.Errorf("artifact hash mismatch: %s", path)
		}
	}
	obsPath := filepath.Join(filepath.Dir(config.RunnerLog), "sni-observations.json")
	for _, path := range []string{config.Capture.Client, config.RunnerLog, obsPath} {
		if record.Artifacts[path] == "" {
			return result, fmt.Errorf("artifact is not hashed in run.json: %s", path)
		}
	}
	var observations observation
	if _, err := readJSON(obsPath, &observations); err != nil {
		return result, err
	}
	var plan wirePlan
	planBytes, err := os.ReadFile(filepath.Join(directory, "plan.yaml"))
	if err != nil {
		return result, err
	}
	if err := yaml.Unmarshal(planBytes, &plan); err != nil {
		return result, err
	}
	if plan.ExperimentID != record.ExperimentID || config.ExperimentID != record.ExperimentID {
		return result, errors.New("experiment IDs differ")
	}
	flows, packets, size, err := readCapture(config.Capture.Client, plan.Endpoint)
	if err != nil {
		return result, err
	}
	if packets != observations.Packets || size != observations.Bytes {
		return result, errors.New("capture counts differ from observations")
	}
	if len(flows) != len(observations.Trials) || len(flows) > len(plan.Trials) {
		return result, errors.New("TCP flow count differs from recorded attempts or plan")
	}
	result = review{
		ExperimentID: record.ExperimentID, StartedUTC: record.StartedUTC, Endpoint: plan.Endpoint,
		VerifiedHashes: len(record.Artifacts), PlanSHA256: digest(planBytes), RunSHA256: digest(runBytes),
		PlannedAttempts: len(plan.Trials), Unstarted: len(plan.Trials) - len(flows),
		Packets: packets, Bytes: size, CaptureDrops: observations.Drops, StopReason: observations.StopReason,
	}
	for i, flow := range flows {
		if observations.Trials[i].SNI != plan.Trials[i].SNI {
			return result, fmt.Errorf("trial %d SNI differs from plan", i)
		}
		trial, err := inspectFlow(flow, plan.Trials[i].Packet.Payload)
		if err != nil {
			return result, fmt.Errorf("trial %d: %w", i, err)
		}
		trial.SNI = plan.Trials[i].SNI
		trial.Stage = observations.Trials[i].Observation.Stage
		trial.TLSVersion = observations.Trials[i].Observation.TLSVersion
		result.Trials = append(result.Trials, trial)
	}
	return result, nil
}

// readCapture accepts the Ethernet/IPv4/TCP captures used by these pilots.
// Ambiguous or additional flows fail the audit rather than being discarded.
func readCapture(path string, target endpoint) ([]flow, int, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, 0, 0, err
	}
	if r.LinkType() != layers.LinkTypeEthernet {
		return nil, 0, 0, errors.New("expected Ethernet capture")
	}
	var flows []flow
	packets, size := 0, 0
	for {
		data, info, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, 0, 0, err
		}
		if info.CaptureLength != info.Length {
			return nil, 0, 0, errors.New("truncated capture frame")
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok || ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0 {
			return nil, 0, 0, errors.New("expected unfragmented IPv4")
		}
		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			return nil, 0, 0, errors.New("expected TCP")
		}
		incoming := ip.SrcIP.String() == target.IP && uint16(tcp.SrcPort) == target.Port
		outgoing := ip.DstIP.String() == target.IP && uint16(tcp.DstPort) == target.Port
		if incoming == outgoing {
			return nil, 0, 0, errors.New("frame is not uniquely associated with endpoint")
		}
		clientIP, port := ip.SrcIP.String(), uint16(tcp.SrcPort)
		if incoming {
			clientIP, port = ip.DstIP.String(), uint16(tcp.DstPort)
		}
		index := -1
		for i := range flows {
			if flows[i].clientIP == clientIP && flows[i].port == port {
				index = i
				break
			}
		}
		if index < 0 {
			if incoming || !tcp.SYN || tcp.ACK {
				return nil, 0, 0, errors.New("TCP flow does not start with client SYN")
			}
			index = len(flows)
			flows = append(flows, flow{clientIP: clientIP, port: port})
		}
		flows[index].frames = append(flows[index].frames, frame{
			time: info.Timestamp, seq: tcp.Seq, ack: tcp.Ack, syn: tcp.SYN,
			ackFlag: tcp.ACK, fin: tcp.FIN, incoming: incoming, payload: append([]byte(nil), tcp.Payload...),
		})
		packets++
		size += info.Length
	}
	return flows, packets, size, nil
}

// inspectFlow intentionally requires one complete initial ClientHello segment.
// A segmented or inconsistent trace needs a different analysis, not a guess.
func inspectFlow(flow flow, planned []byte) (trialReview, error) {
	result := trialReview{ClientPort: flow.port, HelloLength: len(planned)}
	if len(planned) == 0 || len(flow.frames) == 0 {
		return result, errors.New("missing planned hello or TCP frames")
	}
	first := -1
	for i, frame := range flow.frames {
		if !frame.incoming && len(frame.payload) > 0 {
			first = i
			break
		}
	}
	if first < 0 {
		return result, errors.New("no outgoing ClientHello observed")
	}
	hello := flow.frames[first]
	if !bytes.Equal(hello.payload, planned) {
		return result, errors.New("initial payload differs from planned ClientHello or is segmented")
	}
	result.PlanMatches = true
	initial := flow.frames[0]
	var serverSeq uint32
	synAck := false
	for _, frame := range flow.frames[1:first] {
		if frame.incoming && frame.syn && frame.ackFlag && frame.ack == initial.seq+1 {
			serverSeq, synAck = frame.seq, true
		}
		if !frame.incoming && !frame.syn && frame.ackFlag && synAck && frame.ack == serverSeq+1 {
			result.TCPHandshakeObserved = true
		}
	}
	for _, frame := range flow.frames[first+1:] {
		if frame.incoming {
			result.IncomingAfterHello++
		}
		if !frame.incoming && frame.seq == hello.seq && bytes.Equal(frame.payload, planned) {
			result.IdenticalHelloRepeats++
			if result.IdenticalHelloRepeats == 1 {
				result.FirstHelloRepeatDelayMS = float64(frame.time.Sub(hello.time)) / float64(time.Millisecond)
			}
		}
	}
	return result, nil
}
