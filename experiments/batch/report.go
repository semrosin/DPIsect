package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/semrosin/DPIsect/internal/runner"
	"github.com/semrosin/DPIsect/internal/sender"
)

type trial struct {
	SNI         string                       `json:"sni"`
	Started     time.Time                    `json:"started_utc"`
	Finished    time.Time                    `json:"finished_utc"`
	Observation sender.ConnectionObservation `json:"observation"`
	Wire        evidence                     `json:"-"`
	WireNote    string                       `json:"-"`
}

type report struct {
	Host, DNSError            string
	Control, RequestedControl string
	ControlDNSFailed          bool
	Operator, ExperimentID    string
	Started                   time.Time
	Budget                    runner.Budget
	IP                        netip.Addr
	CaptureError              error
	Series                    struct {
		Trials       []trial `json:"trials"`
		Packets      int     `json:"observed_packets"`
		Bytes        int     `json:"observed_ethernet_bytes"`
		CaptureDrops uint    `json:"capture_drops"`
		StopReason   string  `json:"stop_reason"`
	}
}

func (r report) diagnosis() string {
	if r.DNSError != "" {
		return "DNS — системный резолвер не вернул IPv4."
	}
	var target, control *trial
	for i := range r.Series.Trials {
		t := &r.Series.Trials[i]
		if r.Control != "" && t.SNI == r.Control {
			control = t
			continue
		}
		if t.Observation.Stage == "complete" {
			return "TLS — рукопожатие и проверка сертификата прошли."
		}
		if target == nil || t.phase() > target.phase() {
			target = t
		}
	}
	if target == nil && control != nil {
		return "Измерение — серия завершилась на контроле, попытка ресурса не началась."
	}
	if r.CaptureError != nil || target == nil {
		return "Измерение — прогона ресурса с пригодным захватом нет."
	}
	if target.WireNote != "" {
		return "Измерение — пакеты попытки не удалось однозначно сопоставить."
	}
	timedOut := target.Observation.Error == context.DeadlineExceeded.Error()
	retried := target.Wire.DataRepeat && strings.Contains(r.Series.StopReason, "outgoing data or FIN retransmission")
	if control != nil && control.WireNote == "" && control.Observation.Stage == "complete" &&
		control.Wire.HelloSNI == r.Control && target.Wire.HelloSNI == r.Host &&
		target.Wire.HelloBytes > 0 && control.Wire.HelloBytes > 0 && (timedOut || retried) &&
		target.Wire.SYNACK && !target.Wire.ServerData && !target.Wire.Reset && target.Observation.Stage == "tls" {
		if target.Wire.HelloBytes == control.Wire.HelloBytes {
			return "ClientHello — вероятна фильтрация по SNI. На том же IP контроль завершил TLS, ресурс остался без ответа."
		}
		return "ClientHello — у ресурса нет ответа, контроль на том же IP завершил TLS. Отличались SNI и размер ClientHello."
	}
	return target.outcome()
}

func (t trial) phase() int {
	switch {
	case t.Wire.ServerHello || t.Wire.Alert != nil || t.Observation.Stage == "complete":
		return 4
	case t.Wire.ClientData:
		return 3
	case t.Wire.SYNACK:
		return 2
	case t.Wire.SYNs > 0:
		return 1
	default:
		return 0
	}
}

func (t trial) outcome() string {
	w := t.Wire
	switch {
	case t.WireNote != "":
		return t.WireNote
	case !w.SYNACK && w.Reset:
		return "TCP — получен RST до установления соединения."
	case !w.SYNACK:
		return "TCP — отправлен SYN, SYN-ACK не получен."
	case strings.Contains(t.Observation.Error, "x509:"):
		return "TLS — ошибка проверки сертификата."
	case w.Alert != nil:
		return fmt.Sprintf("TLS — получен Alert (код %d).", *w.Alert)
	case strings.Contains(t.Observation.Error, "remote error: tls:"):
		return "TLS — клиент получил TLS Alert."
	case w.Reset && w.ServerHello:
		return "TLS — получен RST после ServerHello."
	case w.Reset && w.ClientData:
		return "TLS — получен RST после начала отправки ClientHello."
	case w.Reset:
		return "TCP — получен RST после SYN-ACK, до наблюдаемого ClientHello."
	case w.ServerHello:
		return "TLS — получен ServerHello, рукопожатие прервалось позже."
	case w.ServerData:
		return "TLS — ответные TCP-данные есть, ServerHello в захвате не распознан."
	case w.HelloBytes > 0:
		return "ClientHello — отправлен, ответных данных TLS в окне захвата нет."
	case w.ClientData:
		return "TLS — видны исходящие TCP-данные, полный ClientHello в захвате не собран."
	default:
		return "TCP — получен SYN-ACK, ClientHello в захвате отсутствует."
	}
}

func (r report) save(dir string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n", r.Host, r.diagnosis())
	if r.DNSError != "" {
		fmt.Fprintf(&b, "\n%s\n", inline(r.DNSError))
	} else if r.IP.IsValid() {
		fmt.Fprintf(&b, "\nIPv4 `%s:443`", r.IP)
		if r.Control != "" {
			fmt.Fprintf(&b, ", контроль `%s`", r.Control)
		}
		b.WriteString(".\n")
	}
	if r.RequestedControl != "" && r.DNSError == "" && r.Control == "" {
		if r.ControlDNSFailed {
			fmt.Fprintf(&b, "DNS контроля `%s` не вернул IPv4.\n", r.RequestedControl)
		} else {
			fmt.Fprintf(&b, "С контролем `%s` нет общего IPv4.\n", r.RequestedControl)
		}
	}
	var attempts, successful int
	for _, t := range r.Series.Trials {
		if t.SNI != r.Control {
			attempts++
			if t.Observation.Stage == "complete" {
				successful++
			}
		}
	}
	if successful > 0 && successful < attempts {
		fmt.Fprintf(&b, "TLS прошёл в %d из %d попыток.\n", successful, attempts)
	}
	if r.Series.StopReason != "" {
		fmt.Fprintf(&b, "Остановка прогона — %s.\n", inline(r.Series.StopReason))
	}
	if r.CaptureError != nil {
		fmt.Fprintf(&b, "Ошибка измерения — %s.\n", inline(r.CaptureError.Error()))
	}
	fmt.Fprintf(&b, "\n%s · %s", r.Started.Format(time.RFC3339), inline(r.Operator))
	if r.ExperimentID != "" {
		fmt.Fprintf(&b, " · %s · %d/%d пакетов, %d/%d Б · лимит %d пак/с, %d с",
			r.ExperimentID, r.Series.Packets, r.Budget.MaxPackets, r.Series.Bytes, r.Budget.MaxBytes,
			r.Budget.MaxRatePPS, r.Budget.MaxDurationS)
	}
	b.WriteByte('\n')
	return os.WriteFile(filepath.Join(dir, r.Host+".md"), []byte(b.String()), 0o600)
}

func inline(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
