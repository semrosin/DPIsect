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

type seriesResult struct {
	Profile      probeProfileSpec `json:"-"`
	Budget       runner.Budget    `json:"-"`
	Err          error            `json:"-"`
	Trials       []trial          `json:"trials"`
	Packets      int              `json:"observed_packets"`
	Bytes        int              `json:"observed_ethernet_bytes"`
	CaptureDrops uint             `json:"capture_drops"`
	StopReason   string           `json:"stop_reason"`
}

type report struct {
	Host, DNSError            string
	Control, RequestedControl string
	ControlDNSFailed          bool
	Operator, BatchID         string
	Started                   time.Time
	IP                        netip.Addr
	SetupError                error
	Runs                      []seriesResult
}

func (s seriesResult) targetTrial(control string) *trial {
	var best *trial
	for i := range s.Trials {
		t := &s.Trials[i]
		if control != "" && t.SNI == control {
			continue
		}
		if t.Observation.Stage == "complete" {
			return t
		}
		if best == nil || t.phase() > best.phase() {
			best = t
		}
	}
	return best
}

func (s seriesResult) connected() bool {
	t := s.targetTrial("")
	return s.Err == nil && t != nil && t.Observation.Stage == "complete"
}

func (s seriesResult) silentHello(t *trial) bool {
	if s.Err != nil || t == nil || t.WireNote != "" || t.Observation.Stage != "tls" {
		return false
	}
	w := t.Wire
	timedOut := t.Observation.Error == context.DeadlineExceeded.Error()
	retried := w.DataRepeat && strings.Contains(s.StopReason, "outgoing data or FIN retransmission")
	return w.SYNACK && w.HelloBytes > 0 && !w.ServerData && !w.Reset && (timedOut || retried)
}

func (s seriesResult) outcome(control string) string {
	t := s.targetTrial(control)
	switch {
	case s.Err != nil:
		return "Ошибка измерения — " + inline(s.Err.Error())
	case t == nil:
		return "Попытка ресурса не началась"
	case t.Observation.Stage == "complete" && s.Profile.tcpOnly:
		return "TCP подключился"
	case t.Observation.Stage == "complete":
		if control == "" && len(s.Trials) == 2 && s.Trials[0].Observation.Stage != s.Trials[1].Observation.Stage {
			return "TLS прошёл в одной из двух попыток"
		}
		return "TLS и проверка сертификата прошли"
	default:
		return strings.TrimSuffix(t.outcome(), ".")
	}
}

func (r report) diagnosis() string {
	if r.DNSError != "" {
		return "Вероятная причина — сбой DNS. Системный резолвер не вернул IPv4."
	}
	if len(r.Runs) == 0 || r.Runs[0].Err != nil {
		return "Вывод — измерение не состоялось."
	}
	tcp := r.Runs[0]
	if !tcp.connected() {
		return failureCause(tcp.targetTrial(""))
	}
	var worked, silent, best *seriesResult
	tlsAvailable := false
	for i := 1; i < len(r.Runs); i++ {
		s := &r.Runs[i]
		t := s.targetTrial(r.Control)
		if s.Err != nil || t == nil {
			continue
		}
		if t.Observation.Stage == "complete" {
			tlsAvailable = true
			if len(s.Trials) == 2 && s.Trials[0].Observation.Stage == "complete" && s.Trials[1].Observation.Stage == "complete" {
				worked = s
			}
			continue
		}
		if best == nil || t.phase() > best.targetTrial(r.Control).phase() {
			best = s
		}
		if s.silentHello(t) {
			silent = s
		}
	}
	if worked != nil && silent != nil {
		return fmt.Sprintf("Вероятная причина — чувствительность к моменту отправки ClientHello. В этой серии «%s» прошёл, «%s» остался без ответа.", worked.Profile.label, silent.Profile.label)
	}
	if tlsAvailable {
		return "Вывод — TLS доступен на выбранном IPv4."
	}
	for i := 1; i < len(r.Runs); i++ {
		s := r.Runs[i]
		t := s.targetTrial(r.Control)
		if r.Control == "" || !s.silentHello(t) || t.Wire.HelloSNI != r.Host {
			continue
		}
		for _, c := range s.Trials {
			if c.SNI != r.Control || c.WireNote != "" || c.Observation.Stage != "complete" || c.Wire.HelloSNI != r.Control {
				continue
			}
			if c.Wire.HelloBytes == t.Wire.HelloBytes {
				return "Вероятная причина — фильтрация или отказ по SNI. На том же IP контроль завершил TLS, ресурс остался без ответа."
			}
			return "Вероятная причина — реакция на параметры ClientHello. На том же IP контроль прошёл, отличались SNI и размер ClientHello."
		}
	}
	if best != nil {
		return failureCause(best.targetTrial(r.Control))
	}
	return "Вывод — TCP доступен, результат TLS для ресурса отсутствует."
}

func failureCause(t *trial) string {
	if t == nil {
		return "Вывод — попытка ресурса не состоялась."
	}
	w := t.Wire
	switch {
	case strings.Contains(t.Observation.Error, "network is unreachable") || strings.Contains(t.Observation.Error, "no route to host"):
		return "Вероятная причина — сбой маршрута до выбранного IP."
	case t.Observation.Error == context.Canceled.Error() && !w.DataRepeat && !w.Reset:
		return "Вывод — проверка остановлена до завершения попытки."
	case t.WireNote != "":
		return "Вывод — пакеты попытки не удалось однозначно сопоставить."
	case !w.SYNACK && w.Reset:
		return "Вероятная причина — отказ на порту TCP/443. На SYN пришёл RST."
	case !w.SYNACK:
		return "Вероятная причина — потеря или фильтрация TCP/443 до TLS. SYN-ACK не получен."
	case strings.Contains(t.Observation.Error, "x509:"):
		return "Вероятная причина — сертификат не прошёл проверку."
	case w.Alert != nil || strings.Contains(t.Observation.Error, "remote error: tls:"):
		return "Вероятная причина — отклонение TLS-рукопожатия. Получен TLS Alert."
	case w.Reset:
		return "Вероятная причина — принудительный сброс TCP после установления соединения."
	case w.ServerHello:
		return "Вывод — сервер начал TLS-рукопожатие, сбой произошёл после ServerHello."
	case w.HelloBytes > 0 && !w.ServerData:
		return "Вероятная причина — отбрасывание ClientHello или ответных пакетов TLS. TCP до этого установился."
	default:
		return "Вывод — TCP установился, сбой произошёл на начальном этапе TLS."
	}
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
	if r.SetupError != nil {
		fmt.Fprintf(&b, "Ошибка запуска — %s.\n", inline(r.SetupError.Error()))
	}
	if r.DNSError == "" && len(r.Runs) > 0 {
		b.WriteByte('\n')
		for i, profile := range profiles {
			outcome := "пропущен"
			if i < len(r.Runs) {
				run := r.Runs[i]
				outcome = run.outcome(r.Control)
				if run.StopReason != "" && run.Err == nil {
					outcome += " (" + shortStop(run.StopReason) + ")"
				}
			}
			fmt.Fprintf(&b, "- %s — %s.\n", profile.label, outcome)
		}
	}
	fmt.Fprintf(&b, "\n%s · %s", r.Started.Format(time.RFC3339), inline(r.Operator))
	if len(r.Runs) > 0 {
		fmt.Fprintf(&b, " · %s · пакеты/байты по режимам", r.BatchID)
		for _, run := range r.Runs {
			fmt.Fprintf(&b, " %d/%d", run.Packets, run.Bytes)
		}
		budget := r.Runs[0].Budget
		fmt.Fprintf(&b, " · лимит на режим %d пакетов, %d Б, %d пак/с, %d с",
			budget.MaxPackets, budget.MaxBytes, budget.MaxRatePPS, budget.MaxDurationS)
	}
	b.WriteByte('\n')
	return os.WriteFile(filepath.Join(dir, r.Host+".md"), []byte(b.String()), 0o600)
}

func shortStop(reason string) string {
	switch {
	case strings.Contains(reason, "SYN retransmission limit"):
		return "остановка после повторного SYN"
	case strings.Contains(reason, "outgoing data or FIN retransmission"):
		return "остановка после повтора TCP-данных или FIN"
	case strings.Contains(reason, "observed limit reached"):
		return "достигнут лимит прогона"
	case strings.Contains(reason, "context canceled"):
		return "прервано"
	default:
		return inline(reason)
	}
}

func inline(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
