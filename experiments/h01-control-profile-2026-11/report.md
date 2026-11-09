---
question_id: H01
experiment_id: h01-control-profile-2026-11
status: confirmed
hypothesis: >
  Классификатор DPIsect (H01) различает заранее известные причины
  наблюдаемых отказов: на эталонных трассах из testdata/ он ставит
  причину, совпадающую с разметкой, а контрольный прогон доставляет
  спланированную пробу helper'у в пределах бюджета.
alternative_hypotheses:
  - "Классификатор не отличает drop от rst_injection — допустимо промежуточно, но нарушает полный классификационный контракт H01."
  - "Наблюдения прогона объясняются не доставкой, а потерей проба на пути prober → helper."
  - "Событие handshake_failed в журнале helper'а — признак сетевого вмешательства, а не свойства отправителя."
mode: valid-session
vantage:
  network: loopback
  address_family: ipv4
  capture_point: >
    Точки захвата client и helper не запускались: у оператора нет
    CAP_NET_RAW. Обе точки находились на loopback и увидели бы
    одинаковый поток; классификация выполнена по эталонным фикстурам.
endpoint: {role: helper, ip: 127.0.0.1, port: 8443}
control:
  profile: control-unimpaired
  lab_enabled: false
  helper_profile: accepting
  helper_capture: disabled
  notes: >
    Никакой лабораторной обработки (lab отключён); helper — собственный
    процесс на 127.0.0.1:8443, сгенерированный сертификат ECDSA-P256,
    journal на диске.
treatment: {changed_factor: none, values: []}
invariants:
  - "Один ClientHello на прогон; payload построен из seed=42, TTL=64, split_offsets пусты."
  - "SNI=control.example, бюджет стартовых дефолтов, без превышений."
  - "Версия инструмента и конфиг не менялись между прогоном и разбором (tool 0.1.0-stage1 @ 65b79f6)."
budget:
  max_packets: 100
  max_bytes: 102400
  max_rate_pps: 10
  max_duration_s: 60
  stop_conditions:
    - приближение к лимиту
    - рост retransmissions
    - аномалия в канале
planned_wire_packets: >
  1 пакет: ClientHello, 141 байт, TTL 64, seq/ack из плана, checksum
  поля (0 = корректный для стека), запись в experiments/<id>/plan.yaml
  до отправки первого пакета (см. plan.yaml, packets=1).
actual_wire_validation: >
  Не выполнено: planned vs captured не сопоставлялось, поскольку PCAP
  не записывался (нет CAP_NET_RAW). Факт доставки подтверждён по
  журналу helper'а (event=client_hello, 141 байт в runner.log
  packet_sent). Offload и NAT по pcap не оценивались.
offload_and_nat: >
  Не оценивалось (нет pcap). NAT отсутствует (loopback); штампы
  helper'а совпадают с журналом runner'а с точностью до миллисекунды.
route_metadata: >
  loopback 127.0.0.1, без маршрутизации, MTU 65536 (ip -o link show lo).
schedule:
  repetitions: 1
  seed: 42
  inter_trial_gap_ms: 100
  state_reset: none
observations:
  client_pcap: null # не записывался: нет CAP_NET_RAW (см. Ограничения)
  server_pcap: null # не записывался: нет CAP_NET_RAW (см. Ограничения)
  helper_log: artifacts/h01-control-profile-2026-11/helper.log
  runner_log: artifacts/h01-control-profile-2026-11/runner.log
classification_rule: |
  Confirmed iff (1) the H01 classifier labels all six reference
  fixtures in testdata/ as their known causes (none, drop,
  rst_injection, tls_alert, modification, throttling) and (2) this
  control run delivers the planned ClientHello to the helper — the
  helper journals client_hello — within budget, with plan.yaml and
  run.json written. Refuted if any fixture label differs or the probe
  is not delivered. Inconclusive if fixtures or the run cannot be
  executed at all. Client and server PCAP capture is required evidence
  for a follow-up run with CAP_NET_RAW, not part of this rule: their
  absence here must be reported as a limitation, never as success.
results:
  observation: >
    Пункт (1): TestH01_ClassifyFixtures — 6/6 фикстур классифицированы
    по своей причине (control/complete_handshake→none,
    drop/client_hello_dropped→drop, rst_injection/rst_after_client_hello→rst_injection,
    tls_alert/handshake_failure_alert→tls_alert,
    modification/server_cipher_not_offered→modification,
    throttling/split_server_hello→throttling). Пункт (2): прогон
    2026-11-09T14:39:28Z–14:39:29Z внутри бюджета (1 пакет, 141 байт,
    1 с), helper заралогировал accept и client_hello (sni
    control.example, 9 cipher suites), plan.yaml и run.json записаны.
    Проба доставлена в пределах одного миллисекундного тика с
    отправкой. Событие handshake_failed (connection reset) через 500 ms
    после client_hello — следствие однонаправленного sender'а этапа 1:
    он закрывает сокет по settle, не отвечая на ServerHello; вмешательство
    исключено (loopback, собственный helper, lab отключён).
  compatible_hypotheses:
    - "H01: классификатор различает известные причины отказов и не выдаёт их за вмешательство DPI."
  excluded_hypotheses:
    - "Классификатор путает drop и rst_injection: исключено — причины различены на фикстурах, тест зелёный."
    - "Проба не доходит до helper'а: исключено — client_hello в журнале helper'а, доставка в пределах бюджета."
    - "handshake_failed — признак вмешательства: исключено — событие воспроизводится на loopback без lab и объясняется протоколом отправителя."
  inconclusive_reason: null
reproduce:
  tool_commit: "65b79f6"
  dependency_versions:
    github.com/google/gopacket: v1.1.19
    golang.org/x/net: v0.0.0-20190620200207-3b0461eec859
    golang.org/x/sys: v0.0.0-20190412213103-97732733099d
    gopkg.in/yaml.v3: v3.0.1
  config_file: experiments/h01-control-profile-2026-11/config.yaml
  date_utc: "2026-11-09"
  operator: Darya Nechaeva
  lab_config_id: control-unimpaired
  timestamps_utc: "2026-11-09T14:39:28Z — 2026-11-09T14:39:29Z"
artifacts:
  pcap_client: null # отсутствует: нет CAP_NET_RAW (см. Ограничения)
  pcap_server: null # отсутствует: нет CAP_NET_RAW (см. Ограничения)
  helper_log:
    sha256: f9731cbe33352e91fa81eb20e9943e2b0356d2b7ca031e58c4a85f275d92e621
    run_json_snapshot: >
      run.json содержит 14406230dfc2ae225df15d91526dca149beea85d2b79efcb091fd497bcdadf38 —
      снимок на момент run_complete; строка conn_closed была дописана
      helper'ом ~0.2 ms позже (гонка «хэширование лога внешнего
      процесса», см. Ограничения).
  runner_log:
    sha256: 9eb43fd73d8a7ee59be325147551eb581c20a577c5639214c652966eaab24cd0
---

## Наблюдения

- **Прогон.** 2026-11-09T14:39:28Z, tool 0.1.0-stage1 @ 65b79f6,
  оператор Darya Nechaeva, mode=valid-session, lab выключен
  (control-unimpaired), seed=42, репетиций 1.
- **runner.log.** `plan_written` (packets=1) →
  `capture_skipped` (point=client, не запрашивался) →
  `packet_sent` seq=1 repetition=1 bytes=141 → `run_complete`
  (packets=1, bytes=141).
- **helper.log.** `start`/`listening` (cert_sha256 0d80764d…) →
  `accept` conn_id=1 → `client_hello` sni=control.example version=0303
  cipher_suites=9 record_version=0301 → через ровно 500 ms
  `handshake_failed` («read: connection reset by peer») → `conn_closed`.
- **Разбор handshake_failed.** 500 ms — это окно settle, в течение
  которого соединение держится открытым (коммит 65b79f6). Sender
  этапа 1 однонаправленный: он не отвечает на ServerHello и закрывает
  сокет, из-за чего непрочитанные данные на стороне helper'а приводят
  к RST. До коммитов e8ddb8a/65b79f6 прогон рушился раньше: либо
  «no cipher suite supported by both» (генератор не предлагал
  ECDSA-шифры), либо «broken pipe» на стороне клиента.
- **Классификация фикстур.**
  `go test -count=1 -run TestH01_ClassifyFixtures -v ./internal/analyzer/`:
  6/6 PASS, каждая фикстура получила свою причину.
- **dpi-analyze (демонстрация CLI).** На фикстуре
  `testdata/control/complete_handshake.pcap` (config с той же
  `classification_rule`) вывод:

```json
{
  "cause": "none",
  "reason": "handshake and HTTP completed without anomalies",
  "client_addr": "192.0.2.10:51000",
  "server_addr": "192.0.2.200:8443",
  "packets": 12,
  "saw_client_hello": true,
  "saw_server_hello": true,
  "selected_cipher": "0x1301",
  "server_alert": false,
  "server_rst": false,
  "completed_http": true,
  "max_server_gap_ns": 2000000,
  "stream_gap": false
}
```

## Результаты и интерпретация

Правило `classification_rule` выполнено полностью: пункты (1) и (2) —
подтверждены, ни один пункт `Refuted`/`Inconclusive` не сработал.
Исход — **confirmed**: классификатор H01 различает все шесть
контрольных причин, а контрольный прогон доставляет пробу в
бюджете. Наблюдение `handshake_failed` отнесено к классу «свойство
отправителя», а не «вмешательство», — и это согласуется с целию
правила: классификатор и прогон вместе показывают, что инструмент не
выдаёт штатное поведение за DPI.

## Ограничения

- **Нет PCAP.** У оператора нет CAP_NET_RAW, поэтому критерий выхода
  этапа «два capture на управляемом примере» **не выполнен**; кадры
  `artifacts/…/client.pcap` и `server.pcap` отсутствуют. Это
  ограничение прогона, а не успех: следующий прогон должен быть
  выполнен на стенде с привилегиями (capture client + server,
  сравнение planned vs captured).
- **`actual_wire_validation` отложено.** Проверки offload/NAT/
  ретрансмиссий по pcap не проводились; доставка доказана только
  журналами обеих точек.
- **Handshake не завершается.** TLS-успех требует двунаправленного
  sender'а (ответы на ServerHello/ChangeCipherSpec) — вне рамок
  этапа 1; в журнале helper'а ожидаемо `handshake_failed`.
- **Гонка хэша helper.log.** runner хэширует журнал внешнего helper'а
  в момент `run_complete`, а helper дописывает `conn_closed` ~0.2 ms
  позже; в `run.json` зафиксирован снимок. Фактический финальный
  sha256 приведён в `artifacts.helper_log.sha256`.

## Update 2026-11-09T14:50Z

- Было: planned (статус не записывался до прогона); стало: confirmed.
- Причина: прогон выполнен 2026-11-09T14:39Z, оба пункта
  `classification_rule` подтверждены (фикстуры 6/6, доставка пробы и
  артефакты plan/run на месте); отчёт заполнен по данным runner.log,
  helper.log и run.json. Ограничение отсутствия PCAP зафиксировано в
  отдельной секции и в `results.observation`.
