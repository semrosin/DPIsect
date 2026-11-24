---
question_id: C01
experiment_id: c01-youtube-split-2026-11
status: inconclusive
hypothesis: "Клиентский симптом может меняться при разбиении ClientHello перед SNI."
alternative_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
mode: valid-session
vantage: {network: WSL2, address_family: IPv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {observation: "попытка не началась"}
treatment: {intended_split: 110, sni_start: 110}
invariants: ["TLS record 260 байт", "SNI www.youtube.com", "профиль B01"]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1}
planned_wire_packets: plan.yaml
actual_wire_validation: "Точный ClientHello из плана наблюдался в двух сегментах длиной 110 и 150 байт, затем повтор второго диапазона."
offload_and_nat: "TSO, GSO, GRO и LRO включены по выводу оператора; WSL2/NAT и offload ограничивают вывод о физической линии."
route_metadata: "eth0, источник 172.26.1.205"
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/c01-youtube-split-2026-11/client.pcap, runner_log: artifacts/c01-youtube-split-2026-11/runner.log, observations: artifacts/c01-youtube-split-2026-11/sni-observations.json}
classification_rule: "См. config.yaml и plan.yaml."
results:
  observation: "TCP установлен, ClientHello отправлен в двух сегментах, через 215,958 мс повторён второй; после ClientHello входящих кадров нет."
  compatible_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
  excluded_hypotheses: []
  inconclusive_reason: "Контроль в этой серии не запущен, доставку endpoint клиентский захват не подтверждает."
reproduce: {tool_commit: unknown, tool_version: dev, config_file: config.yaml, date_utc: "2026-11-20", operator: qjolk, metadata: run.json}
artifacts:
  pcap_client: {sha256: e911a7235668f4b1903912e0a296ae7c62a9eaabe4e0c704254d7944c3e7158c}
  runner_log: {sha256: f07512e2c279edc260f2a2a4b58ecb070a194ca53eb70c403b12628492fc78c9}
  observations: {sha256: 588749bcfe459d08cbf0d83d322f7edd23365a045be56e639411969164282220}
  review: {path: artifacts/c01-youtube-split-2026-11/review.json, sha256: 50350c3c907a13c5569827f6003233885ce45c77a8d267616e5dc6125dc40acb}
---

Пользователь запустил серию 20 ноября 2026 года в 17:06 UTC. По PCAP
разбиение в точке 110 совпало с планом, байты ClientHello совпали.
После полной отправки входящих кадров не было. Повтор второго сегмента
остановил монитор, поэтому контрольная попытка не запускалась.

Это первый наблюдённый вариант с разбиением перед SNI на том же endpoint
и с тем же управляемым профилем, что в опытах B01. В этих опытах
ClientHello без разбиения также повторялся без входящего ответа. Новая
попытка отличается случайными TLS-полями, временем и условиями offload.
Статус соответствует заранее записанному правилу, причинный вывод и
частота симптома не установлены.

В run.json указан tool_commit: unknown, поскольку бинарь собран без
передачи commit через ldflags. Артефакты сверены по хэшам.

## Errata 2026-11-24

В сохранённых конфигурации, расписании, плане и журнале первая
сегментированная попытка помечена runner как control, а в этом отчёте
она названа treatment. Это несоответствие меток. Фактическая TCP-граница,
плановые байты и наблюдение по PCAP остаются прежними. Второй вариант
внутри этой серии не запускался. Исторические файлы не изменены.

## Сверка файлов 2026-11-24

- plan.yaml — SHA-256 5041da5cc57e067ad26b9c288f0d4949f84158a66033b8cbdcdaa052bc980f36
- config.yaml — SHA-256 21a92901fa47851e544cce6be26352b01e7198bc90a6b0907ba693cf457cf668
- sni-schedule.yaml — SHA-256 81ad9fd358c6871c76fa804d3de25d4098e406364ce0116d989da4c0f0f25071

Хэши вычислены после опыта и не подтверждают время создания файлов.
