---
question_id: C01
experiment_id: c01-youtube-after-2026-11
status: inconclusive
hypothesis: "Разделение ClientHello после SNI может изменить клиентский симптом."
alternative_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
mode: valid-session
vantage: {network: WSL2, address_family: IPv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {observation: "в этой серии попытка не началась"}
treatment: {intended_split: 126, sni_range: "[110, 125)"}
invariants: ["TLS record 260 байт", "SNI www.youtube.com", "профиль B01"]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1}
planned_wire_packets: plan.yaml
actual_wire_validation: "Точный ClientHello из плана наблюдался в сегментах 126 и 134 байта, затем повтор второго диапазона."
offload_and_nat: "TSO, GSO, GRO и LRO включены по выводу оператора; WSL2/NAT и offload ограничивают вывод о физической линии."
route_metadata: "eth0, источник 172.26.1.205"
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/c01-youtube-after-2026-11/client.pcap, runner_log: artifacts/c01-youtube-after-2026-11/runner.log, observations: artifacts/c01-youtube-after-2026-11/sni-observations.json}
classification_rule: "См. config.yaml и plan.yaml."
results:
  observation: "TCP установлен, ClientHello разделён после SNI, через 123,708 мс повторён второй сегмент; после ClientHello входящих кадров нет."
  compatible_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
  excluded_hypotheses: []
  inconclusive_reason: "Контроль в этой серии не запущен, доставку endpoint клиентский захват не подтверждает."
reproduce: {tool_commit: a998f04ac49d0939a120fc3434b271091e1a7ef0, tool_version: c01-pilot, config_file: config.yaml, date_utc: "2026-11-20", operator: qjolk, metadata: run.json}
artifacts:
  pcap_client: {sha256: 71732bc0e4bd380e4f8bb875f0ce2098927fa673db27cfe0b2bb1c9fab239535}
  runner_log: {sha256: bc11ae6fa826f180af06ad4ffa164295f1c9931c9e4bb51e6bfc023032c473e4}
  observations: {sha256: 40cd18a75d07da2db0d346eb330410fada7b6fe76a4aaa70d03be0e98994784d}
  review: {path: artifacts/c01-youtube-after-2026-11/review.json, sha256: 0ffd76242e506dbff0e3d2ca2f6d5a560dd5522b77c7ed8ada0a70a50a1f4ad6}
---

Пользователь запустил серию 20 ноября 2026 года в 17:14 UTC. PCAP
подтверждает байты плана и границу после имени SNI. После отправки
ClientHello входящих кадров не было. Повтор второго сегмента остановил
монитор, поэтому следующая попытка не запускалась.

## Errata 2026-11-24

В сохранённых конфигурации, расписании, плане и журнале первая
сегментированная попытка помечена runner как control, а в этом отчёте
она названа treatment. Это несоответствие меток. Фактическая TCP-граница,
плановые байты и наблюдение по PCAP остаются прежними. Второй вариант
внутри этой серии не запускался. Исторические файлы не изменены.

## Сверка файлов 2026-11-24

- plan.yaml — SHA-256 af09fbd1fb486ca58cff19f1895bb4fd03068ca42bea7ac21b1fa33ffed83256
- config.yaml — SHA-256 23b8871b5d8670d7516ae3c07312f9e3b9cac0a5f369fc9c08f3cc68ceb83c87
- sni-schedule.yaml — SHA-256 547bd4ecda90c9410f692f6294c5aada21a8e8af9db2e576f4cff6c8037245f2

Хэши вычислены после опыта и не подтверждают время создания файлов.
