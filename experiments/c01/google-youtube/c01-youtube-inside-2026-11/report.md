---
question_id: C01
experiment_id: c01-youtube-inside-2026-11
status: inconclusive
hypothesis: "Разделение ClientHello внутри SNI может изменить клиентский симптом."
alternative_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
mode: valid-session
vantage: {network: WSL2, address_family: IPv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {observation: "в этой серии попытка не началась"}
treatment: {intended_split: 117, sni_range: "[110, 125)"}
invariants: ["TLS record 260 байт", "SNI www.youtube.com", "профиль B01"]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1}
planned_wire_packets: plan.yaml
actual_wire_validation: "Точный ClientHello из плана наблюдался в сегментах 117 и 143 байта, затем повтор второго диапазона."
offload_and_nat: "TSO, GSO, GRO и LRO включены по выводу оператора; WSL2/NAT и offload ограничивают вывод о физической линии."
route_metadata: "eth0, источник 172.26.1.205"
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/c01-youtube-inside-2026-11/client.pcap, runner_log: artifacts/c01-youtube-inside-2026-11/runner.log, observations: artifacts/c01-youtube-inside-2026-11/sni-observations.json}
classification_rule: "См. config.yaml и plan.yaml."
results:
  observation: "TCP установлен, ClientHello разделён внутри SNI, через 47,181 мс повторён второй сегмент; после ClientHello входящих кадров нет."
  compatible_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
  excluded_hypotheses: []
  inconclusive_reason: "Контроль в этой серии не запущен, доставку endpoint клиентский захват не подтверждает."
reproduce: {tool_commit: 2517b8dbccf0f6a12040806b15bedb27df92e172, tool_version: c01-pilot, config_file: config.yaml, date_utc: "2026-11-20", operator: qjolk, metadata: run.json}
artifacts:
  pcap_client: {sha256: f3ea57158303cad87e2c0c0f00d1056e6d4fb15d3a4dde2e98fa50137c074da2}
  runner_log: {sha256: d0e8fb8580eced08f4ac3337f2ce90af7b6ec3230bda0efdbc7a47b6495209f2}
  observations: {sha256: 1e782663cda5a64bf88472937bf257e38e3ecc5fd5dd6dd9ede51c78c8ccc6d9}
  review: {path: artifacts/c01-youtube-inside-2026-11/review.json, sha256: 768dc4d5d0332a5272fc66d45110a9149f629936ba624d2f0988ae89101274f2}
---

Пользователь запустил серию 20 ноября 2026 года в 17:13 UTC. PCAP
подтверждает байты плана и границу внутри имени SNI. После отправки
ClientHello входящих кадров не было. Повтор второго сегмента остановил
монитор, поэтому следующая попытка не запускалась.

Тот же симптом наблюдался в отдельных опытах без разбиения и с
[границей перед SNI](../c01-youtube-split-2026-11/report.md). Случайные
поля TLS и время попыток различались. По одной попытке каждого варианта
частота и причина симптома не установлены.
