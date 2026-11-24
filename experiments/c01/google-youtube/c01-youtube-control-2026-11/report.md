---
question_id: C01
experiment_id: c01-youtube-control-2026-11
status: inconclusive
hypothesis: "Симптом может зависеть от разбиения ClientHello."
alternative_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
mode: valid-session
vantage: {network: WSL2, address_family: IPv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {intended_split: none}
treatment: {observation: "в этой серии попытка не началась"}
invariants: ["TLS record 260 байт", "SNI www.youtube.com", "профиль B01"]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1}
planned_wire_packets: plan.yaml
actual_wire_validation: "Полный ClientHello из плана виден в одном TCP-сегменте и повторён целиком."
offload_and_nat: "Отдельный снимок перед контрольной серией отсутствует. В предыдущей серии TSO, GSO, GRO и LRO были включены; WSL2/NAT ограничивают вывод о линии."
route_metadata: "eth0, источник 172.26.1.205"
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/c01-youtube-control-2026-11/client.pcap, runner_log: artifacts/c01-youtube-control-2026-11/runner.log, observations: artifacts/c01-youtube-control-2026-11/sni-observations.json}
classification_rule: "См. config.yaml и plan.yaml."
results:
  observation: "TCP установлен, ClientHello виден в одном сегменте, затем через 264,639 мс повторён без входящих кадров после него."
  compatible_hypotheses: ["потери", "обработка сервером", "сетевое вмешательство", "особенности захвата"]
  excluded_hypotheses: []
  inconclusive_reason: "Исследуемая попытка в этой серии не запущена, доставку endpoint клиентский захват не подтверждает."
reproduce: {tool_commit: unknown, tool_version: dev, config_file: config.yaml, date_utc: "2026-11-20", operator: qjolk, metadata: run.json}
artifacts:
  pcap_client: {sha256: 5cbf3d766c099bc03028338f2111c6e4b93d79bfc13bbf3ac779137e0883c829}
  runner_log: {sha256: 6e2fd35ecd0881953bcf0408c067d9788d6a8de7b894d1098bc7c11c34abea9e}
  observations: {sha256: db9284ed1b1e482be3259d6a4ab56122f35772319626b2e312e562dc60e02761}
  review: {path: artifacts/c01-youtube-control-2026-11/review.json, sha256: 2dd275b88b4a659b1fa3d1386c2ea33a8843706e56a058ed39612a717d8bb669}
---

Пользователь запустил серию 20 ноября 2026 года в 17:09 UTC. Повтор
первого ClientHello остановил монитор до следующей попытки.

В отдельной [серии с разбиением](../c01-youtube-split-2026-11/report.md)
при том же IP и TLS-профиле также наблюдался повтор без входящего ответа.
Случайные поля TLS и время попыток различались. Одной пары недостаточно
для оценки вероятности или причинного вывода. Клиентский PCAP не
подтверждает доставку серверу.

В run.json указан tool_commit: unknown, поскольку бинарь собран без
передачи commit через ldflags. Хэши артефактов сверены.

## Дополнение 2026-11-24

В этой серии первая попытка с одним сегментом помечена runner как control.
В остальных трёх сериях control обозначал сегментированную первую попытку.
См. errata в соответствующих отчётах.

## Сверка файлов 2026-11-24

- plan.yaml — SHA-256 cd1c55638b90f0965384febb5d3afa9b83ade4eba5053442126f4a4e04af4181
- config.yaml — SHA-256 3e0316b9f05a7fc17088e05944d29d7153052e0a231a43d9414a0bcad81b7396
- sni-schedule.yaml — SHA-256 153c0d6ba6520c6d99d7a6e9f7ac57a3fa0f123758e5d8a1dc12d1ec47d0caee

Хэши вычислены после опыта и не подтверждают время создания файлов.
