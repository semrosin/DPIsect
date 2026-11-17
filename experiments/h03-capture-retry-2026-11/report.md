---
question_id: H03
experiment_id: h03-capture-retry-2026-11
status: confirmed
hypothesis: >
  На loopback оба capture сохраняют плановый ClientHello, а локальный
  helper регистрирует его получение.
alternative_hypotheses:
  - Один из capture не сохраняет плановые байты.
  - Helper не получает ClientHello.
  - Прогон или захват аварийно завершается.
mode: valid-session
vantage: {network: loopback, address_family: ipv4, capture_point: lo}
endpoint: {role: lab, ip: 127.0.0.1, port: 18443}
control: {profile: loopback-unimpaired, lab_enabled: false}
treatment: {changed_factor: none, values: []}
invariants: ["Одна проба, SNI control.example, seed 42"]
budget:
  max_packets: 100
  max_bytes: 102400
  max_rate_pps: 10
  max_duration_s: 60
  stop_conditions: ["Ctrl+C", "приближение к лимиту", "рост повторных передач", "аномалия"]
  note: >
    Runner считает записи и байты payload, а не все пакеты TCP. В клиентском
    PCAP видно 18 кадров по порту опыта, включая дубли loopback; весь PCAP
    содержит 129 кадров, включая посторонний трафик интерфейса.
planned_wire_packets: >
  Одна запись ClientHello размером 141 байт; реальные TCP-поля выбирает
  ядро. План записан в plan.yaml перед отправкой.
actual_wire_validation: >
  Плановый ClientHello найден целиком в каждом PCAP; сопоставление
  физических полей и захват после NIC не выполнялись.
offload_and_nat: Не оценивались; loopback не является физической линией.
route_metadata: Локальный интерфейс lo, MTU 65536, внешний маршрут отсутствует.
schedule: {repetitions: 1, seed: 42, inter_trial_gap_ms: 100, state_reset: none}
observations:
  client_pcap: artifacts/h03-capture-retry-2026-11/client.pcap
  server_pcap: artifacts/h03-capture-retry-2026-11/server.pcap
  helper_log: artifacts/h03-capture-retry-2026-11/helper.log
  runner_log: artifacts/h03-capture-retry-2026-11/runner.log
classification_rule: >
  Для локального контроля confirmed, если оба PCAP содержат плановый
  ClientHello и helper записал приём; refuted при доказанном расхождении;
  иначе inconclusive. Два capture на loopback не подтверждают внешнюю линию.
results:
  observation: >
    В обоих PCAP найдены 141 байт ClientHello из плана; в каждом по два
    соответствующих кадра. Helper зарегистрировал client_hello. Runner
    завершился с кодом 0, stderr helper пуст; код helper не сохранён.
    Серверный PCAP дописывался
    после снимка хэша в run.json; окончательный хэш записан отдельно.
  compatible_hypotheses:
    - Локальный приём и два экземпляра захвата работают на данном примере.
  excluded_hypotheses:
    - Helper не получил ClientHello в данном запуске.
    - Плановые байты отсутствуют в любом из двух итоговых PCAP.
  inconclusive_reason: null
reproduce:
  tool_commit: working-tree-cadd3f0
  tool_version: 0.1.0-stage1-capture-fix
  tool_commit_note: >
    Бинарники собраны из рабочего дерева на базе cadd3f0 с незакоммиченным
    исправлением capture; идентификатор не является хэшем коммита.
  capture_source_sha256: b7462c5c749f9e73549e1ea14f618311cfd4fba38ba21b19274411c8f244e337
  capture_fix_commit: 22c6321
  prober_binary_sha256: 04de2832fc7b1a765130a50930899f5d7980b409637a63f62a3189a1f9a611bb
  helper_binary_sha256: 0a1f265b53437d67767643b12b8b0f8cf48dbe4ecef5d7d4a0f145431f8566eb
  dependency_versions:
    github.com/google/gopacket: v1.1.19
    golang.org/x/net: v0.0.0-20190620200207-3b0461eec859
    golang.org/x/sys: v0.0.0-20190412213103-97732733099d
    gopkg.in/yaml.v3: v3.0.1
  config_file: experiments/h03-capture-retry-2026-11/config.yaml
  date_utc: '2026-11-10'
  operator: qjolk
  lab_config_id: loopback-unimpaired
  timestamps_utc: '2026-11-10T16:17:08Z–16:17:09Z'
  run_json: experiments/h03-capture-retry-2026-11/run.json
artifacts:
  final_hash_manifest: experiments/h03-capture-retry-2026-11/final-sha256.txt
  pcap_client_sha256: 31d479732a4a3fac4b2be58ff4bd8a4b3e74486ce4d5caa476ad007efa931e76
  pcap_server_final_sha256: ede11867f70289547cc5eef760155c93d2566732a70df3cb62941937844a1565
  pcap_server_run_json_snapshot_sha256: 146d0e33cb4fccca174e7335d4c4b3a088e3de5e9f9e73f706327efd8ba789cf
  helper_log_sha256: 299fb48bb8f7c9f38aa4c9a41eafd940a98ea6e984873490741b28f7891f83b1
  runner_log_sha256: e369169180e9dc4dc55f09399a6da04916fa5d75a672eeda4e7652ab23490bb0
---

## Результат

Пользователь выполнил повтор после исправления capture. Спланированный
ClientHello целиком найден в клиентском и серверном файлах, helper
зафиксировал его приём. Код возврата runner — 0; stderr helper пуст,
но скрипт не сохранил его код завершения. Для заранее записанного
**локального** правила исход `confirmed`.
Это не подтверждает полный H03 на физической линии: оба capture работают
на `lo`, NAT и offload не исследовались, TLS-handshake не завершался.

Runner хэширует файл server.pcap, пока внешний helper ещё пишет его.
Хэш в исходном `run.json` относится к промежуточному снимку и не совпадает
с окончательным файлом. Исходный `run.json` сохранён без изменений;
проверяемые итоговые хэши после остановки helper находятся в
`final-sha256.txt`. Это ограничение автоматической фиксации артефактов,
которое ещё нужно устранить. Сырые файлы вне git содержат и посторонний
трафик loopback.

## Update 2026-11-10T16:17:50Z

- Было: `planned`; стало: `confirmed` для локального правила.
- Причина: оба PCAP содержат плановые байты, helper зарегистрировал приём,
  пробер завершился с кодом 0. Ограничения и хэши указаны выше.
