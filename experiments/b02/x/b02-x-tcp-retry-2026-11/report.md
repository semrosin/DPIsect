---
question_id: B02
experiment_id: b02-x-tcp-retry-2026-11
status: inconclusive
hypothesis: TCP-соединение с выбранным DNS-адресом x.com может установиться.
alternative_hypotheses: [потери или отказ на маршруте, локальная проблема или ошибка захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: определяется перед запуском}
endpoint: {role: target, ip: 172.66.0.227, port: 443}
control: {profile: одиночное TCP-соединение без данных приложения}
treatment: {changed_factor: нет, values: []}
invariants: [один адрес, один порт, одно соединение, системный TCP]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Системный TCP handshake и закрытие без данных приложения; поля задаёт ядро, runner сохраняет plan.yaml до подключения.
actual_wire_validation: В клиентском захвате SYN, SYN-ACK, ACK и закрытие; семь пакетов, потерь захвата нет.
offload_and_nat: WSL2 и NAT ограничивают выводы захвата; состояние offload записывается перед пробой.
route_metadata: После пробы маршрут через eth0 и 172.26.0.1; маршрут непосредственно перед пробой не представлен.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 0, state_reset: none}
observations: {client_pcap: artifacts/b02-x-tcp-retry-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-x-tcp-retry-2026-11/runner.log}
classification_rule: Одно TCP-соединение не отвечает на B02; фиксируется исход подключения без вывода о причине или месте вмешательства и доступности сайта.
results: {observation: TCP установился и закрылся без прикладных данных, compatible_hypotheses: [адрес отвечал на TCP в момент пробы], excluded_hypotheses: [], inconclusive_reason: SNI не передавался; проверка B02 не проводилась.}
reproduce:
  tool_commit: 'unknown'
  dependency_versions:
    github.com/google/gopacket: v1.1.19
    golang.org/x/net: v0.0.0-20190620200207-3b0461eec859
    golang.org/x/sys: v0.0.0-20190412213103-97732733099d
    gopkg.in/yaml.v3: v3.0.1
  config_file: experiments/b02/x/b02-x-tcp-retry-2026-11/config.yaml
  date_utc: '2026-11-14'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-14T13:35:40.534877958Z — 2026-11-14T13:35:41.016701307Z'
  run_json: experiments/b02/x/b02-x-tcp-retry-2026-11/run.json
artifacts:
  pcap_client: {sha256: 738148f04efb9837b649dbfa6366e2e599b5fc8ba4afacc2a70c762b138e7a65}
  pcap_server: null
  runner_log: {sha256: 24387a8159c999ab91a1c3a3f943327314b3983d669ce372a2e7eac50fd1df74}
  observations: {sha256: 19a110850a7614b18ff48356b1c4ad7be1cee1c1dc74b6efeb57e2aef1d34e7d}
  wire_plan: {sha256: 0e9dbb40f54ca7ee2456b052866374e65189adb216a9e5c4d55291fcb6c66dcb}
  config: {sha256: a3e25bb1d1bcf2cb15a68e1b5fc4046c22e11bf748cdf5d1eb13f94a842599e9}
  run_json: {sha256: 1bad4a54c352a3cc870808984afb3de242c65d054828b9d55bd7f2b05d46f094}
---

## План

Пользователь получил IPv4 `172.66.0.227` через системный DNS для `x.com`.
Одна попытка ограничивает нагрузку, но не позволяет оценить другие адреса.
SNI в TCP-контроле не передаётся. Результат не определяет причину сбоев.

До запуска проверить `docs/DO_NOT_SCAN.md`, если он появился. Пользователь
подтвердил проверку X и самостоятельно выполняет сетевые команды. При
обнаружении уязвимости остановиться; канал сообщения —
[центр помощи X](https://help.x.com/en/rules-and-policies/reporting-security-vulnerabilities).
PCAP и логи сохраняются вне git. Оператор следит за повторами TCP в отдельном
терминале и останавливает серию по Ctrl+C при повторной передаче, аномалии или
проблеме захвата; повтор SYN также останавливает runner автоматически.

## Update 2026-11-14T13:35:41Z

- Было: `planned`; стало: `inconclusive` для B02.
- Причина: TCP успешно установился; SNI не передавался, влияние имени не исследовано.
  Runner зафиксировал 7 кадров, 478 байт, 0 повторных SYN и 0 потерь захвата.
  Метаданные и остальные хэши сохранены в `run.json`. После пробы TSO, GSO,
  GRO были включены, LRO выключен; состояние непосредственно до пробы неизвестно.
