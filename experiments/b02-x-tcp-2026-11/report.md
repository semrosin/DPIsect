---
question_id: B02
experiment_id: b02-x-tcp-2026-11
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
actual_wire_validation: Не выполнялась.
offload_and_nat: WSL2 и NAT ограничивают выводы захвата; состояние offload записывается перед пробой.
route_metadata: Определяется перед запуском.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 0, state_reset: none}
observations: {client_pcap: artifacts/b02-x-tcp-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-x-tcp-2026-11/runner.log}
classification_rule: Одно TCP-соединение не отвечает на B02; фиксируется исход подключения без вывода о причине или месте вмешательства и доступности сайта.
results: {observation: не выполнено, compatible_hypotheses: [], excluded_hypotheses: [], inconclusive_reason: захват не запустился; сетевых измерений нет}
reproduce: {tool_commit: null, dependency_versions: null, config_file: experiments/b02-x-tcp-2026-11/config.yaml, date_utc: null, operator: null, lab_config_id: null, timestamps_utc: null}
artifacts: {pcap_client: null, pcap_server: null}
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

## Update 2026-11-14T13:13:31Z

- Было: `planned`; стало: `inconclusive`.
- Причина: захват не запустился с ошибкой `operation not permitted`, до
  TCP-подключения дело не дошло. `/tmp` смонтирован с `nosuid`, поэтому
  capability исполняемого файла в этом каталоге не вступает в действие.
