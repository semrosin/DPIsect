---
question_id: B02
experiment_id: b02-telegram-api-tcp-2026-11
status: planned
hypothesis: TCP-соединение с выбранным адресом API Telegram может установиться.
alternative_hypotheses: [потери или отказ на маршруте, локальная проблема или ошибка захвата]
mode: valid-session
vantage: {network: WSL2 пользователя, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 149.154.166.110, port: 443}
control: {profile: одиночное TCP-соединение без данных приложения}
treatment: {changed_factor: нет, values: []}
invariants: [один адрес, один порт, одно соединение, системный TCP]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Системный TCP handshake и закрытие; содержимое приложения не отправляется. Ядро определяет поля и сегментацию; runner сохраняет plan.yaml до подключения.
actual_wire_validation: null
offload_and_nat: WSL2 и внешний NAT ограничивают выводы по клиентскому захвату; перед запуском проверить и отключить offload, после восстановить прежние значения.
route_metadata: Проверить маршрут непосредственно перед запуском.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 0, state_reset: none}
observations: {client_pcap: artifacts/b02-telegram-api-tcp-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-telegram-api-tcp-2026-11/runner.log}
classification_rule: Одно TCP-соединение не отвечает на B02; B02 остаётся inconclusive. Фиксируется исход подключения без вывода о причине, месте вмешательства или доступности Telegram Web.
results: {observation: null, compatible_hypotheses: [], excluded_hypotheses: [], inconclusive_reason: null}
reproduce: {tool_commit: null, dependency_versions: null, config_file: experiments/b02-telegram-api-tcp-2026-11/config.yaml, date_utc: null, operator: null, lab_config_id: null, timestamps_utc: null}
artifacts: {pcap_client: null, pcap_server: null}
---

## План

Адрес `149.154.166.110` пользователь получил при системном разрешении
`api.telegram.org`. Его текущая доступность и пригодность для Telegram Web
не установлены. Одна попытка ограничивает нагрузку и не образует достаточной
выборки для вывода об адресах Telegram в целом.

Повторный SYN останавливает серию автоматически, но другие TCP-повторы этот
счётчик не распознаёт. Оператор наблюдает пакеты в отдельном терминале через
`tcpdump -nn -tt -S -l`, отслеживает повторение последовательностей исходящих
сегментов и при повторе или аномалии прерывает runner через Ctrl+C. Захват и
ручное прерывание асинхронны; уже отправленные пакеты не отзываются.

До запуска проверить отсутствие адреса в `docs/DO_NOT_SCAN.md`; пока файла нет,
нужно явное подтверждение пользователя на эту серию. Контакт Telegram для
сообщения об уязвимости указан в отчёте предыдущего пилота. PCAP и журнал —
вне git, каталог 0700, файлы 0600. Результатов пока нет.
