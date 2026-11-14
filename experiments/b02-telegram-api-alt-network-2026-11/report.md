---
question_id: B02
experiment_id: b02-telegram-api-alt-network-2026-11
status: planned
hypothesis: TCP-соединение с одним и тем же адресом API Telegram может иметь другой исход при переключении на другую сеть.
alternative_hypotheses: [изменение доступности endpoint или потерь со временем, изменения WSL2 или NAT, неполный захват, другие изменения условий]
mode: valid-session
vantage: {network: другая сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 149.154.166.110, port: 443}
control: {profile: ранее выполненная одиночная TCP-попытка в исходной сети, experiment: b02-telegram-api-tcp-2026-11}
treatment: {changed_factor: сеть подключения, values: [исходная сеть, другая сеть]}
invariants: [один IPv4 и порт, одна попытка в каждой сети, tcp_only без данных приложения, порог первого повторного SYN, клиентский захват eth0]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Системный TCP handshake и закрытие; содержимое приложения не отправляется. Ядро определяет поля и сегментацию; runner сохраняет plan.yaml до подключения.
actual_wire_validation: null
offload_and_nat: WSL2 и NAT ограничивают выводы по клиентскому захвату; проверить offload до и после пробы. Переключение сети может изменить внешний NAT и маршрут.
route_metadata: После переключения сохранить вывод ip route get; одинаковый WSL-маршрут сам по себе не доказывает использование той же внешней сети.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 0, state_reset: none}
observations: {client_pcap: artifacts/b02-telegram-api-alt-network-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-telegram-api-alt-network-2026-11/runner.log}
classification_rule: Две одиночные TCP-попытки в разных сетях не отвечают на B02; B02 остаётся inconclusive. Фиксируется исход подключения без вывода о причине, месте вмешательства или доступности Telegram Web.
results: {observation: null, compatible_hypotheses: [], excluded_hypotheses: [], inconclusive_reason: null}
reproduce: {tool_commit: null, dependency_versions: null, config_file: experiments/b02-telegram-api-alt-network-2026-11/config.yaml, date_utc: null, operator: null, lab_config_id: null, timestamps_utc: null}
artifacts: {pcap_client: null, pcap_server: null}
---

## План

После переключения компьютера на другую сеть пользователь повторяет одну
обычную TCP-попытку к тому же адресу, что и в [исходной сети](../b02-telegram-api-tcp-2026-11/report.md).
Новая сеть, время, NAT и маршрут могут измениться одновременно, поэтому даже
различие исходов не устанавливает причину или место вмешательства. Успешный
TCP-handshake также не гарантирует завершение TLS или доступность Web.

Повторный SYN останавливает серию автоматически, но другие TCP-повторы этот
счётчик не распознаёт. Оператор наблюдает пакеты в отдельном терминале через
`tcpdump -nn -tt -S -l`, отслеживает повторение последовательностей исходящих
сегментов и при повторе или аномалии прерывает runner через Ctrl+C. Захват и
ручное прерывание асинхронны; уже отправленные пакеты не отзываются.

До запуска проверить отсутствие адреса в `docs/DO_NOT_SCAN.md`; пока файла нет,
нужно явное подтверждение пользователя на эту серию. Контакт Telegram для
сообщения об уязвимости указан в отчёте предыдущего пилота. PCAP и журнал —
вне git, каталог 0700, файлы 0600. Результатов пока нет.
