---
question_id: B02
experiment_id: b02-google-youtube-sni-retry-2026-11
status: planned
hypothesis: На одном адресе Google обычные TLS-подключения с именами www.google.com и www.youtube.com могут иметь разные исходы.
alternative_hypotheses: [различная обработка имён сервером или сертификатом, потери и изменения состояния сети, отличия ClientHello и их размеров, проблемы WSL2 или захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {sni: www.google.com, note: принятие имени сервером и сертификат на данном endpoint заранее не проверены}
treatment: {changed_factor: имя SNI, values: [www.youtube.com]}
invariants: [один IPv4 и порт, обычный TLS-клиент Go с проверкой сертификата, отдельное TCP-соединение, одинаковый режим таймаутов и интерфейс]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Runner создаёт plan.yaml с точными байтами обоих ClientHello до первого подключения. Сегментация и ретрансляции управляются ядром; последующие TLS-пакеты зависят от ответа.
actual_wire_validation: null
offload_and_nat: WSL2 и NAT ограничивают выводы клиентского захвата; проверить и отключить offload перед пробой и восстановить исходное состояние после неё.
route_metadata: До запуска проверить маршрут к endpoint и интерфейс захвата.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/b02-google-youtube-sni-retry-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-google-youtube-sni-retry-2026-11/runner.log}
classification_rule: Пилот из двух подключений не отвечает на полный вопрос B02. Фиксируются исходы TCP и TLS, проверка сертификата, размеры ClientHello и ограничения захвата; B02 остаётся inconclusive.
results: {observation: null, compatible_hypotheses: [], excluded_hypotheses: [], inconclusive_reason: null}
reproduce: {tool_commit: null, dependency_versions: null, config_file: experiments/b02-google-youtube-sni-retry-2026-11/config.yaml, date_utc: null, operator: null, lab_config_id: null, timestamps_utc: null}
artifacts: {pcap_client: null, pcap_server: null}
---

## План и ограничения

Системный DNS пользователя вернул `142.251.155.119` для `www.google.com`;
в списке адресов `www.youtube.com` этот IPv4 отсутствовал. Сервер может как
принять второе имя, так и отказать ему или выдать неподходящий сертификат;
это не установлено до опыта. [Предыдущая попытка](../b02-google-youtube-sni-pilot-2026-11/report.md)
остановлена счётчиком частоты до YouTube; здесь скорость считается по
исходящим пакетам, общий бюджет — по обоим направлениям. Одна пара — пилот
выполнимости, не достаточная выборка для устойчивого вывода или полной
матрицы B02. Имена различаются по длине; одинаковая длина и идентичность
ClientHello не гарантируются.

Устанавливаются только TLS-соединения без HTTP-запроса, поэтому успешный TLS
не доказывает доступность сайта. Различие исходов не отделяет поведение сервера
от вмешательства сети. Автоматический лимит 90% частоты исходящих пакетов
может прервать даже первое подключение; capture асинхронен и не измеряет
физическую линию.

Повторный SYN останавливает серию автоматически, но другие TCP-повторы этот
счётчик не распознаёт. Оператор наблюдает пакеты в отдельном терминале через
`tcpdump -nn -tt -S -l`, отслеживает повторение последовательностей исходящих
сегментов и при повторе или аномалии прерывает runner через Ctrl+C. Захват и
ручное прерывание асинхронны; уже отправленные пакеты не отзываются.

До запуска проверить отсутствие адреса в `docs/DO_NOT_SCAN.md`; пока файла нет,
нужно явное подтверждение пользователя на эту серию. При обнаружении
уязвимости контакт — [Google Bug Hunters](https://bughunters.google.com/report).
PCAP и журнал — вне git, каталог 0700, файлы 0600. Результатов пока нет.
