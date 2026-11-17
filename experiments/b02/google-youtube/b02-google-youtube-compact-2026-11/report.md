---
question_id: B02
experiment_id: b02-google-youtube-compact-2026-11
status: planned
hypothesis: На одном адресе Google обычные TLS-подключения с именами www.google.com и www.youtube.com могут иметь разные исходы.
alternative_hypotheses: [различная обработка имён сервером или сертификатом, потери и состояние сети, отличия ClientHello и их размеров, особенности WSL2 или захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {sni: www.google.com, note: адрес получен пользователем из системного DNS 14 ноября; доступность может измениться}
treatment: {changed_factor: имя SNI, values: [www.youtube.com]}
invariants: [один IPv4 и порт, обычный TLS-клиент Go с проверкой сертификата, отдельное TCP-соединение, одинаковая пауза после TCP, одинаковый режим таймаутов и интерфейс]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, повтор исходящих данных или FIN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Runner создаёт plan.yaml с байтами ClientHello до первого подключения. Системный TCP выбирает поля и сегментацию; TLS после ClientHello зависит от ответа.
actual_wire_validation: null
offload_and_nat: WSL2 и NAT ограничивают выводы клиентского захвата; исходные настройки offload сохраняются и восстанавливаются скриптом.
route_metadata: Перед запуском скрипт проверяет маршрут к endpoint и записывает вывод пользователю.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none, client_hello_delay_ms: 1100}
observations: {client_pcap: artifacts/b02-google-youtube-compact-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-google-youtube-compact-2026-11/runner.log}
classification_rule: Пилот из двух подключений не отвечает на полный вопрос B02. Фиксируются исходы TCP и TLS, проверка сертификата, размеры ClientHello и ограничения захвата; B02 остаётся inconclusive.
results: {observation: null, compatible_hypotheses: [], excluded_hypotheses: [], inconclusive_reason: null}
reproduce: {tool_commit: null, dependency_versions: null, config_file: experiments/b02/google-youtube/b02-google-youtube-compact-2026-11/config.yaml, date_utc: null, operator: null, lab_config_id: null, timestamps_utc: null}
artifacts: {pcap_client: null, pcap_server: null}
---

## План и ограничения

Одна пара — пилот выполнимости. Между TCP-handshake и ClientHello для каждого
имени запланирована одинаковая пауза 1,1 секунды. Пауза меняет тайминг и не
гарантирует соблюдение лимита частоты. Для обеих попыток задан
`GODEBUG=tlsmlkem=0`: гибридные ML-KEM группы отключены только в процессе
опыта. Локальная подготовка без сети дала ClientHello длиной 292 и 293 байта
соответственно. Обычный TLS не проверяет доступность
сайта без HTTP; разные имена могут обрабатываться сервером по-разному и
порождают ClientHello разной длины. Односторонний захват не позволяет
отделить сетевое вмешательство от ответа сервера.

Монитор останавливает серию при повторном SYN, исходящих данных или FIN,
ошибке захвата или достижении порога бюджета. После закрытия сокета ядро может
продолжить ретрансляции за пределами окна захвата. Дубли захвата могут вызвать
раннюю остановку, а асинхронный монитор не отменяет уже отправленные пакеты.

До запуска проверить `docs/DO_NOT_SCAN.md`; пока файла нет, необходимо явное
подтверждение пользователя на серию. Канал сообщения об уязвимости —
[Google Bug Hunters](https://bughunters.google.com/report). Сырые PCAP и
журналы — вне Git. Результатов пока нет.

`run.sh` запускается пользователем: он проверяет маршрут и отсутствие ранее
созданных файлов, отключает offload, выдаёт capability одному проберу и
восстанавливает исходные настройки при обычном выходе, SIGINT или SIGTERM.
Если список Do Not Scan появился, скрипт останавливается до подключения.
Скрипт фиксирует TLS-профиль через `GODEBUG=tlsmlkem=0` и не проверяет
актуальность сохранённого DNS-ответа от 14 ноября.
