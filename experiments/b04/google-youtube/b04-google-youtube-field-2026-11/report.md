---
question_id: B04
experiment_id: b04-google-youtube-field-2026-11
status: inconclusive
hypothesis: "Исход может зависеть от того, находится ли имя YouTube в SNI или в частном расширении."
alternative_hypotheses: [поведение сервера или сертификата, потери или фильтрация, состояние сети, особенности WSL2 и захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {sni: www.google.com, shape: "{record_length: 260, sni_offset: 110, ignored_data: www.youtube.com}"}
treatment: {sni: www.youtube.com, changed_factor: "размещение имени в SNI или частном расширении", shape: "{record_length: 260, sni_offset: 110, ignored_data: www.google.com}"}
invariants: [один IPv4 и порт, TLS 1.2 с проверкой сертификата, отдельные TCP-соединения, одинаковая пауза после TCP, одинаковые лимиты]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, повтор исходящих данных или FIN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Runner фиксирует полные байты ClientHello и параметры обоих вариантов до подключения; TCP-сегментацию и повторы выбирает ядро.
actual_wire_validation: "Контрольный ClientHello повторился без наблюдаемого ответа; серия остановлена."
offload_and_nat: WSL2 и NAT ограничивают выводы; скрипт сохраняет и восстанавливает исходные настройки offload.
route_metadata: Скрипт проверяет маршрут до запуска и выводит его пользователю.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none, client_hello_delay_ms: 1100, close_delay_ms: 1100}
observations: {client_pcap: artifacts/b04-google-youtube-field-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b04-google-youtube-field-2026-11/runner.log}
classification_rule: Одна пара на чужом target является пилотом; недостаток наблюдений и отсутствие серверного контроля оставляют вопрос inconclusive. Незапущенные попытки не классифицируются как измерения.
results: {observation: "Контрольный ClientHello повторился без наблюдаемого ответа; серия остановлена.", compatible_hypotheses: [эффект есть, эффекта нет], excluded_hypotheses: [], inconclusive_reason: "Исследуемый вариант не запускался, сравнение отсутствует."}
reproduce: {tool_commit: 9a25b0f, dependency_versions: run.json, config_file: experiments/b04/google-youtube/b04-google-youtube-field-2026-11/config.yaml, date_utc: 2026-11-17, operator: qjolk, lab_config_id: null, timestamps_utc: run.json}
artifacts: {pcap_client: {sha256: 1aa5d7e8289bbb339f9d93c59f520310b3669e2630118d9077cfe66a718fdee1}, pcap_server: null, runner_log: {sha256: 739e84ab810ff4a43d3aa629163573aa94a9ebf4ba6c2d011a33d939e22cf1a3}, observations: {sha256: 2758bdd2604d34586e6727ce8561573fbf9f32e95d7405d8bd466808ed6beb0e}, wire_plan: {sha256: cb28ad6311c5e1edc8a6e9852e351a1b97e485d3b05ab38a7d6129c4eecf369a}}
---

## План и ограничения

Прямой пилот target; принятие обоих профилей и серверное поведение заранее неизвестны. Профили используют uTLS и TLS 1.2 с проверкой сертификата;
два частных расширения содержат данные и заполнитель. Смещение SNI считается
от начала TLS-записи, а не TCP-пакета. Одинаковая пауза 1,1 секунды после
TCP-handshake меняет тайминг; случайные поля TLS различаются. Возможность
сервера принять оба имени и частные расширения заранее не установлена.

После успешного TLS соединение удерживается открытым 1,1 секунды; монитор
остаётся активным. Пауза не гарантирует соблюдение лимита при повторах.

Каждый опыт — одна пара с паузой 3 секунды между попытками, без HTTP.
Между сериями предусмотрено 3 секунды. Общий скрипт прекращает пакет
при первой ошибке, повторе TCP или достижении лимита; последующие серии
тогда не выполняются. Асинхронный монитор не отменяет уже отправленные
пакеты; ядро может продолжать FIN после завершения захвата. Наблюдения
одного клиентского интерфейса не определяют причину или место вмешательства.

Для B01 канонический метод требует путь к helper; для B04 и B07 также нужны
контролируемые сравнения и проверка принятия сообщений. Эта прямая серия
по решению пользователя не является автоматической заменой таких наблюдений.
DNS пользователя вернул этот адрес для `www.google.com` 14 ноября; его
текущая принадлежность DNS-ответу не проверяется. До запуска проверить
`docs/DO_NOT_SCAN.md`; пока его нет, серия требует подтверждения пользователя.
Канал сообщения об уязвимости — [Google Bug Hunters](https://bughunters.google.com/report).
Сырые PCAP и журналы остаются вне Git.

## Update 2026-11-17 12:11 UTC

Статус `planned` → `inconclusive`. TCP-handshake завершился. После контрольного ClientHello длиной 260 байт захват не показал ACK или ответа сервера до повтора этого ClientHello через примерно 315 мс. Монитор остановил серию; причина отсутствия ответа неизвестна. Исследуемый вариант не запускался.

Наблюдено кадров: 5, байт Ethernet: 866, потерь захвата: 0. Маршрут: `142.251.155.119 via 172.26.0.1 dev eth0 src 172.26.1.205`. Пользователь сообщил о восстановлении исходных настроек offload. Хеши PCAP, журнала и наблюдений — в `run.json`; сырые артефакты вне Git.
