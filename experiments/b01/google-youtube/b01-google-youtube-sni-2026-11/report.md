---
question_id: B01
experiment_id: b01-google-youtube-sni-2026-11
status: inconclusive
hypothesis: "На одном IPv4 исходы TLS с именами Google и YouTube могут различаться."
alternative_hypotheses: [поведение сервера или сертификата, потери или фильтрация, состояние сети, особенности WSL2 и захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {sni: www.google.com, shape: "{record_length: 260, sni_offset: 110, ignored_data: neutral}"}
treatment: {sni: www.youtube.com, changed_factor: "имя SNI при равной длине и позиции", shape: "{record_length: 260, sni_offset: 110, ignored_data: neutral}"}
invariants: [один IPv4 и порт, TLS 1.2 с проверкой сертификата, отдельные TCP-соединения, одинаковая пауза после TCP, одинаковые лимиты]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, повтор исходящих данных или FIN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Runner фиксирует полные байты ClientHello и параметры обоих вариантов до подключения; TCP-сегментацию и повторы выбирает ядро.
actual_wire_validation: "Оба ClientHello — 260 байт; контроль завершил TLS, исследуемый ClientHello повторился без наблюдаемого ответа."
offload_and_nat: WSL2 и NAT ограничивают выводы; скрипт сохраняет и восстанавливает исходные настройки offload.
route_metadata: Скрипт проверяет маршрут до запуска и выводит его пользователю.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none, client_hello_delay_ms: 1100, close_delay_ms: 1100}
observations: {client_pcap: artifacts/b01-google-youtube-sni-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b01-google-youtube-sni-2026-11/runner.log}
classification_rule: Одна пара на чужом target является пилотом; недостаток наблюдений и отсутствие серверного контроля оставляют вопрос inconclusive. Незапущенные попытки не классифицируются как измерения.
results: {observation: "Google завершил TLS; YouTube ClientHello повторился без наблюдаемого ответа.", compatible_hypotheses: [сетевое вмешательство, поведение сервера, потеря пакетов], excluded_hypotheses: [], inconclusive_reason: "Одна пара без серверного наблюдения не устанавливает причину различия или принятие YouTube сервером."}
reproduce: {tool_commit: 9a25b0f, dependency_versions: run.json, config_file: experiments/b01/google-youtube/b01-google-youtube-sni-2026-11/config.yaml, date_utc: 2026-11-17, operator: qjolk, lab_config_id: null, timestamps_utc: run.json}
artifacts: {pcap_client: {sha256: f8b199952c1faafd1f6b6b991c73134b296a9259ba9250728412a684c6b483c5}, pcap_server: null, runner_log: {sha256: 950081cb3a27c76f2d21f94331a341458da1ad9f9ccc662d9fd2144ba53c1bbb}, observations: {sha256: 08c47fad5a7064c1c44c2c9bf7838b07e51be5c282520bd8e9ba80788b8f0412}, wire_plan: {sha256: 6ad8e7aca897dce3e7dbd4dfc7c037a72209de81bd56fa67fa86af013a1ba0bc}}
---

## План и ограничения

Прямой пилот target; канонический B01 исследует путь к helper и этой серией не подтверждается. Профили используют uTLS и TLS 1.2 с проверкой сертификата;
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

## Update 2026-11-17 14:24 UTC

Статус `planned` → `inconclusive`. Контроль `www.google.com` завершил TLS 1.2
с проверкой сертификата. На том же IP TCP для `www.youtube.com` установился,
после ClientHello длиной 260 байт ACK или ответ в захвате не наблюдался;
примерно через 385 мс ClientHello повторился и монитор остановил серию.
Одной пары и клиентского захвата недостаточно для установления причины;
принятие YouTube этим сервером отдельно не проверено.

Наблюдено 22 кадра, 5080 байт Ethernet, потерь захвата нет. Маршрут:
`142.251.155.119 via 172.26.0.1 dev eth0 src 172.26.1.205`. Пользователь
сообщил о восстановлении исходных offload. Хеши артефактов — в `run.json`.
