---
question_id: B07
experiment_id: b07-google-length-2026-11
status: inconclusive
hypothesis: "Исход TLS может зависеть от длины ClientHello при одинаковом положении SNI."
alternative_hypotheses: [поведение сервера или сертификата, потери или фильтрация, состояние сети, особенности WSL2 и захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 142.251.155.119, port: 443}
control: {sni: www.google.com, shape: "{record_length: 260, sni_offset: 110, ignored_data: neutral}"}
treatment: {sni: www.google.com, changed_factor: "длина ClientHello при одинаковом положении SNI", shape: "{record_length: 300, sni_offset: 110, ignored_data: neutral}"}
invariants: [один IPv4 и порт, TLS 1.2 с проверкой сертификата, отдельные TCP-соединения, одинаковая пауза после TCP, одинаковые лимиты]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, повтор исходящих данных или FIN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Runner фиксирует полные байты ClientHello и параметры обоих вариантов до подключения; TCP-сегментацию и повторы выбирает ядро.
actual_wire_validation: "Обе длины 260 и 300 байт: TLS 1.2 завершился."
offload_and_nat: WSL2 и NAT ограничивают выводы; скрипт сохраняет и восстанавливает исходные настройки offload.
route_metadata: Скрипт проверяет маршрут до запуска и выводит его пользователю.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none, client_hello_delay_ms: 1100, close_delay_ms: 1100}
observations: {client_pcap: artifacts/b07-google-length-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b07-google-length-2026-11/runner.log}
classification_rule: Одна пара на чужом target является пилотом; недостаток наблюдений и отсутствие серверного контроля оставляют вопрос inconclusive. Незапущенные попытки не классифицируются как измерения.
results: {observation: "Обе длины 260 и 300 байт: TLS 1.2 завершился.", compatible_hypotheses: [эффект есть, эффекта нет], excluded_hypotheses: [], inconclusive_reason: "Одна пара не устанавливает воспроизводимый эффект или отсутствие эффекта."}
reproduce: {tool_commit: 9a25b0f, dependency_versions: run.json, config_file: experiments/b07/google-youtube/b07-google-length-2026-11/config.yaml, date_utc: 2026-11-17, operator: qjolk, lab_config_id: null, timestamps_utc: run.json}
artifacts: {pcap_client: {sha256: e37bf31c15cf04c05c6652ddc5236be1b18d6613ea81e2081a301036d869d98c}, pcap_server: null}
---

## План и ограничения

Две длины записи при одном положении SNI на адресе Google. Профили используют uTLS и TLS 1.2 с проверкой сертификата;
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

Статус `planned` → `inconclusive`. Для обеих длин ClientHello, 260 и 300 байт, успешно завершился TLS 1.2 с проверкой сертификата. Смещение SNI одинаковое — 110 байт. В пределах одного парного опыта различия в завершении TLS не наблюдалось.

Наблюдено кадров: 34, байт Ethernet: 8469, потерь захвата: 0. Маршрут: `142.251.155.119 via 172.26.0.1 dev eth0 src 172.26.1.205`. Пользователь сообщил о восстановлении исходных настроек offload. Хеши PCAP, журнала и наблюдений — в `run.json`; сырые артефакты вне Git.
