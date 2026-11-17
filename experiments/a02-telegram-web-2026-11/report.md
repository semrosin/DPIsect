---
question_id: A02
experiment_id: a02-telegram-web-2026-11
status: inconclusive
hypothesis: >
  Системное разрешение имени возвращает IPv4, TCP-соединение с
  web.telegram.org:443 устанавливается и TLS-handshake завершается
  с успешной проверкой имени и сертификата.
alternative_hypotheses:
  - TCP-соединение не установилось до истечения таймаута.
  - TCP-соединение установилось, но TLS-handshake не завершился вовремя.
  - Данные недостаточны для определения стадии сбоя.
mode: valid-session
vantage:
  network: текущая сеть пользователя, точный провайдер не зафиксирован
  address_family: ipv4
  capture_point: PCAP не записывался; события получены из журналов клиента
endpoint:
  role: target
  hostname: web.telegram.org
  ip: 149.154.167.99
  port: 443
control:
  profile: отсутствует
  note: Контрольная сеть и серверные журналы отсутствуют.
treatment:
  changed_factor: none
  values: []
invariants:
  - Один выбранный системным разрешением IPv4; SNI web.telegram.org.
  - Одна попытка с проверкой имени и сертификата.
budget:
  max_packets: 100
  max_bytes: 102400
  max_rate_pps: 10
  max_duration_s: 60
  stop_conditions:
    - Ctrl+C
    - таймаут DNS 10 секунд и TLS 20 секунд
  actual_wire_budget: Не измерен; PCAP отсутствует, число TCP-пакетов неизвестно.
planned_wire_packets: >
  Обычное TCP-соединение и TLS handshake через OpenSSL; TCP-поля и
  случайные байты выбираются ОС и OpenSSL. Отдельного плана байтов нет.
actual_wire_validation: Не проводилась; PCAP отсутствует.
offload_and_nat: Не оценивались; адрес источника относится к сети WSL2.
route_metadata: Маршрут через eth0 и локальный шлюз WSL2; см. route.txt.
schedule:
  repetitions: 1
  seed: null
  inter_trial_gap: not_applicable
  state_reset: none
observations:
  dns: artifacts/a02-telegram-web-2026-11/run-2VunN8yP/dns.txt
  route: artifacts/a02-telegram-web-2026-11/run-2VunN8yP/route.txt
  tls_log: artifacts/a02-telegram-web-2026-11/run-2VunN8yP/tls.txt
  metadata: artifacts/a02-telegram-web-2026-11/run-2VunN8yP/metadata.txt
  client_pcap: null
  server_pcap: null
  helper_log: null
  runner_log: null
classification_rule: >
  confirmed — TLS-handshake завершён, имя и сертификат успешно проверены;
  refuted — определённый отказ TCP или TLS/проверки сертификата;
  inconclusive — DNS-ошибка, таймаут или недостаточно данных.
results:
  observation: >
    Системное разрешение вернуло 149.154.167.99. По истечении 20 секунд
    timeout завершил OpenSSL с кодом 124; журнал TLS пуст. Установление
    TCP и отправка ClientHello по этим данным не подтверждены.
  compatible_hypotheses:
    - TCP не установился в течение окна.
    - TCP установился, но TLS не завершился; вывод клиента не сохранился.
    - Сетевая или локальная ошибка помешала завершению подключения.
  excluded_hypotheses:
    - Системное разрешение имени не вернуло IPv4 во время этого запуска.
  inconclusive_reason: >
    Таймаут, пустой журнал клиента, отсутствие PCAP и контрольной сети
    не позволяют определить стадию или причину сбоя.
reproduce:
  tool_commit: null
  tool_note: DPIsect не запускался; использован OpenSSL и локальный скрипт.
  repository_head: a24013715805fcd06b1aa6f498193b0f82eb5b2a
  script_sha256: 0e14e180ae58d1ea7ea2f9fe3e512c7cad890227c7f568ee7c29969e0869bc0e
  openssl: OpenSSL 3.5.5 27 Jan 2026
  kernel: 6.6.87.2-microsoft-standard-WSL2
  config_file: experiments/a02-telegram-web-2026-11/README.md
  date_utc: '2026-11-10'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-10T15:00:47Z — 2026-11-10T15:01:07Z'
  run_json: null
artifacts:
  metadata_sha256: f080bbd1aa80971a2db63935f17f76ce08f2758a2c6a341d140d19219d6fd8ce
  dns_sha256: f8f8bacabceb8f2c262d4aa09053be0e652170886fe7d162d7f100369dfc8bac
  dns_error_sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  route_sha256: 4e7fd57acc76f1064a16a262fc3c13554ce39b6aedbdf19c25d51476373ed2ec
  tls_sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  pcap_client: null
  pcap_server: null
---

## Наблюдения и вывод

Пользователь выполнил один запуск 10 ноября 2026 года в 15:00:47 UTC.
Системное разрешение имени `web.telegram.org` вернуло `149.154.167.99`.
Через 20 секунд попытка завершилась по таймауту; файл вывода TLS пуст.

Исход **inconclusive** по заранее заданному правилу. Полученный IPv4
подтверждает только успех системного разрешения имени в этом запуске.
Пустой журнал не доказывает ни отсутствие соединения, ни его успешное
установление: среди возможных причин отсутствия вывода — буферизация.
Не установлены причина таймаута, факт DPI-блокировки и доступность всего
Telegram или его приложений. Контрольная сеть, клиентский и серверный
PCAP отсутствуют; повторяемость не оценивалась.

## Update 2026-11-10T15:01:56Z

- Было: `planned`; стало: `inconclusive`.
- Причина: выполнен один запуск, исчерпано 20-секундное окно TLS,
  для определения стадии таймаута нет достаточных наблюдений.

## Дополнительный запуск с клиентским PCAP — 2026-11-10

Пользователь самостоятельно выполнил запланированный в
`capture-followup.md` повтор с записью на интерфейсе `eth0`, без повторного
DNS-разрешения. Цель — тот же IPv4 `149.154.167.99:443`, имя TLS —
`web.telegram.org`. Время — 15:36:50–15:37:10 UTC. OpenSSL завершился по
20-секундному таймауту, код `124`; его журнал пуст.

В клиентском PCAP восемь исходящих TCP SYN одного соединения: первая
попытка и семь повторных передач ядра. Это видимые в захвате кадры на
интерфейсе WSL2; доставка за пределы WSL2 или до сервера не подтверждена.
SYN-ACK, RST, другие входящие пакеты и TCP payload в записи отсутствуют.
Таким образом, **TCP handshake не наблюдался как завершённый; TLS
ClientHello в захваченных пакетах не было**. Стадия после TCP для этого
запуска не достигнута по доступным данным.

`tcpdump` сообщил `8 packets captured`, `9 packets received by filter`,
`0 packets dropped by kernel`. Это расхождение не позволяет считать
захват абсолютно полным; по одному клиентскому наблюдению нельзя
доказать, что сервер не ответил, определить место потери либо установить
блокировку. Независимый маршрут, серверный PCAP и повторные измерения
отсутствуют. Разница между сетью WSL2 и внешним маршрутом также остаётся
возможной причиной. Первый запуск без PCAP задним числом не переоценивается.

Для гипотезы исходного опыта статус остаётся **inconclusive** в соответствии
с правилом о таймауте. Дополнительная запись уточняет наблюдаемую стадию
неудачного подключения, но не устанавливает его причину.

Артефакты второго запуска — вне git, каталог
`artifacts/a02-telegram-web-2026-11/capture-TPHptz11/`:

| Файл | SHA-256 |
| --- | --- |
| `client.pcap` | `704575ecede4b7a9a1f8bf2970e889496bbedc31a4daa69b4a6648546e701434` |
| `capture.log` | `686db9e3db02233d254786c66d28e863e37267363ad7cd0a57c320885d59a43d` |
| `metadata.txt` | `1a49fad67920c6a7d8b2b1b4f8d595e6af0e41dd7d4cdbe4a81df14e6a51ffe7` |
| `route.txt` | `4e7fd57acc76f1064a16a262fc3c13554ce39b6aedbdf19c25d51476373ed2ec` |
| `tls.txt` (пуст) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Update 2026-11-10T15:38:47Z

- Было: `inconclusive`; стало: `inconclusive`.
- Причина: повторный таймаут с клиентским PCAP позволил увидеть исходящие
  SYN без наблюдаемого SYN-ACK, но причина отсутствия ответа неизвестна.
