---
question_id: B02
experiment_id: b02-telegram-sni-pilot-2026-11
status: inconclusive
hypothesis: >
  На одном адресе Telegram могут наблюдаться разные результаты обычных
  TCP/TLS-подключений при двух именах SNI одинаковой длины.
alternative_hypotheses:
  - Сервер по-разному обрабатывает виртуальные хосты или сертификаты.
  - Потери, временная недоступность или остаточное состояние меняют исходы.
  - Локальная сеть, NAT или capture влияют на наблюдение.
mode: valid-session
vantage:
  network: сеть пользователя через WSL2; провайдер и внешний маршрут не установлены
  address_family: ipv4
  capture_point: клиентский интерфейс eth0
endpoint: {role: target, ip: 149.154.167.99, port: 443}
control:
  sni: www.telegram.org
  note: Приём этого имени и сертификат на данном endpoint заранее не проверены.
treatment: {changed_factor: sni, values: [web.telegram.org]}
invariants:
  - Один IPv4 и порт; оба имени содержат по 16 ASCII-байтов.
  - Обычный TLS-клиент Go с проверкой имени и сертификата; отдельное TCP-соединение на попытку.
  - Профиль библиотеки и параметры серии одинаковы; случайные значения TLS независимы.
budget:
  max_packets: 100
  max_bytes: 102400
  max_rate_pps: 10
  max_duration_s: 60
  stop_conditions:
    - приближение к лимиту по клиентскому capture
    - ошибка или потери capture
    - аномалия в канале
    - SIGINT или SIGTERM
planned_wire_packets: >
  До первого подключения runner создаёт plan.yaml с точным ClientHello
  каждой попытки. TCP-сегментация и ретрансляции управляются ядром;
  последующие TLS-сообщения зависят от ответа сервера. Сохранённые четыре
  ClientHello имеют длину 1520 байт каждый и содержат запланированные имена.
actual_wire_validation: >
  В клиентском PCAP 20 исходящих SYN: по пять кадров с одинаковым TCP SEQ
  для каждого из четырёх соединений. SYN-ACK, RST и TCP payload не
  наблюдались; ни один из четырёх запланированных ClientHello не обнаружен
  в клиентском захвате. Таким образом, TCP-handshake и передача ClientHello
  по этим данным не подтверждены. Клиентский PCAP WSL2 не доказывает,
  какие пакеты прошли физический интерфейс, и не локализует потерю.
offload_and_nat: >
  При подготовке на eth0 были включены TSO, GSO, GRO и LRO. Пользователь
  отключил их; повторная проверка ethtool показала off для всех четырёх.
  WSL2 использует виртуальный интерфейс и локальный шлюз; настройки
  Windows-хоста, внешнего NAT и CGNAT неизвестны, поэтому число кадров
  клиента не является доказательством числа пакетов на физической линии.
  После серии пользователь восстанавливает исходное состояние offload.
route_metadata: >
  При подготовке ip route get указал интерфейс eth0, MTU 1280 и шлюз
  WSL2. Адрес назначения передан пользователем из системного DNS;
  маршрут может измениться до запуска.
schedule:
  repetitions: 2
  seed: 0
  inter_trial_gap_ms: 3000
  state_reset: none
observations:
  client_pcap: artifacts/b02-telegram-sni-pilot-2026-11/client.pcap
  server_pcap: null
  helper_log: null
  runner_log: artifacts/b02-telegram-sni-pilot-2026-11/runner.log
  trials: artifacts/b02-telegram-sni-pilot-2026-11/sni-observations.json
classification_rule: |
  This is a feasibility pilot on one target address, not the full B02
  address matrix. Record each attempt and the capture limitations. A
  difference between names alone does not distinguish server behavior
  from network interference. B02 remains inconclusive after this pilot;
  do not classify an unstarted, interrupted, incomplete, or ambiguous
  series as a confirmed or refuted result.
results:
  observation: >
    Все четыре попытки завершились по таймауту TCP за 5 секунд. В клиентском
    capture записаны только исходящие SYN, по пять на каждую попытку;
    ответных пакетов и TLS ClientHello не наблюдалось.
  compatible_hypotheses:
    - Потеря или фильтрация пакетов на маршруте либо на endpoint.
    - Локальная проблема WSL2, NAT, интерфейса или захвата.
    - Иная причина отсутствия наблюдаемого ответа в окне попыток.
  excluded_hypotheses: []
  inconclusive_reason: >
    Ни одно соединение не достигло передачи SNI. Односторонний захват не
    устанавливает причину или место потери; одного адреса недостаточно для
    предусмотренной B02 матрицы адресов.
reproduce:
  tool_commit: 0f6f32d
  dependency_versions:
    github.com/google/gopacket: v1.1.19
    golang.org/x/net: v0.0.0-20190620200207-3b0461eec859
    golang.org/x/sys: v0.0.0-20190412213103-97732733099d
    gopkg.in/yaml.v3: v3.0.1
  config_file: experiments/b02/telegram/b02-telegram-sni-pilot-2026-11/config.yaml
  date_utc: '2026-11-13'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-13T16:44:38.048183743Z — 2026-11-13T16:45:07.468839277Z'
  run_json: experiments/b02/telegram/b02-telegram-sni-pilot-2026-11/run.json
artifacts:
  pcap_client:
    sha256: 4b7a2e9b83a7f1cb5455b215727c5eca7985207813408111ecb51df8f365ecc3
  pcap_server: null
  runner_log:
    sha256: d9479e961a1e1697bc34809fe8d585bc5594d7135ab682b0e62f9773d74aa31c
  trials:
    sha256: ff304966a2415fe295bad98ed3eb8250a5242812aec432287e0448dfb1240d1d
  wire_plan:
    sha256: f428c214273e662be8ec8b84f2eea2db93247307ccdeefa6d6e882f698aefa10
  run_json:
    sha256: 0472531b4bfe6b22f62fde93a3015dc88772c050f8f8bc546c271872a99a9689
  config:
    sha256: 9fee7724fde185fa3725a85ba2acea6bda70a4c779473ebdc14b79f558fa31cc
  executable:
    sha256: d2e405ce2b4be8afa9984477e33a92b378213846b4d3ab405e07f4220fa51617
---

## План и ограничения

Порядок попыток: `www.telegram.org`, `web.telegram.org`,
`web.telegram.org`, `www.telegram.org`. Две пары выбраны как небольшой
пилот доступности и управления инструментом, а не как достаточная выборка
для статистического вывода. При четырёх таймаутах по 5 секунд и трёх
интервалах по 3 секунды остаётся запас относительно лимита 60 секунд.
Автоматическая остановка при 90% лимита частоты может прервать даже первую
сессию: TCP и TLS передают несколько кадров подряд.

Выбранный контроль имеет ту же длину, но пока не доказано, что endpoint
принимает его или предъявляет подходящий сертификат. Равенство длины имени
также не гарантирует равенство полного ClientHello. По одному адресу и без
серверных наблюдений различие ответов нельзя приписать сети или серверу.
Полная матрица B02 включает собственные адреса helper и в этот пилот не
входит.

При обнаружении уязвимости контакт для сообщения владельцу —
`security@telegram.org` ([официальная программа Telegram](https://core.telegram.org/bug-bounty)).
До запуска проверить `docs/DO_NOT_SCAN.md`; пока файл отсутствует, серия по
`target` требует явного подтверждения пользователя. Ключи TLS не сохраняются.
PCAP и сырые логи остаются вне git с правами 0600, каталог — 0700.

## Подготовка интерфейса

Пользователь выполнил `ethtool -K eth0 tso off gso off gro off lro off`.
Последующая локальная проверка показала `off` для всех четырёх настроек;
до изменения все четыре были `on`. Сетевые пробы при этой подготовке не
запускались. После серии восстановить исходные настройки командой
`sudo ethtool -K eth0 tso on gso on gro on lro on` и проверить результат.

## Наблюдения пилота

Пользователь выполнил серию 13 ноября 2026 года в 16:44:38–16:45:07 UTC.
Чередование совпало с планом: `www`, `web`, `web`, `www`. Каждый TCP dial
истёк по пятиисекундному таймауту. По клиентскому PCAP для каждой попытки
наблюдались начальный SYN и четыре SYN с теми же последовательными
номерами; входящие пакеты и payload отсутствовали. Поскольку TCP-соединения
не установились, запланированные ClientHello в этом захвате не наблюдались
и сравнение реакции на SNI не состоялось. Все четыре ClientHello в плане
имеют одинаковую длину — 1520 байт.

В PCAP записано 20 кадров, 1480 байт Ethernet и не более одного кадра за
скользящую секунду по временным меткам capture. В журнале монитора указаны
нулевые потери захвата; это не доказывает полноту наблюдения за пределами
WSL2. Длительность от начала до окончания runner — около 29,4 секунды.
Наблюдаемые показатели не превысили заданные пределы, но не являются
прямым измерением физической линии.

Исходные TSO, GSO, GRO и LRO пользователь восстановил; повторная локальная
проверка показала `on` для всех четырёх. Capability `CAP_NET_RAW` с бинаря
снята. В плане не был задан порог роста ретрансляций, а runner не умеет
автоматически останавливать серию по этому признаку, хотя в каждой попытке
наблюдались четыре повторных SYN. Это недостаток подготовки и реализации
относительно `SAFETY.md` §3: до следующей серии критерий нужно определить
и обеспечить. Сравнение с другой сетью, серверный capture и состояние
внешнего NAT отсутствуют.

## Update 2026-11-13T16:46:01Z

- Было: `planned`; стало: `inconclusive`.
- Причина: четыре попытки завершились на TCP до наблюдаемой отправки
  ClientHello; данные не позволяют оценить SNI-эффект или выполнить
  полную матрицу B02.
