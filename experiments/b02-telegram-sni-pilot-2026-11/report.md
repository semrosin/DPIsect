---
question_id: B02
experiment_id: b02-telegram-sni-pilot-2026-11
status: planned
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
  последующие TLS-сообщения зависят от ответа сервера. План остаётся
  локальным файлом до выполнения команды пользователем.
actual_wire_validation: Не выполнялась; серия не запускалась.
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
  client_pcap: null
  server_pcap: null
  helper_log: null
  runner_log: null
classification_rule: |
  This is a feasibility pilot on one target address, not the full B02
  address matrix. Record each attempt and the capture limitations. A
  difference between names alone does not distinguish server behavior
  from network interference. B02 remains inconclusive after this pilot;
  do not classify an unstarted, interrupted, incomplete, or ambiguous
  series as a confirmed or refuted result.
results:
  observation: Не проводилось.
  compatible_hypotheses: []
  excluded_hypotheses: []
  inconclusive_reason: null
reproduce:
  tool_commit: null
  dependency_versions: null
  config_file: experiments/b02-telegram-sni-pilot-2026-11/config.yaml
  date_utc: null
  operator: null
  lab_config_id: null
  timestamps_utc: null
artifacts:
  pcap_client: null
  pcap_server: null
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
входит. Незапущенный пилот не является результатом вопроса B02.

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
