---
question_id: B02
experiment_id: b02-google-youtube-sni-pilot-2026-11
status: inconclusive
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
actual_wire_validation: На клиентском PCAP завершён TCP handshake, исходящий ClientHello Google размером 1518 байт разбит на два сегмента; получены входящие TCP-данные. TLS не завершён из-за остановки монитором; попытка YouTube не началась.
offload_and_nat: WSL2 и NAT ограничивают выводы клиентского захвата; сведения об offload непосредственно до пробы не представлены. После пробы пользователь восстановил настройки, локальная проверка показала все четыре on.
route_metadata: Вывод маршрута перед пробой не представлен; интерфейс захвата eth0.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/b02-google-youtube-sni-pilot-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-google-youtube-sni-pilot-2026-11/runner.log}
classification_rule: Пилот из двух подключений не отвечает на полный вопрос B02. Фиксируются исходы TCP и TLS, проверка сертификата, размеры ClientHello и ограничения захвата; B02 остаётся inconclusive.
results:
  observation: TCP к Google установлен; TLS с www.google.com отменён монитором после девяти кадров за секунду. Попытка www.youtube.com не началась.
  compatible_hypotheses: [сервер ответил на TCP и прислал TLS-данные, скорость обмена достигла заданного порога]
  excluded_hypotheses: []
  inconclusive_reason: Запланированная пара не выполнена; TLS контрольного имени прерван самим пробером, сравнения SNI нет.
reproduce:
  tool_commit: 939bd00
  dependency_versions: {github.com/google/gopacket: v1.1.19, golang.org/x/net: v0.0.0-20190620200207-3b0461eec859, golang.org/x/sys: v0.0.0-20190412213103-97732733099d, gopkg.in/yaml.v3: v3.0.1}
  config_file: experiments/b02-google-youtube-sni-pilot-2026-11/config.yaml
  date_utc: '2026-11-14'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-14T11:37:49.672996883Z — 2026-11-14T11:37:49.893066451Z'
  run_json: experiments/b02-google-youtube-sni-pilot-2026-11/run.json
artifacts:
  pcap_client: {sha256: 632fa578f6dcb0e6e01978e9fda9a20eddfd7e8809ff586ea94f2a5f1d37fa9a}
  pcap_server: null
  runner_log: {sha256: be199ca0f45e850dc069effa7a8874172e737c4142366ed656dea712099db473}
  observations: {sha256: babd62de08e7b5505797e355da1c7bfa57c62b030bb1a97f918ee23fdec4d2ed}
  wire_plan: {sha256: bd67eaa677aaaacd12719a7cf47d09bb077960d979f6fce9747629e640c49f1a}
  run_json: {sha256: 636ba528c34abe4cfafef8b23e22cb40d3781ffad9f42bd45a566ad5fdd90fac}
  config: {sha256: d298613aa2bd4e7725b8dc0245464b254549bd82fe27ea13a65514a5f2cb6d66}
  sni_schedule: {sha256: 91a348ab6aa50d603b566381f709686eee5244df6817b915c2595ea14066ceba}
  executable: {sha256: e13ce1b1361b3123db66f899bb564163ce7a1dfda9a25cc8e255468e4ce50784}
---

## План и ограничения

Системный DNS пользователя вернул `142.251.155.119` для `www.google.com`;
в списке адресов `www.youtube.com` этот IPv4 отсутствовал. Сервер может как
принять второе имя, так и отказать ему или выдать неподходящий сертификат;
это не установлено до опыта. Одна пара — пилот выполнимости, не достаточная
выборка для устойчивого вывода или полной матрицы B02. Имена различаются по
длине; одинаковая длина и идентичность ClientHello не гарантируются.

Устанавливаются только TLS-соединения без HTTP-запроса, поэтому успешный TLS
не доказывает доступность сайта. Различие исходов не отделяет поведение сервера
от вмешательства сети. Автоматический лимит 90% частоты может прервать даже
первое подключение; capture асинхронен и не измеряет физическую линию.

Повторный SYN останавливает серию автоматически, но другие TCP-повторы этот
счётчик не распознаёт. Оператор наблюдает пакеты в отдельном терминале через
`tcpdump -nn -tt -S -l`, отслеживает повторение последовательностей исходящих
сегментов и при повторе или аномалии прерывает runner через Ctrl+C. Захват и
ручное прерывание асинхронны; уже отправленные пакеты не отзываются.

До запуска проверить отсутствие адреса в `docs/DO_NOT_SCAN.md`; пока файла нет,
нужно явное подтверждение пользователя на эту серию. При обнаружении
уязвимости контакт — [Google Bug Hunters](https://bughunters.google.com/report).
PCAP и журнал — вне git, каталог 0700, файлы 0600.

## Наблюдения

14 ноября 2026 года пользователь запустил серию. TCP с `142.251.155.119`
установился, после чего ClientHello с именем `www.google.com` был захвачен
в двух TCP-сегментах, а сервер прислал ответные TCP-данные. Монитор отменил
TLS до завершения из-за девяти кадров за секунду, включая оба направления:
это 90% заданного лимита. Всего учтены 9 кадров, 4584 байта Ethernet, ноль
повторных SYN и нулевые потери capture. Неуспешное завершение контрольной
попытки вызвано остановкой пробера и не означает отказ сервера.

До соединения runner подготовил ClientHello длиной 1518 байт для Google и
1519 байт для YouTube. Второе сообщение запланировано, но его попытка не
началась. Серверный захват отсутствует; клиентский capture в WSL2 не
показывает напрямую физическую линию. Сравнение имён не состоялось.

Capability с бинаря снята; TSO, GSO, GRO и LRO после восстановления
показывают `on`. Какие значения были непосредственно во время пробы, по
представленным данным не установлено.

## Update 2026-11-14T11:39:25Z

- Было: `planned`; стало: `inconclusive`.
- Причина: автоматическая остановка по частоте прервала TLS контрольного
  имени до завершения, а попытка с именем YouTube не была начата.
