---
question_id: B02
experiment_id: b02-cloudflare-tcp-control-2026-11
status: inconclusive
hypothesis: TCP-соединение с выбранным адресом Cloudflare может установиться.
alternative_hypotheses: [потери или отказ на маршруте, локальная проблема или ошибка захвата]
mode: valid-session
vantage: {network: WSL2 пользователя, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 104.16.133.229, port: 443}
control: {profile: одиночное TCP-соединение без данных приложения}
treatment: {changed_factor: нет, values: []}
invariants: [один адрес, один порт, одно соединение, системный TCP]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Системный TCP handshake и закрытие; содержимое приложения не отправляется. Ядро определяет поля и сегментацию; runner сохраняет plan.yaml до подключения.
actual_wire_validation: В клиентском PCAP наблюдаются SYN, SYN-ACK, ACK и закрытие FIN с обеих сторон; прикладных данных нет. Клиентский захват WSL2 не показывает весь физический маршрут.
offload_and_nat: WSL2 и внешний NAT ограничивают выводы; сведения об offload непосредственно до пробы не представлены. После пробы пользователь восстановил настройки, локальная проверка показала все четыре on.
route_metadata: Маршрут перед пробой не представлен; исходящий интерфейс захвата eth0.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 0, state_reset: none}
observations: {client_pcap: artifacts/b02-cloudflare-tcp-control-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-cloudflare-tcp-control-2026-11/runner.log}
classification_rule: Один TCP-контроль не отвечает на B02; B02 остаётся inconclusive. Фиксируется исход подключения, причина поведения другого endpoint не устанавливается.
results:
  observation: TCP-соединение установлено и закрыто без передачи прикладных данных; повторные SYN не наблюдались.
  compatible_hypotheses: [доступность TCP к выбранному адресу в момент наблюдения]
  excluded_hypotheses: []
  inconclusive_reason: Этот контроль не исследует SNI и не объясняет отсутствие ответа другого endpoint.
reproduce:
  tool_commit: 939bd00
  dependency_versions: {github.com/google/gopacket: v1.1.19, golang.org/x/net: v0.0.0-20190620200207-3b0461eec859, golang.org/x/sys: v0.0.0-20190412213103-97732733099d, gopkg.in/yaml.v3: v3.0.1}
  config_file: experiments/b02/cloudflare/b02-cloudflare-tcp-control-2026-11/config.yaml
  date_utc: '2026-11-13'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-13T19:28:50.549030391Z — 2026-11-13T19:28:51.108867165Z'
  run_json: experiments/b02/cloudflare/b02-cloudflare-tcp-control-2026-11/run.json
artifacts:
  pcap_client: {sha256: 4d00184271fda6e158f0af1bb0929ecdfe9eb06285486c18da4e53d5b6d699f7}
  pcap_server: null
  runner_log: {sha256: 2c26e30d0b24d5f215dd3aa01cba128b6773431e0c9b77931287e5918b0e9b1e}
  observations: {sha256: 51540f7aa086234843d9eb851451aa8df41bc5eb1841037b65f00197f61f895f}
  wire_plan: {sha256: 45b0f4365b9641090bcb037b6a5e8ab57111c18ea215e021e6956a35ab76f400}
  run_json: {sha256: 80ddae55e3032c4055065acfd22118936f786fac03a027f7165523ca980b5de7}
  config: {sha256: a5fc40ef3703d65c38a6895019cce019def77cd928392c83939bb5c7f8eb9848}
  executable: {sha256: e13ce1b1361b3123db66f899bb564163ce7a1dfda9a25cc8e255468e4ce50784}
---

## План

Пользователь получил адрес `104.16.133.229` через системный DNS для
`cloudflare.com`. Одна попытка ограничивает нагрузку и проверяет только
доступность выбранного endpoint в момент пробы; она не объясняет предыдущие
таймауты Telegram и не является парным сравнением SNI.

Повторный SYN останавливает серию автоматически, но другие TCP-повторы этот
счётчик не распознаёт. Оператор наблюдает пакеты в отдельном терминале через
`tcpdump -nn -tt -S -l`, отслеживает повторение последовательностей исходящих
сегментов и при повторе или аномалии прерывает runner через Ctrl+C. Захват и
ручное прерывание асинхронны; уже отправленные пакеты не отзываются.

До запуска проверить отсутствие адреса в `docs/DO_NOT_SCAN.md`; пока файла нет,
нужно явное подтверждение пользователя на эту серию. При обнаружении
уязвимости использовать [программу раскрытия Cloudflare](https://www.cloudflare.com/disclosure/).
PCAP и журнал — вне git, каталог 0700, файлы 0600.

## Наблюдения

13 ноября 2026 года пользователь выполнил одну попытку. В клиентском PCAP
наблюдаются SYN, SYN-ACK и ACK, затем FIN с обеих сторон и подтверждение;
TCP payload отсутствует. Runner записал завершённое подключение, 6 кадров,
412 байт Ethernet, ноль повторных SYN и нулевые потери захвата.

Предшествующая [попытка к дата-центру Telegram](../../telegram/b02-telegram-dc-tcp-2026-11/report.md)
остановилась после одного повторного SYN без наблюдаемого ответа. Проверки
проводились последовательно на разных адресах и в разное время, поэтому
различие не определяет причину отсутствия ответа Telegram и не является
сравнением SNI. Capability с бинаря снята; TSO, GSO, GRO и LRO после
восстановления показывают `on`. Значения непосредственно во время пробы по
представленным данным не установлены.

## Update 2026-11-13T19:29:30Z

- Было: `planned`; стало: `inconclusive`.
- Причина: контрольное TCP-соединение установилось, но оно не проверяет B02
  и не устанавливает причину отсутствия ответа от другого адреса.
