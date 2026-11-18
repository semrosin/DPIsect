---
question_id: B02
experiment_id: b02-telegram-dc-tcp-2026-11
status: inconclusive
hypothesis: TCP-соединение с выбранным адресом дата-центра Telegram может установиться.
alternative_hypotheses: [потери или отказ на маршруте, локальная проблема или ошибка захвата]
mode: valid-session
vantage: {network: WSL2 пользователя, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 149.154.175.50, port: 443}
control: {profile: одиночное TCP-соединение без данных приложения}
treatment: {changed_factor: нет, values: []}
invariants: [один адрес, один порт, одно соединение, системный TCP]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Системный TCP handshake и закрытие; содержимое приложения не отправляется. Ядро определяет поля и сегментацию; runner сохраняет plan.yaml до подключения.
actual_wire_validation: В клиентском PCAP два исходящих SYN одного соединения, второй с тем же SEQ; ответные пакеты и данные отсутствуют. Захват WSL2 не доказывает передачу на физическую линию.
offload_and_nat: WSL2 и внешний NAT ограничивают выводы; сведения об offload непосредственно до пробы не представлены. После пробы пользователь восстановил настройки, локальная проверка показала все четыре on.
route_metadata: Маршрут перед пробой не представлен; исходящий интерфейс захвата eth0.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 0, state_reset: none}
observations: {client_pcap: artifacts/b02-telegram-dc-tcp-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-telegram-dc-tcp-2026-11/runner.log}
classification_rule: Одно TCP-соединение не отвечает на B02; B02 остаётся inconclusive. Фиксируется исход подключения без вывода о причине, месте вмешательства или доступности Telegram Web.
results:
  observation: Исходный и один повторный SYN; после повтора runner отменил подключение. SYN-ACK и RST не наблюдались.
  compatible_hypotheses: [потери или фильтрация на маршруте, отказ или недоступность endpoint, особенности WSL2 или захвата]
  excluded_hypotheses: []
  inconclusive_reason: TCP не установился в окне наблюдения; причина и место отсутствия ответа неизвестны. SNI не передавался.
reproduce:
  tool_commit: 939bd00
  dependency_versions: {github.com/google/gopacket: v1.1.19, golang.org/x/net: v0.0.0-20190620200207-3b0461eec859, golang.org/x/sys: v0.0.0-20190412213103-97732733099d, gopkg.in/yaml.v3: v3.0.1}
  config_file: experiments/b02/telegram/b02-telegram-dc-tcp-2026-11/config.yaml
  date_utc: '2026-11-13'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-13T19:24:45.567247835Z — 2026-11-13T19:24:46.677448175Z'
  run_json: experiments/b02/telegram/b02-telegram-dc-tcp-2026-11/run.json
artifacts:
  pcap_client: {sha256: e76a15723a3f865df9df8c12838502049a59cdc733d34260bc0249a659fe82b6}
  pcap_server: null
  runner_log: {sha256: a1af7b96ddf93ac7728bcc8dae58361ca3f7f96d5147d0b749e8c4b14e4fa5e9}
  observations: {sha256: 1c4faa456a1e6eb3951bc3cff5de02468c4873427affdba4d7cc3c9e85f01ced}
  wire_plan: {sha256: 58dc6a8482e569bf699f9a06b40065554b907973f852dc756cf58004a2d1e10e}
  run_json: {sha256: 9b366117dcf88ce7289393fa15d25a5c7cfe168aa791e288b303f1ab1df313b5}
  config: {sha256: d1da4d7f7067e36270bec367e5c70ab4553f154e707e1a0b1e8a001ea599050b}
  executable: {sha256: e13ce1b1361b3123db66f899bb564163ce7a1dfda9a25cc8e255468e4ce50784}
---

## План

Адрес `149.154.175.50:443` указан в [исходном коде Android-клиента
Telegram](https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/jni/tgnet/ConnectionsManager.cpp)
как адрес дата-центра. Это не подтверждение его текущей доступности или
пригодности для Telegram Web. Одна попытка ограничивает нагрузку и не
образует достаточной выборки для вывода об адресах Telegram в целом.

Повторный SYN останавливает серию автоматически, но другие TCP-повторы этот
счётчик не распознаёт. Оператор наблюдает пакеты в отдельном терминале через
`tcpdump -nn -tt -S -l`, отслеживает повторение последовательностей исходящих
сегментов и при повторе или аномалии прерывает runner через Ctrl+C. Захват и
ручное прерывание асинхронны; уже отправленные пакеты не отзываются.

До запуска проверить отсутствие адреса в `docs/DO_NOT_SCAN.md`; пока файла нет,
нужно явное подтверждение пользователя на эту серию. Контакт Telegram для
сообщения об уязвимости указан в отчёте предыдущего пилота. PCAP и журнал —
вне git, каталог 0700, файлы 0600.

## Наблюдения

13 ноября 2026 года пользователь выполнил одну попытку. В клиентском
PCAP видны два исходящих SYN с одинаковым SEQ, с интервалом около 1,003 с;
входящих пакетов нет. Runner зафиксировал 2 кадра, 148 байт Ethernet,
нулевые потери capture и отменил подключение по заданному пределу первого
повторного SYN. Ошибка отмены означает выполнение этого условия остановки,
а не самостоятельный сетевой отказ. Серверного захвата нет, контроль другого
endpoint ещё не запущен.

Capability с бинаря снята; TSO, GSO, GRO и LRO после восстановления
показывают `on`. Какие значения были непосредственно во время пробы, по
представленным данным не установлено.

## Update 2026-11-13T19:27:27Z

- Было: `planned`; стало: `inconclusive`.
- Причина: в окне до остановки при первом повторном SYN ответ не наблюдался;
  место и причина отсутствия ответа не установлены, проверка SNI не проводилась.
