---
question_id: B02
experiment_id: b02-google-youtube-delay-2026-11
status: inconclusive
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
actual_wire_validation: TCP-handshake завершился; ClientHello Google передан двумя сегментами, второй сегмент повторён. Повтор захвачен и остановил серию; попытка YouTube не началась.
offload_and_nat: Пользовательский вывод показал исходные on, затем восстановление всех четырёх offload в on; скрипт проверяет отключение перед пробой. WSL2 и NAT ограничивают выводы клиентского захвата.
route_metadata: Вывод пользователя указал dev eth0 и шлюз WSL2; внешний маршрут и NAT не установлены.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none, client_hello_delay_ms: 1100}
observations: {client_pcap: artifacts/b02-google-youtube-delay-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-google-youtube-delay-2026-11/runner.log}
classification_rule: Пилот из двух подключений не отвечает на полный вопрос B02. Фиксируются исходы TCP и TLS, проверка сертификата, размеры ClientHello и ограничения захвата; B02 остаётся inconclusive.
results:
  observation: TCP к Google установлен, после паузы отправлен ClientHello. Второй исходящий сегмент повторён; монитор отменил TLS и не начал попытку YouTube.
  compatible_hypotheses: [потеря или задержка сегмента либо подтверждения, фильтрация, особенности маршрута или конечной системы]
  excluded_hypotheses: []
  inconclusive_reason: Сравнение имён не состоялось; причина повтора неизвестна, сертификат и TLS не проверены до завершения.
reproduce:
  tool_commit: 8056d0c
  dependency_versions: {github.com/google/gopacket: v1.1.19, golang.org/x/net: v0.0.0-20190620200207-3b0461eec859, golang.org/x/sys: v0.0.0-20190412213103-97732733099d, gopkg.in/yaml.v3: v3.0.1}
  config_file: experiments/b02/google-youtube/b02-google-youtube-delay-2026-11/config.yaml
  date_utc: '2026-11-17'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-17T10:17:51.412693015Z — 2026-11-17T10:17:52.931189373Z'
  run_json: experiments/b02/google-youtube/b02-google-youtube-delay-2026-11/run.json
artifacts:
  pcap_client: {sha256: 67b28fa896c1da1c9f6b51f541b1ae21495152cd5204509eef6620aa8966e353}
  pcap_server: null
  runner_log: {sha256: 2079ea99bf8bb0d65434318831a3e3f01741742e8e3cc608bb83ff4fdc20d7bc}
  observations: {sha256: 391dcdb8503ccfdfc911cb97553e6b98853cc2a977966288acee1d88b8e6d69b}
  wire_plan: {sha256: 9d4af9ebf902c9e16cc05b987265a41130070a27119217e705e06d4765baf30c}
  run_json: {sha256: 6205ec2e2755de7fd866223ec416cc34b6dec0058c6be13ce05e16a479ae76e9}
  config: {sha256: e38ac3cb14fb9c2375067cf64e8c1eb2b187615cd4db677626b9420c98ec8f16}
  sni_schedule: {sha256: c87046c7a8f4e1414cd63cb0c14cf6cbce9de0477abdc259ff96ae71ae3783c5}
  executable: {sha256: f91b1b61eed7fbee51825f181d6f35f3dca52400c4b3e7bafaac86fed56155ab}
---

## План и ограничения

Одна пара — пилот выполнимости. Между TCP-handshake и ClientHello для каждого
имени запланирована одинаковая пауза 1,1 секунды. Она меняет тайминг и не
гарантирует соблюдение лимита частоты. Обычный TLS не проверяет доступность
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
журналы — вне Git.

`run.sh` запускается пользователем: он проверяет маршрут и отсутствие ранее
созданных файлов, отключает offload, выдаёт capability одному проберу и
восстанавливает исходные настройки при обычном выходе, SIGINT или SIGTERM.
Если список Do Not Scan появился, скрипт останавливается до подключения.
Скрипт не проверяет актуальность сохранённого DNS-ответа от 14 ноября.

## Наблюдения

17 ноября пользователь выполнил серию. Клиентский PCAP содержит TCP-handshake,
затем через примерно 1,1 секунды ClientHello Google в двух сегментах размером
1228 и 290 байт. Входящий ACK подтвердил первый сегмент; примерно через 279 мс
после отправки второго наблюдался повтор того же диапазона TCP-последовательности.
Первые два сегмента побайтно совпадают с запланированным ClientHello длиной
1518 байт; содержимое повторного сегмента совпадает с исходным. Монитор
остановил серию по запланированному правилу. Всего записаны 7 кадров,
2286 байт, ноль потерь захвата и повторных SYN. Неуспешное завершение TLS
вызвано отменой пробера; причина повтора сегмента из клиентского захвата
неизвестна. Попытка с именем YouTube не началась.

Пользовательский скрипт снял capability и восстановил все четыре offload;
последующая локальная проверка подтвердила эти состояния. Серверного захвата
нет, а захват WSL2 не доказывает число пакетов на физической линии.

## Update 2026-11-17T10:17:52Z

- Было: `planned`; стало: `inconclusive`.
- Причина: сравнение не выполнено — контрольное TLS-соединение прервано при
  повторе TCP-данных; попытка YouTube не запускалась.
