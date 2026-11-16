---
question_id: B02
experiment_id: b02-x-sni-again-2026-11
status: inconclusive
hypothesis: На выбранном IP исходы обычных TLS-подключений с именами example.com и x.com могут различаться.
alternative_hypotheses: [обработка имён сервером и сертификат, потери и состояние сети, различие размеров ClientHello, особенности WSL2 и захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 172.66.0.227, port: 443}
control: {sni: x.com, note: первое имя в расписании; принятие имени сервером и сертификат не проверены}
treatment: {changed_factor: имя SNI, values: [example.com]}
invariants: [один IPv4 и порт, обычный TLS-клиент Go с проверкой сертификата, отдельные TCP-соединения, одинаковые таймауты и интерфейс]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Runner сохраняет plan.yaml с байтами ClientHello до подключения; последующие пакеты зависят от ответа, сегментация и повторы управляются ядром.
actual_wire_validation: Внешний tcpdump показал два TCP handshake; после x.com подтверждены байты ClientHello, TLS-данные не наблюдались 5 секунд; после example.com получены TCP-данные. Видны повторы FIN первого соединения и данных второго.
offload_and_nat: WSL2 и NAT ограничивают выводы; состояние offload непосредственно до пробы не установлено.
route_metadata: Перед пробой уточнить маршрут.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/b02-x-sni-again-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-x-sni-again-2026-11/runner.log}
classification_rule: Пилот из двух подключений не отвечает на полный B02; фиксируются исходы TCP и TLS, проверка сертификата, размеры ClientHello и ограничения захвата. B02 остаётся inconclusive.
results: {observation: x.com истёк по таймауту TLS; example.com получил данные, затем TLS отменён монитором, compatible_hypotheses: [разное поведение сервера по имени, сетевое вмешательство, потери или состояние сети, различие ClientHello], excluded_hypotheses: [], inconclusive_reason: одна пара, TLS контроля отменён, возможны серверные различия, повторы TCP и отсутствие серверного наблюдения}
reproduce:
  tool_commit: 'unknown'
  dependency_versions:
    github.com/google/gopacket: v1.1.19
    golang.org/x/net: v0.0.0-20190620200207-3b0461eec859
    golang.org/x/sys: v0.0.0-20190412213103-97732733099d
    gopkg.in/yaml.v3: v3.0.1
  config_file: experiments/b02-x-sni-again-2026-11/config.yaml
  date_utc: '2026-11-14'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-14T17:45:12.443839867Z — 2026-11-14T17:45:20.858487774Z'
  run_json: experiments/b02-x-sni-again-2026-11/run.json
artifacts:
  pcap_client: {sha256: 464db923ff56185cd7bd84f65aad3daf6706657b5fc2781b9217f83146f12bd5}
  pcap_server: null
  runner_log: {sha256: 0294a57f6388dff5eba0517eef064761f91201e486aeba155ec83393243d3de3}
  observations: {sha256: 8b345a49443b275a0f34019d42a0a5209cdd71d02ef4f7da7cea88606b12a83c}
  wire_plan: {sha256: 04f8bd62376ef2d602cfd4a5757838e09f4b6a16ef24e70d5ccca2ab424831cf}
  config: {sha256: 05578ea294aed65467c65db013b39a6a0f7558fb8012a8de064175b39c016d12}
  sni_schedule: {sha256: 3bccaa166ae6a0cc07143fd9874200498a795cc25c8a9776e799122cd769b90e}
  run_json: {sha256: 96b3a511e5cffa7e373d800ca4dd2e80236481ea3c3771edeae28f8d85553cb1}
---

## План и ограничения

Одиночный TCP-контроль к этому адресу установлен, см. соседний отчёт
`b02-x-tcp-retry-2026-11`. Контрольное имя выбрано как допустимое DNS-имя;
неизвестно, обслуживает ли endpoint это имя и выдаёт ли подходящий сертификат.
Имена разной длины, генератор не обеспечивает одинаковые ClientHello. Один
пилот не устанавливает устойчивость эффекта или его причину. Возможна остановка
монитора на 90% лимита частоты, включая при обычном TLS-обмене.

Только обычные TLS-соединения без HTTP; пользователь выполняет сетевые команды.
При обнаружении уязвимости остановиться; контакт —
[центр помощи X](https://help.x.com/en/rules-and-policies/reporting-security-vulnerabilities).
Повторный SYN останавливает runner автоматически. Оператор следит за остальными
повторами TCP через tcpdump и при них или аномалии прерывает серию Ctrl+C.

Первое имя x.com выбрано после остановки предыдущего повтора на лимите
частоты при example.com. Сырые данные повтора сохранены в
artifacts/b02-x-sni-retry-2026-11/; его метаданные удалены пользователем.
Тот повтор зафиксировал 16 кадров и 9 исходящих за секунду, TLS отменён
монитором; x.com не отправлялся. Это не позволяет оценить B02.

Повтор по просьбе пользователя. Предыдущая попытка остановилась на ограничении частоты; такое поведение может повториться.

## Update 2026-11-14T17:45:20Z

- Было: `planned`; стало: `inconclusive` для B02.
- Причина: при `x.com` TLS истёк через 5 секунд, при `example.com`
  получены данные, затем TLS отменён монитором на лимите 9 исходящих кадров
  в секунду. В пользовательском tcpdump видны повторы FIN после таймаута и
  повтор сегмента данных второй попытки; предусмотренная ручная остановка
  при повторах не произошла, что ограничивает интерпретацию и дальнейшие
  запуски. Runner зафиксировал 28 кадров, 10849 байт, ноль потерь capture
  и повторов SYN; внешний tcpdump содержит 38 кадров, включая после остановки.
  TSO/GSO/GRO восстановлены пользователем; остальные хэши и время в run.json.
