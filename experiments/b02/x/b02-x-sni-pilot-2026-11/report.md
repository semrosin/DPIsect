---
question_id: B02
experiment_id: b02-x-sni-pilot-2026-11
status: inconclusive
hypothesis: На выбранном IP исходы обычных TLS-подключений с именами example.com и x.com могут различаться.
alternative_hypotheses: [обработка имён сервером и сертификат, потери и состояние сети, различие размеров ClientHello, особенности WSL2 и захвата]
mode: valid-session
vantage: {network: сеть пользователя через WSL2, address_family: ipv4, capture_point: eth0}
endpoint: {role: target, ip: 172.66.0.227, port: 443}
control: {sni: example.com, note: принятие имени сервером и сертификат на endpoint не проверены}
treatment: {changed_factor: имя SNI, values: [x.com]}
invariants: [один IPv4 и порт, обычный TLS-клиент Go с проверкой сертификата, отдельные TCP-соединения, одинаковые таймауты и интерфейс]
budget: {max_packets: 100, max_bytes: 102400, max_rate_pps: 10, max_duration_s: 60, max_syn_retransmissions: 1, stop_conditions: [первый повторный SYN, лимит, ошибка или потери захвата, аномалия, SIGINT]}
planned_wire_packets: Runner сохраняет plan.yaml с байтами ClientHello до подключения; последующие пакеты зависят от ответа, сегментация и повторы управляются ядром.
actual_wire_validation: TCP установлен, ClientHello example.com виден в исходящем кадре с 1515 байтами TCP-данных; монитор остановил серию при кадре сверх допуска MTU. Внешний tcpdump показал последующие ответные данные, но handshake не завершён.
offload_and_nat: WSL2 и NAT ограничивают выводы; состояние offload непосредственно до пробы не установлено.
route_metadata: Перед пробой уточнить маршрут.
schedule: {repetitions: 1, seed: 0, inter_trial_gap_ms: 3000, state_reset: none}
observations: {client_pcap: artifacts/b02-x-sni-pilot-2026-11/client.pcap, server_pcap: null, helper_log: null, runner_log: artifacts/b02-x-sni-pilot-2026-11/runner.log}
classification_rule: Пилот из двух подключений не отвечает на полный B02; фиксируются исходы TCP и TLS, проверка сертификата, размеры ClientHello и ограничения захвата. B02 остаётся inconclusive.
results: {observation: TCP установлен и example.com отправлен; монитор отменил TLS, x.com не отправлялся, compatible_hypotheses: [offload исказил размер кадра в локальном захвате, сервер или сеть ответили данными], excluded_hypotheses: [], inconclusive_reason: сравнение имён не состоялось}
reproduce:
  tool_commit: 'unknown'
  dependency_versions:
    github.com/google/gopacket: v1.1.19
    golang.org/x/net: v0.0.0-20190620200207-3b0461eec859
    golang.org/x/sys: v0.0.0-20190412213103-97732733099d
    gopkg.in/yaml.v3: v3.0.1
  config_file: experiments/b02/x/b02-x-sni-pilot-2026-11/config.yaml
  date_utc: '2026-11-14'
  operator: qjolk
  lab_config_id: null
  timestamps_utc: '2026-11-14T17:19:09.028345603Z — 2026-11-14T17:19:09.340146909Z'
  run_json: experiments/b02/x/b02-x-sni-pilot-2026-11/run.json
artifacts:
  pcap_client: {sha256: 87cbf82ed16f7634d8671b83d0b30abcac6c23d07d093625f7eb81eae787d8be}
  pcap_server: null
  runner_log: {sha256: 4e4365c2a58bc73e09f5f58825915f43a685e730752184407632c7619c845cd2}
  observations: {sha256: b4dff48b14f78cc3e54db14ec3502e46d84f82204e6d800a941695ad59d38854}
  wire_plan: {sha256: 91d423622a466ec7083888df63201872755f80eb15d494ad3c687b2e9c94bf0a}
  config: {sha256: 9feb766434883d6e8f92e2d49739afd2a41761512d49ffd805f7803ab56c5d0a}
  sni_schedule: {sha256: c8d59ee8719ffae4e1c248ddaf8966f78b52fa5928461e7a090d5bfa9258ce5b}
  run_json: {sha256: 39605356f83ff078d37c640d24807d95306c761a0d2dc3df42837c15ffca17f7}
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

## Update 2026-11-14T17:19:09Z

- Было: `planned`; стало: `inconclusive`.
- Причина: монитор остановил серию из-за кадра больше допуска MTU;
  отправлен только ClientHello с `example.com`, попытка `x.com` не началась.
  Runner учёл 4 кадра и 1795 байт, 0 потерь capture и 0 повторов SYN;
  внешний tcpdump увидел позднейшие данные. Ошибка `context canceled` вызвана
  остановкой пробера и не означает отказ сервера. После пробы MTU 1280,
  TSO/GSO/GRO включены, LRO выключен; непосредственно до пробы не проверено.
  Метаданные и дополнительные хэши сохранены в `run.json`.
