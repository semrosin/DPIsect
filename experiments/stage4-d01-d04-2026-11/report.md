---
question_id: D01–D04
experiment_id: stage4-d01-d04-2026-11
status: inconclusive
hypothesis: >
  Наблюдатель на пути может обрабатывать fake-пробу с независимо
  изменённым TTL, SEQ, ACK или TCP checksum иначе, чем корректную
  пробу, и это меняет обработку следующего ClientHello.
alternative_hypotheses:
  - "Наблюдателя на лабораторном маршруте нет; различия объясняются только поведением TCP endpoint."
  - "Fake-проба с корректными полями сама принимается endpoint и меняет stream, поэтому контрольный arm нельзя считать отсутствием воздействия."
  - "Одной репетиции недостаточно для вывода о воспроизводимости."
mode: raw-experiment
vantage:
  network: Linux network namespaces client → router → helper
  address_family: ipv4
  capture_point: >
    AF_PACKET на client veth-c и server veth-s; fake-проба считается
    доставленной только если она присутствует в server PCAP.
endpoint: {role: lab, ip: 10.77.2.2, port: 8443}
control:
  profile: d01-control / d02-control / d03-control / d04-control
  lab_enabled: false
  helper_profile: accepting
  notes: >
    Router namespace — обычный Linux forwarder без DPI. Helper —
    собственный процесс в server namespace. Offload на обоих veth
    выключен перед прогоном.
treatment:
  changed_factor: TTL, SEQ, ACK, TCP checksum
  values: [ttl=1, seq=out_of_order, seq=old, ack=wrong, checksum=corrupt]
invariants:
  - "SNI=probe.example; fake и real ClientHello построены одним генератором."
  - "D01/D02/D04: fake и real в одном TCP-соединении; D03: fake в отдельном соединении, real в свежем."
  - "Бюджет: 100 пакетов, 102400 байт, 10 pps, 60 с; одна репетиция на arm."
  - "Raw только к lab endpoint; target не использовался."
budget:
  max_packets: 100
  max_bytes: 102400
  max_rate_pps: 10
  max_duration_s: 60
  stop_conditions:
    - превышение пакетного или байтового бюджета
    - истечение max_duration_s
planned_wire_packets: >
  Для каждого arm: одна fake-проба (139 байт) с выбранным полем и
  следующий real ClientHello (139 байт). D01 ttl1: fake TTL=1; D02
  out_of_order: SEQ = SndNxt + len(payload); D02 old: SEQ = SndNxt -
  1 MiB; D03 wrong: ACK = RcvNxt + 1 в отдельном TCP-соединении; D04
  corrupt: TCP checksum инвертирован. Планы сохранены в
  `runs/<arm>/plan.yaml` до первого пакета.
actual_wire_validation: >
  `dpi-analyze -raw` сопоставил payload hash, TTL, SEQ, ACK и checksum
  с client PCAP; доставка проверена по server PCAP. D01 TTL=1:
  fake есть на client veth, отсутствует на server veth, server ACK
  до real ClientHello нет → `not_delivered`. D01 TTL=64: fake есть на
  обоих, ACK до real → `accepted`. D02 old/out_of_order: fake доставлен,
  ACK не подтверждает конец fake payload → `not_accepted`. D03 wrong
  ACK: fake доставлен, но helper не получил ClientHello в первом
  соединении; real в свежем соединении доставлен → `not_accepted`.
  D04 corrupt: fake виден на server veth, ACK до real нет → `rejected`;
  D04 control → `accepted`.
offload_and_nat: >
  NAT отсутствует. `ethtool -K veth-c/veth-s tx off rx off tso off gso
  off gro off` выполнен до прогона; снимки `offload-*.txt` лежат в
  artifacts. D04 corrupt checksum совпал на client и server capture,
  поэтому результат не объясняется локальным исправлением checksum.
route_metadata: >
  client 10.77.1.2/24 → router 10.77.1.1/10.77.2.1 → helper
  10.77.2.2/24; `ip_forward=1` в router namespace. TTL=1 истекает на
  router, поэтому helper его не видит.
schedule: {repetitions: 1, seed: 42, inter_trial_gap_ms: 100, state_reset: none}
observations:
  client_pcap: artifacts/<arm>/client.pcap
  server_pcap: artifacts/<arm>/server.pcap
  helper_log: artifacts/<arm>/helper.log
  runner_log: artifacts/<arm>/runner.log
  raw_observations: experiments/stage4-d01-d04-2026-11/runs/<arm>/raw-observations.json
  analysis: artifacts/<arm>/analysis.json
classification_rule: |
  Confirmed iff the treatment changes the endpoint/observer response
  relative to its control across all repetitions with only the named
  field changed. Refuted iff treatment equals control. Inconclusive
  iff no observer is present on the path or the endpoint behavior
  cannot be separated from DPI reaction.
results:
  observation: >
    D01: TTL=64 fake принят endpoint, TTL=1 fake не дошёл до server
    veth; real ClientHello виден в обоих arm. D02: control принят;
    old и out_of_order fake не приняты (ACK не подтверждает конец fake
    payload), real ClientHello доставлен. D03: control fake принят в
    первом соединении; wrong ACK fake не дал ClientHello в helper,
    real в свежем соединении доставлен. D04: control принят; corrupt
    checksum fake дошёл до server veth, но endpoint его не подтвердил,
    real ClientHello доставлен. Во всех arm endpoint-поведение
    подтверждено; DPI-наблюдателя на пути нет.
  compatible_hypotheses:
    - "Endpoint-поведение для TTL/SEQ/ACK/checksum измерено и воспроизводимо в одном пилоте."
    - "Различия treatment/control объясняются TCP-стеком endpoint, а не DPI."
  excluded_hypotheses:
    - "D01 TTL=1 fake дошёл до helper: исключено server PCAP."
    - "D04 corrupt checksum был исправлен локальным offload: исключено совпадением checksum на client и server capture."
    - "D03 wrong ACK fake был принят как ClientHello: исключено helper.log (в первом соединении нет client_hello)."
  inconclusive_reason: >
    На маршруте нет DPI-наблюдателя: router — обычный Linux forwarder.
    Поэтому нельзя утверждать, что fake-проба изменила обработку
    ClientHello наблюдателем. Пилот также содержит одну репетицию на arm.
reproduce:
  tool_commit: 4e1cd8c-dirty
  dependency_versions:
    github.com/google/gopacket: v1.1.19
    golang.org/x/net: v0.0.0-20190620200207-3b0461eec859
    golang.org/x/sys: v0.0.0-20190412213103-97732733099d
    gopkg.in/yaml.v3: v3.0.1
  config_file: experiments/stage4-d01-d04-2026-11/runs/<arm>/config.yaml
  date_utc: "2026-11-24"
  operator: "root (unprivileged user namespace; host user darya)"
  lab_config_id: netns-router-2026-11
  timestamps_utc: "2026-11-24T16:32:27Z — 2026-11-24T16:32:45Z"
artifacts:
  pcap_client: artifacts/<arm>/client.pcap
  pcap_server: artifacts/<arm>/server.pcap
  analysis: artifacts/<arm>/analysis.json
  run_json: experiments/stage4-d01-d04-2026-11/runs/<arm>/run.json
---

## Наблюдения

Запуск: `2026-11-24T16:32:27Z — 16:32:45Z`, tool `0.1.0-stage4`
@ `4e1cd8c-dirty`, seed 42, по одной репетиции на arm. Все прогоны
завершились кодом 0; `run.json` и server-хэши записаны после остановки
helper'а. `dpi-analyze` для raw-трасс даёт `cause=inconclusive` или
`tls_alert`; это классификатор обычного TLS-потока, а не вердикт по
D01–D04. Evidence по вопросам — `raw_actual_validation` и server PCAP.

| arm | fake на client | fake на server | ACK до real | real ClientHello | endpoint |
| --- | --- | --- | --- | --- | --- |
| d01-control | да, TTL 64 | да | да | да | accepted |
| d01-ttl1 | да, TTL 1 | нет | нет | да | not_delivered |
| d02-control | да | да | да | да | accepted |
| d02-old | да | да | да, но не конец fake | да | not_accepted |
| d02-out-of-order | да | да | да, но не конец fake | да | not_accepted |
| d03-control | да | да | да | да | accepted |
| d03-wrong-ack | да | да | да, но не конец fake | да, в свежем TCP | not_accepted |
| d04-control | да | да | да | да | accepted |
| d04-corrupt-checksum | да, checksum corrupt | да | нет | да | rejected |

### D01 — TTL

TTL=64 fake принят endpoint, TTL=1 fake не дошёл до server veth.
Разница между control и treatment на endpoint подтверждена. Это
наблюдение о маршруте и TCP endpoint, не о DPI. Статус по DPI:
`inconclusive`.

### D02 — SEQ

`old` и `out_of_order` fake доставлены до server veth, но endpoint не
подтвердил конец fake payload; real ClientHello доставлен. Control
fake принят. Это подтверждает, что endpoint различает SEQ-режимы;
DPI-реакция не наблюдалась. Статус: `inconclusive`.

### D03 — ACK

В control fake с корректным ACK принят в первом TCP-соединении, real
ClientHello — во втором. В wrong-ACK arm helper не увидел ClientHello
в первом соединении (`parse_error: EOF`), real ClientHello доставлен
в свежем соединении. Endpoint-различие подтверждено; DPI-реакция не
наблюдалась. Статус: `inconclusive`.

### D04 — checksum

Control fake принят. Corrupt-checksum fake присутствует в client и
server PCAP, но server не отправил ACK до real ClientHello; real
ClientHello доставлен. Offload выключен, checksum на обоих capture
совпадает с планом. Endpoint отбрасывает corrupt checksum; DPI-реакция
не наблюдалась. Статус: `inconclusive`.

## Ограничения

- На маршруте нет реального DPI/цензора; router namespace только
  форвардит пакеты. Нельзя делать вывод о реакции наблюдателя.
- Одна репетиция на arm; это пилот, не оценка воспроизводимости.
- Helper завершает TLS-handshake ошибкой после синтетического
  ClientHello: клиент однонаправленный и закрывает сокет. Это
  ожидаемо и не является сетевым вмешательством.
- Server PCAP на veth-s видит пакет до проверки checksum хостом;
  поэтому `fake_seen_server` означает доставку до точки захвата, а
  `accepted/rejected` определяется по ACK до real ClientHello.
- В D03 control прогон занял около 10 с из-за ожидания helper'а
  in-flight handler; на результат не влияет.

## Артефакты (sha256)

```text
d01-control client.pcap       efbb778e7e014df87df329e40fec6812e6a73aecb9b32f18e6f9a344582ae7c2
d01-control server.pcap       89d30b3e7d633d78189d3cbd0833216af06542964c4d6d869086176c356ab8a9
d01-ttl1 client.pcap          ff75224c7b4d79009be2eaa95904d06b5eb391cbe91c0a7fa7afd4c0518ade0a
d01-ttl1 server.pcap          63b28b0d47d287fe49baeaa261d00d12bcd78e9f7298c6d1b683124a1ff11789
d02-control client.pcap       174c9804f484ff995588b611a2bd96843f7923e654e21ac27180929a3db2c46a
d02-control server.pcap       1f5f492e0fe2ce6ae297cb7261f7053b1d61a519acb4abf199e6f62fd83aa2d0
d02-old client.pcap           b6917c913664d965a7845b8f5cee2dcb99cfb6a930d69c0f2f63dd08ee68e948
d02-old server.pcap           a43db11ec799e00a195ee00aa8cd4c2d230d87555f451866927af9c8631bb4e5
d02-out-of-order client.pcap  fe03e620c19f2e57c910e71a849bfa69ba56b206c68deff85f4cd9b35cbce0c5
d02-out-of-order server.pcap  bc21fa04494f94289164e86758643bfb56ef2956b8a0f4dddf322cbeaa1b0d3d
d03-control client.pcap       bd38baafc556325be1e4c031cb02d6850f4969ea7523ca0956a6983b94b2c178
d03-control server.pcap       56308f3a85feb9bc636e3a54d379848c20f3cb4e324511ada580abf8ea98cda3
d03-wrong-ack client.pcap     76c8c99001762ed722d0c1c56ac086082e71f70ccfccd2418f935dac41f565a3
d03-wrong-ack server.pcap     fb97ae84875bd6acac9a9ed6fc102878ef2cc60912844c31134536f8615f4a64
d04-control client.pcap       44aca1621fe0d7632d994fe9e8632ea763aa95676191886af5ef293c6aa69a8a
d04-control server.pcap       39c8840197a779310f388c1da341a3d53fe7aac95b120ea73fbb420e1139a818
d04-corrupt-checksum client.pcap  52ebd943d0f40c6c21b5ef6c6f3b55eb43815d6ccae74b9c26b087b3f7bf6afe
d04-corrupt-checksum server.pcap  67f6805d1386ae7f4ec0ba600cc33ae511bd70835f979b3c8173101ff1e8a034
```
