---
question_id: C03
experiment_id: c03-loopback-order-2026-11
status: inconclusive
hypothesis: "Порядок доставки TCP-сегментов может влиять на реакцию наблюдателя при одинаковом восстановленном потоке."
alternative_hypotheses: ["Реакция зависит от собранного потока", "Реакция зависит от тайминга", "Исходный симптом вызван другим фактором"]
mode: valid-session
vantage: {network: "изолированное пространство имён", address_family: IPv4, capture_point: "входящие кадры AF_PACKET на lo после netem"}
endpoint: {role: lab, ip: 127.0.0.1, port: ephemeral}
control: {delay_ms: 30, expected_offsets: [0, 48]}
treatment: {changed_factor: "доставка второго сегмента перед первым", expected_offsets: [48, 0]}
invariants: ["байты ClientHello", "TCP split offset 48", "TLS record layout", "локальная точка захвата"]
budget: {plan: plan.yaml, max_captured_frames_per_attempt: 64, deadline_s_per_connection: 5}
planned_wire_packets: plan.yaml
actual_wire_validation: "Входящий PCAP показал порядок [0, 48] в контроле и [48, 0] в опыте. Приёмник прочитал одни и те же 142 байта."
offload_and_nat: "Loopback без NAT. Исходящие копии отфильтрованы, отдельное изменение offload не применялось."
route_metadata: "Только lo в отдельном пространстве имён. Linux netem включён после TCP-handshake."
schedule: {repetitions: 1, seed: null, state_reset: "новый TCP-сеанс на вариант"}
observations: {runner_log: "artifacts/c03-loopback-order-2026-11/test.log", pcap_index: run.json}
classification_rule: "См. plan.yaml. Для исследовательского вывода требуется наблюдаемая реакция DPI."
results:
  observation: "Калибровка пройдена. Порядок первых появлений TCP-диапазонов изменён, граница TCP на 48 и конец TLS record на 142 сохранены. IPv4-фрагментации нет."
  compatible_hypotheses: ["Реакция зависит от порядка", "Реакция зависит от тайминга", "Реакция зависит от восстановленного потока"]
  excluded_hypotheses: []
  inconclusive_reason: "Стенд содержит TCP-приёмник, но не наблюдатель DPI на исследуемом маршруте. Данных о реакции наблюдателя нет."
reproduce: {metadata: run.json, config_file: plan.yaml, date_utc: "2026-11-20", operator: Codex}
artifacts: {paths_and_sha256: run.json}
---

Ядро отправило один и тот же ClientHello через обычный TCP. `netem`
изменил порядок доставки. После сборки TCP принимающее приложение
сравнило прочитанные байты с исходным сообщением. Проверка завершилась
на ответном маркере. TLS-handshake не входил в калибровку.

| Вариант | Первое появление диапазонов в PCAP | Диапазоны в TCP-потоке | Конец TLS record | Кадры |
| --- | --- | --- | ---: | ---: |
| Контроль | 0, 48 | [0, 48), [48, 142) | 142 | 8 |
| Перестановка | 48, 0 | [0, 48), [48, 142) | 142 | 8 |

[План](plan.yaml) и [метаданные](run.json) содержат параметры netem,
версию теста, пути и SHA-256 обоих PCAP и журнала. Сырые артефакты
сохранены вне git в `artifacts/c03-loopback-order-2026-11/`.
Первый прогон с относительным путём не сохранил PCAP. Его журнал лежит
в `failed-artifact-path/` и не входит в таблицу.

## Errata 2026-11-24

План использует локальные пределы числа кадров и дедлайна, а не полный
набор полей budget из шаблона EXPERIMENTS.md. Порт назначался ядром;
фактические значения для попыток находятся в run.json. План и run.json
сохранены в исходном виде, недостающие поля бюджета задним числом
не объявляются заранее установленными.
