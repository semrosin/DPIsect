---
question_id: C01
experiment_id: c01-loopback-layout-2026-11
status: inconclusive
hypothesis: "Границы TCP-сегментов могут влиять на наблюдаемый симптом после ClientHello."
alternative_hypotheses: ["Обработка endpoint", "Потери на маршруте", "Особенности захвата и offload"]
mode: valid-session
vantage: {network: "изолированное пространство имён", address_family: IPv4, capture_point: "входящие кадры AF_PACKET на lo"}
endpoint: {role: lab, ip: 127.0.0.1, port: ephemeral}
control: {tcp_split_offsets: []}
treatment: {changed_factor: "TCP split offset", values: [76, 85, 94]}
invariants: ["байты ClientHello", "TLS record layout", "локальная точка захвата"]
budget: {plan: plan.yaml, max_captured_frames_per_attempt: 64, deadline_s_per_connection: 5}
planned_wire_packets: plan.yaml
actual_wire_validation: "Границы TCP по PCAP совпали с планом, принимающий сокет прочитал 142 исходных байта в каждой попытке."
offload_and_nat: "Loopback без NAT. Захват отфильтровал исходящие копии кадров, отдельное изменение offload не применялось."
route_metadata: "Только lo в изолированном пространстве имён."
schedule: {repetitions: 1, seed: null, state_reset: "новый TCP-сеанс на вариант"}
observations: {runner_log: "artifacts/c01-loopback-layout-2026-11/test.log", pcap_index: run.json}
classification_rule: "См. plan.yaml. Для исследовательского вывода требуется симптом на исследуемом маршруте."
results:
  observation: "Калибровка пройдена. В захватах видны TCP-границы [], [76], [85] и [94]. Во всех вариантах один TLS record длиной 142 байта, IPv4-фрагментации нет."
  compatible_hypotheses: ["Обработка endpoint", "Потери на маршруте", "Сетевое вмешательство", "Особенности захвата"]
  excluded_hypotheses: []
  inconclusive_reason: "Стенд проверяет TCP-разметку и получение байтов. На нём отсутствует наблюдаемый сбой из этапа 2."
reproduce: {metadata: run.json, config_file: plan.yaml, date_utc: "2026-11-20", operator: Codex}
artifacts: {paths_and_sha256: run.json}
---

Четыре новых TCP-соединения использовали один и тот же ClientHello.
Тест остановил захват на ответном маркере приложения. TLS-handshake
явно не входил в калибровку. В рамках этой калибровки подтверждены
границы TCP и неизменность байтов TLS, а вывод про симптом остаётся
`inconclusive`.

| Вариант | TCP-сегменты, смещения начала | Конец TLS record | Кадры в PCAP |
| --- | --- | ---: | ---: |
| Без разбиения | 0 | 142 | 6 |
| До SNI | 0, 76 | 142 | 8 |
| Внутри SNI | 0, 85 | 142 | 8 |
| После SNI | 0, 94 | 142 | 8 |

[План](plan.yaml) и [метаданные](run.json) содержат версию теста,
адреса сокетов, пути и SHA-256 всех четырёх PCAP и журнала. Сырые
артефакты сохранены вне git в `artifacts/c01-loopback-layout-2026-11/`.
Первый прогон с относительным путём не сохранил PCAP. Его журнал лежит
в `failed-artifact-path/` и не входит в таблицу.

## Errata 2026-11-24

План использует локальные пределы числа кадров и дедлайна, а не полный
набор полей budget из шаблона EXPERIMENTS.md. Порт назначался ядром;
фактические значения для попыток находятся в run.json. План и run.json
сохранены в исходном виде, недостающие поля бюджета задним числом
не объявляются заранее установленными.
