---
question_id: C01
experiment_id: c01-loopback-tls-2026-11
status: confirmed
hypothesis: "Локальный Go-сервер завершает проверяемый TLS 1.3 при подтверждённой передаче одной записи ClientHello в одном или двух TCP-сегментах."
alternative_hypotheses: ["Разбиение не получилось в захвате", "Разбиение мешает завершить TLS на стенде"]
mode: valid-session
vantage: {network: "изолированный loopback", address_family: IPv4, capture_point: "входящие кадры AF_PACKET на lo"}
endpoint: {role: lab, ip: 127.0.0.1, port: ephemeral}
control: {tcp_split_offsets: []}
treatment: {changed_factor: "граница TCP", tcp_split_offsets: [32]}
invariants: ["TLS 1.3 и один TLS record ClientHello", "сертификат тестового сервера", "тестовый HTTP-ответ"]
budget: {plan: plan.yaml}
planned_wire_packets: plan.yaml
actual_wire_validation: "Три захвата с одним и три с двумя TCP-сегментами. Стартовые смещения подтверждены по TCP SEQ."
offload_and_nat: "Loopback без NAT. Исходящие копии отфильтрованы, отдельная настройка offload не менялась."
route_metadata: "Только lo в отдельном сетевом пространстве имён."
schedule: {repetitions: 3, seed: null, state_reset: "отдельный TCP-сеанс"}
observations: {pcap_and_log_index: run.json}
classification_rule: "Совместимость на стенде подтверждается, если все запланированные границы видны в PCAP и каждая сессия проходит проверку сертификата и обмен HTTP."
results:
  observation: "6 из 6 сессий завершили проверенный TLS 1.3 и получили ожидаемый HTTP-ответ. Один TLS record длиной 255 байт, IPv4-фрагментации нет."
  compatible_hypotheses: ["Локальный endpoint обрабатывает оба проверенных варианта."]
  excluded_hypotheses: ["В этой серии разбиение не произошло", "Проверенное разбиение препятствует TLS на локальном endpoint"]
reproduce: {metadata: run.json, config_file: plan.yaml, date_utc: "2026-11-20", operator: Codex}
artifacts: {paths_and_sha256: run.json}
---

| Вариант | Смещения TCP-сегментов | TLS и HTTP |
| --- | --- | --- |
| Контроль | 0 | 3/3 |
| Два сегмента | 0, 32 | 3/3 |

В каждой сессии использовались свежие TLS-случайные поля. Сверка с
захватом выполнена по байтам конкретной попытки. TCP-граница задана
независимо от SNI. Результат относится к совместимости локального
сервера. Исходный симптом на исследуемом маршруте остаётся
`inconclusive`. Результат [разметки вокруг SNI](../c01-loopback-layout-2026-11/report.md)
зафиксирован отдельно.

Шесть PCAP и три журнала сохранены вне Git. Пути и SHA-256 указаны
в [метаданных](run.json).
