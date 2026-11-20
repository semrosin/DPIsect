---
question_id: C03
experiment_id: c03-loopback-tls-2026-11
status: confirmed
hypothesis: "Локальный Go-сервер завершает проверяемый TLS 1.3 при обоих порядках доставки двух TCP-сегментов ClientHello."
alternative_hypotheses: ["Перестановка не произошла", "Обратная доставка мешает завершить TLS на стенде"]
mode: valid-session
vantage: {network: "изолированный loopback", address_family: IPv4, capture_point: "входящие кадры AF_PACKET после netem"}
endpoint: {role: lab, ip: 127.0.0.1, port: ephemeral}
control: {first_seen_offsets: [0, 32]}
treatment: {changed_factor: "порядок доставки TCP", first_seen_offsets: [32, 0]}
invariants: ["граница TCP на 32", "TLS 1.3 и один TLS record ClientHello", "сертификат тестового сервера"]
budget: {plan: plan.yaml}
planned_wire_packets: plan.yaml
actual_wire_validation: "Все шесть захватов имеют одну TCP-границу 32 и ожидаемый порядок первых появлений диапазонов."
offload_and_nat: "Loopback без NAT. Исходящие копии отфильтрованы, отдельная настройка offload не менялась."
route_metadata: "Только lo в отдельном сетевом пространстве имён."
schedule: {repetitions: 3, seed: null, state_reset: "отдельный TCP-сеанс"}
observations: {pcap_and_log_index: run.json}
classification_rule: "Совместимость на стенде подтверждается, если порядок следует плану и все попытки проходят проверку сертификата и обмен HTTP."
results:
  observation: "6 из 6 сессий завершили проверенный TLS 1.3 и получили ожидаемый HTTP-ответ. Один TLS record длиной 255 байт, IPv4-фрагментации нет."
  compatible_hypotheses: ["TCP восстанавливает поток для TLS при обоих проверенных порядках."]
  excluded_hypotheses: ["В этой серии перестановка не произошла", "Проверенная перестановка препятствует TLS на локальном endpoint"]
reproduce: {metadata: run.json, config_file: plan.yaml, date_utc: "2026-11-20", operator: Codex}
artifacts: {paths_and_sha256: run.json}
---

| Вариант | Порядок диапазонов в PCAP | TLS и HTTP |
| --- | --- | --- |
| Контроль | 0, 32 | 3/3 |
| Обратный порядок | 32, 0 | 3/3 |

Случайные поля ClientHello различались между TLS-сессиями. Каждая
запись сверена со своим исходным сообщением. В [калибровке C03](../c03-loopback-order-2026-11/report.md)
байт-в-байт восстановление одинакового потока проверено отдельной
парой. Результат полной TLS-сессии относится к локальному endpoint.
Реакция наблюдателя DPI остаётся `inconclusive`.

Шесть PCAP и три журнала сохранены вне Git. Пути и SHA-256 указаны
в [метаданных](run.json).
