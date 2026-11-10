# Методология экспериментов

Правила планирования, проведения и документирования опытов DPIsect.
Методы и ограничения отдельных вопросов — в `RESEARCH_MATRIX.md`;
здесь — процесс, артефакты и критерии интерпретации.

## 0. Связанные документы

- `SAFETY.md` — допустимые цели, лимиты, привилегии. **Прочитать до
  планирования любой сетевой пробы.**
- `AGENTS.md` §Принципы — базовые инварианты (`valid-session` ≠
  `raw-experiment`, `helper` ≠ `target`).
- `DEVELOPMENT.md` — этапы и их критерии выхода; отчёт об опыте —
  условие завершения этапа.
- `RESEARCH_MATRIX.md` — источник истины по `question_id`, методам и
  ограничениям.

## 1. Терминология: три уровня воспроизводимости

Термины используются в смысле ACM (Dagstuhl guide):

| Уровень | Команда | Установка | Что означает |
| --- | --- | --- | --- |
| **Repeatability** | та же | та же | вы повторяете свой опыт в тех же условиях |
| **Replicability** | другая | та же | другая команда повторяет опыт на той же установке |
| **Reproducibility** | другая | другая | другая команда получает результат на своей установке |

Для внутренней валидации в DPIsect достаточно repeatability. Для
переноса результата на другую сеть или публикации требуется
reproducibility — и результат helper **не** гарантирует его.

## 2. Чек-лист «До запуска»

- [ ] `question_id` из матрицы; гипотеза и конкурирующие объяснения.
- [ ] Режим: `valid-session` или `raw-experiment` — с разными критериями
      успеха.
- [ ] Контроль и treatment: один изменяемый фактор; инварианты
      перечислены явно.
- [ ] Роли endpoint и допустимость raw-проб соответствуют
      `SAFETY.md` §1.
- [ ] Endpoint list и **бюджет серии** (см. структуру `budget` в §4):
      число повторов, интервалы, способ сброса состояния. Число
      повторов обосновывается ожидаемой вариабельностью, а не «пять по
      умолчанию».
- [ ] Правило классификации (`classification_rule`) сформулировано и
      сохранено **до** отправки первого пакета; оно определяет,
      какой исход считается `confirmed`, `refuted` или `inconclusive`.
- [ ] Проверка `SAFETY.md`: допустимые цели, привилегии
      (`CAP_NET_RAW`), изолированная среда.
- [ ] План пакетов (planned wire packets): логические байты, TCP
      split offsets, TLS record layout, TTL/SEQ/ACK/checksum — что
      именно планируется отправить; план сохранён в
      `experiments/<experiment_id>/plan.yaml` до отправки первого
      пакета.
- [ ] Seed для любого случайного выбора; зафиксирован.
- [ ] Для TTL-локализации: план сравнения триггера и контроля при
      каждом TTL; исключена автоматическая ретрансляция с обычным TTL.

## 3. Чек-лист «После запуска»

- [ ] Валидация фактических пакетов: сопоставлены planned vs captured
      с учётом offload (TSO/GSO/GRO), NAT, MTU/MSS, ретрансляций.
      Локальный capture и предупреждение Wireshark о checksum не
      доказывают, что пакет ушёл на линию.
- [ ] Клиентский и серверный PCAP сохранены **вне git**; путь и
      `sha256` записаны в отчёте.
- [ ] Для опыта с helper и серверным PCAP: после остановки helper выполнить
      `dpi-prober -finalize -config <config.yaml>` после переноса файлов; до
      финализации серверные хэши не входят в `run.json`. Команда не запускает
      сетевых проб; отсутствие файла или ошибка сохраняют старый `run.json`.
- [ ] Метаданные: commit/tag, версии зависимостей, seed, UTC-время,
      сеть, адреса и порты, маршрут, offload/NAT.
- [ ] `run.json` записан: версии, seed, UTC-времена, оператор, пути и
      `sha256` артефактов (`H07`); поля `reproduce` отчёта заполнены
      из него.
- [ ] Обоснован период выборки: полный capture или подмножество;
      частота сбора; timezone (UTC предпочтителен; если измерения
      зависят от суточного цикла — локальное время).
- [ ] Охарактеризован источник трафика: raw socket / kernel /
      user-space; интерфейс; offload; MTU/MSS.
- [ ] Вердикт по `classification_rule` ставит оператор/агент (§7);
      измерения — из `dpi-analyze`; результат —
      `confirmed` / `refuted` / `inconclusive`.
- [ ] Отчёт создан по шаблону (§4); артефакты связаны через
      `experiment_id`.

## 4. Шаблон отчёта

Обязательный минимум для `experiments/<experiment_id>/report.md`
(YAML front-matter + секции).

`experiment_id` = `<question_id>-<slug>-<YYYY-MM>`, например
`b01-sni-padding-2026-11`. Ветка — `exp/<question_id>-<slug>`, тег —
`exp/<experiment_id>` (см. `GIT_WORKFLOW.md` §3).

Статусы: `planned` → `in_progress` → `confirmed` | `refuted` |
`inconclusive`. Семантика исходов — §7. Изменение статуса
допускается, но сопровождается разделом `## Update <UTC>` с причиной
(см. §6).

Поля `budget` заполнены стартовыми дефолтами `SAFETY.md` §3;
превышение — только с обоснованием в `planned_wire_packets` и при
цели `lab`/`helper` (`SAFETY.md` §3).

```yaml
question_id: B01
experiment_id: b01-sni-padding-2026-11
status: planned # in_progress | confirmed | refuted | inconclusive
hypothesis: ...
alternative_hypotheses: [...]
mode: valid-session | raw-experiment
vantage: {network, address_family, capture_point}
endpoint: {role: helper|target|lab, ip, port}
control: {profile, ...}
treatment: {changed_factor, values}
invariants: [...]
budget:
  max_packets: 100
  max_bytes: 102400
  max_rate_pps: 10
  max_duration_s: 60
  stop_conditions: []
planned_wire_packets: ...
actual_wire_validation: ...
offload_and_nat: ...
route_metadata: ...
schedule: {repetitions, seed, inter_trial_gap, state_reset}
observations:
  client_pcap: <path outside git>
  server_pcap: <path outside git>
  helper_log: <path outside git>
  runner_log: <path outside git>
classification_rule: ...
results: {observation, compatible_hypotheses, excluded_hypotheses, inconclusive_reason}
reproduce:
  tool_commit: null
  dependency_versions: null
  config_file: null
  date_utc: null
  operator: null
  lab_config_id: null
  timestamps_utc: null
artifacts:
  pcap_client: {sha256: ...}
  pcap_server: {sha256: ...}
```

Поля `reproduce` заполняются из `run.json` — его пишет runner по
завершении прогона (`ARCHITECTURE.md` §4); отчёт заполняет
оператор/агент.

## 5. Артефакты и хранение

- В git — план, отчёт и метаданные: `experiments/<experiment_id>/`.
- Вне git — сырые PCAP и логи: `artifacts/<experiment_id>/`
  (в `.gitignore`, каталог `0700`, файлы `0600`) или внешнее
  хранилище. В отчёте — фактический путь и `sha256` каждого файла.
- Сроки хранения, права, аудит и обращение с `SSLKEYLOGFILE` —
  `SAFETY.md` §5 (канон политики): 90 дней от завершения этапа или
  публикации отчёта.
- Для долговременной публикации артефактов — Zenodo (DOI); DOI
  указывается в отчёте после публикации.

## 6. Изменение статуса

Каждое изменение уже присвоенного статуса сопровождается в
`report.md` разделом:

```markdown
## Update <UTC>
- Было: <status>; стало: <status>.
- Причина: <почему вывод изменился>.
```

Причина обязательна (получены дополнительные наблюдения, исправлена
ошибка в `classification_rule` и т.п.). Статус, изменённый без
такого раздела, не считается действительным.

## 7. Интерпретация исхода

`confirmed`, `refuted` и `inconclusive` — равноправные исходы.
Отрицательный и неопределённый результат валиден и не требует
повтора без изменения условий.

Вердикт по `classification_rule` ставит оператор/агент;
`dpi-analyze` даёт измерения и классификацию причин (`H01`),
но не выставляет статус (`ARCHITECTURE.md` §4).

| Данные | Статус | Действие |
| --- | --- | --- |
| `classification_rule` выполнено, наблюдение подтверждает гипотезу | `confirmed` | записать `results.excluded_hypotheses` |
| `classification_rule` выполнено, наблюдение опровергает гипотезу | `refuted` | записать причину в `results`; исход валиден |
| данных недостаточно, гипотезы неразличимы | `inconclusive` | записать `results.inconclusive_reason`; не выдавать за подтверждённый (`AGENTS.md` §Границы) |
| `classification_rule` не зафиксировано до отправки первого пакета | — | не классифицировать; вернуться к §2 |
