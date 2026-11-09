# Архитектура DPIsect

Роли и границы компонентов, поток данных и контракты между ними.
Требование — `DEVELOPMENT.md` §Этап 1 (подшаг 3, критерий выхода).
Термины — `GLOSSARY.md`; стиль и структура каталогов — `GO_STYLE.md` §8.

Scope v1: TLS ClientHello поверх TCP, только Linux. Что не входит в v1 —
`DEVELOPMENT.md` §«Вне scope v1» (IPv6, QUIC, ECH, HTTP, `A05`/`A06` и др.).

## 1. Компоненты: роли и границы

| Компонент | Роль | Граница (не делает) | Где в коде |
| --- | --- | --- | --- |
| `generator` | Построение проб: ClientHello builder, TLS-record builder, packet scheduler, TCP split offsets, TTL/SEQ/ACK/checksum, тайминг между пакетами; режимы `valid-session` и `raw-experiment` | Не отправляет пакеты, не захватывает, не классифицирует | `internal/generator` |
| `runner` | Оркестрация опыта по `config.yaml`: preflight (`dnsprobe`), бюджет серии, kill switch, seed, повторы, расписание, `plan.yaml`, `run.json`, `runner_log`; запуск capture и отправки | Не классифицирует результаты; не пишет `report.md` | `cmd/dpi-prober`, `internal/runner` |
| `dnsprobe` | Preflight до сери: сравнение системного резолвера с независимым источником, TCP-доступность (`G01`, `G02`); результаты — в observations | Не делает TLS-пробы и raw-отправку | `internal/dnsprobe`, вызов — runner |
| `sender` | Отправка плана на линию: обычный путь (OS TCP) и raw-путь за флагом и подтверждением | Не строит пакеты, не захватывает, не классифицирует; бюджет и kill switch — на runner | `internal/sender` |
| `capture` | Две точки захвата (клиент и helper), запись PCAP в `artifacts/` (вне git) | Не интерпретирует трафик | `internal/capture` |
| `helper` | Свой сервер: приём соединений, журнал серверных событий (парсинг ClientHello, TLS Alert, HTTP), server PCAP; профили «принимающий» и «отвергающий» | Не интерпретирует результаты опыта | `cmd/dpi-helper` |
| `analyzer` | Offline: измерения по PCAP/логам и классификация причин (`H01`) | Не отправляет пакеты, не запускает опыты; не ставит вердикт (см. §4) | `cmd/dpi-analyze`, `internal/analyzer` |
| `lab` | Управляемый стенд: drop / reorder / delay / MTU через `tc` (netem), `veth` и network namespace | Не входит в бинари prober/helper; управление — из runner и тестов | `internal/lab` |

## 2. Поток данных

```text
config.yaml
  → preflight          (dnsprobe: DNS + TCP-доступность)
  → generator          (planned_wire_packets)
  → sender             (линия; raw-путь только lab/helper)
  → capture ×2         (client PCAP + server PCAP → artifacts/)
  → observations       (PCAP, dns_log, runner_log, helper_log)
  → dpi-analyze        (измерения + классификация причин H01)
  → run.json           (experiments/<experiment_id>/, пишет runner)
  → report.md          (experiments/<experiment_id>/, оператор/агент)
```

`plan.yaml` фиксируется в `experiments/<experiment_id>/` до отправки
первого пакета; сверка planned vs actual — в измерениях analyzer
(`EXPERIMENTS.md` §3). Поля отчёта — `EXPERIMENTS.md` §4; семантика
исходов и автор вердикта — `EXPERIMENTS.md` §7.

## 3. Граница `valid-session` vs `raw-experiment` в коде

- Режимы — разные пути в коде: разные типы возвращаемых результатов,
  разные критерии ошибок, разные тесты (`GO_STYLE.md` §4).
- `raw-experiment` по построению не может быть направлен по чужому
  `target` без явного флага и подтверждения (`GO_STYLE.md` §4,
  `SAFETY.md` §1).
- По умолчанию — `valid-session`. Для чужого `target` — только обычные
  подключения (`SAFETY.md` §1).
- Успех `raw-experiment` — полученные наблюдения, а не открытая
  HTTPS-сессия (`GLOSSARY.md` §6).

## 4. Интерфейсы (контракты)

Документные контракты; точные Go-типы — в скелете `internal/`.
Изменение контракта — правка этого раздела до кода.

| Контракт | Направление | Содержание |
| --- | --- | --- |
| `PlannedWirePacket` | generator → runner | Логические байты, TCP split offsets, TLS record layout, TTL/SEQ/ACK/checksum, тайминг `SendAfterMS` (`GO_STYLE.md` §3) |
| Запуск/останов capture | runner → capture | Точка захвата, путь файла, время окна |
| Отправка | runner → sender | По одному пакету плана; raw-путь — только при установленном флаге и подтверждении; бюджет и kill switch — на стороне runner (`SAFETY.md` §3) |
| Preflight | runner → dnsprobe | Имя для резолва, независимый резолвер, endpoint; результаты — в observations (`dns_log`) |
| План пакетов | runner → `plan.yaml` | Персистентность плана до первого пакета (`EXPERIMENTS.md` §2) |
| Метаданные прогона | runner → `run.json` | Версии бинаря и зависимостей, seed, UTC-времена, оператор, `lab_config_id`, пути и `sha256` артефактов (`H07`) |
| Серверные события | helper → observations | `helper_log` + server PCAP (пути вне git, `sha256` в отчёте) |
| `ClassificationResult` | analyzer ← observations | Измерения + классификация причин (`H01`); вердикт `confirmed` / `refuted` / `inconclusive` по `classification_rule` ставит оператор/агент (`EXPERIMENTS.md` §7) |

`classification_rule` — проза в `config.yaml`, фиксируется до первого
пакета; analyzer его не применяет. `analyzer` читает только артефакты;
обратной связи в sender нет.

## 5. Бинари и каталоги

- `cmd/dpi-prober` — клиент эксперимента (preflight, generator, runner,
  capture, sender).
- `cmd/dpi-helper` — сервер-приёмник.
- `cmd/dpi-analyze` — offline-классификатор (без привилегий и сети).
- `internal/` — все внутренние пакеты, включая `lab`, `dnsprobe`,
  `sender`.
- `testdata/` — размеченные fixtures с известными причинами.
- `experiments/<experiment_id>/` — в git: `config.yaml`, `plan.yaml`,
  `run.json`, `report.md`; при включённом preflight — также
  `dns_log.yaml`.
- `artifacts/` — сырые PCAP и логи (вне git; `SAFETY.md` §5).

## 6. Зависимости

- `github.com/google/gopacket` — парсинг и запись PCAP без cgo
  (`pcapgo`, `afpacket`); готовые слои TCP/TLS.
- `golang.org/x/sys/unix` — raw-сокеты и syscall-доступ на Linux.
- `gopkg.in/yaml.v3` — загрузка `config.yaml` опыта
  (`docs/config.example.yaml`).

Все три — зафиксированные исключения в правило «новая зависимость —
сначала спросить» (`AGENTS.md` §Границы); критерии допуска и
обоснование выбора — `GO_STYLE.md` §8.

## 7. Платформа и привилегии

- Только Linux: `//go:build linux` или суффикс `_linux.go`
  (`GO_STYLE.md` §5).
- `CAP_NET_RAW` — только коду отправки (`setcap` на бинарь `dpi-prober`,
  не запускать от root целиком; `SAFETY.md` §4).
- Тесты с привилегиями — под build-тегом `privileged`; `go test ./...`
  без привилегий не падает (`GO_STYLE.md` §5).

## 8. Логирование и артефакты

- Логи — `log/slog`, ключи по `GO_STYLE.md` §7; секреты не логируются.
- PCAP и сырые логи — `artifacts/<experiment_id>/` (вне git, права
  `0700`/`0600`); в отчёте — путь и `sha256` (`EXPERIMENTS.md` §5).
- Версия и commit бинаря — через `-ldflags`, вывод в `--version` и логи
  старта (нужно для `H07`; `GO_STYLE.md` §8).

## 9. Расширения этапов 3–5 (зафиксированы, не реализованы)

Чтобы не переписывать каркас при выходе на этапы 3–5
(`DEVELOPMENT.md`):

- Модель плана: отправка вне порядка, фейковые пакеты, многофазные
  прогоны (триггер → контроль) — `C03`, `D05`–`D09`, `E04`, `E05`.
- Endpoint matrix (несколько адресов/портов в одном прогоне) — `B02`.
- Структурированные метрики анализа (точка расхождения `A02`,
  направление потерь `A04`, атрибуция RST `A03`) — выход за рамки
  строкового `Results`.
- Методическое ограничение: в `valid-session` TCP-сегментацию в основном
  решает ядро (`TCP_NODELAY`, `TCP_MAXSEG`); точный контроль — только
  raw-путь (`lab` / `helper`).
