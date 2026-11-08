# Архитектура DPIsect

Роли и границы компонентов, поток данных и контракты между ними.
Требование — `DEVELOPMENT.md` §Этап 1 (подшаг 3, критерий выхода).
Термины — `GLOSSARY.md`; стиль и структура каталогов — `GO_STYLE.md` §8.

Scope v1: TLS ClientHello поверх TCP, только Linux. Что не входит в v1 —
`DEVELOPMENT.md` §«Вне scope v1» (IPv6, QUIC, ECH, HTTP, `A05`/`A06` и др.).

## 1. Компоненты: роли и границы

| Компонент | Роль | Граница (не делает) | Где в коде |
| --- | --- | --- | --- |
| `generator` | Построение проб: ClientHello builder, TLS-record builder, packet scheduler, TCP split offsets, TTL/SEQ/ACK/checksum; режимы `valid-session` и `raw-experiment` | Не отправляет пакеты, не захватывает, не классифицирует | `internal/generator` |
| `runner` | Оркестрация опыта по `config.yaml`: бюджет серии, kill switch, seed, повторы, расписание, `runner_log`; запуск capture и отправки | Не классифицирует результаты | `cmd/dpi-prober`, `internal/runner` |
| `capture` | Две точки захвата (клиент и helper), запись PCAP в `artifacts/` (вне git) | Не интерпретирует трафик | `internal/capture` |
| `helper` | Свой сервер: приём соединений, журнал серверных событий (парсинг ClientHello, TLS Alert, HTTP), server PCAP; профили «принимающий» и «отвергающий» | Не интерпретирует результаты опыта | `cmd/dpi-helper` |
| `analyzer` | Offline-классификатор: PCAP/логи + `classification_rule` → `confirmed` / `refuted` / `inconclusive` по эталонным причинам (`H01`) | Не отправляет пакеты, не запускает опыты | `cmd/dpi-analyze`, `internal/analyzer` |
| `lab` | Управляемый стенд: drop / reorder / delay / MTU через `tc` (netem), `veth` и network namespace | Не входит в бинари prober/helper; управление — из runner и тестов | `internal/lab` |

Отправка (sender) — внутренняя часть `dpi-prober`: обычный путь и
raw-путь разделены (см. §4).

## 2. Поток данных

```text
config.yaml
  → generator          (planned_wire_packets)
  → sender             (линия; raw-путь только lab/helper)
  → capture ×2         (client PCAP + server PCAP → artifacts/)
  → observations       (PCAP, runner_log, helper_log)
  → dpi-analyze        (classification_rule)
  → results            (confirmed | refuted | inconclusive)
  → report.md          (experiments/<experiment_id>/)
```

Поля плана, наблюдений и результатов — `EXPERIMENTS.md` §4; семантика
исходов — `EXPERIMENTS.md` §7.

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

Документные контракты; точные Go-типы фиксируются при реализации
скелета (этап 1).

| Контракт | Направление | Содержание |
| --- | --- | --- |
| `PlannedWirePacket` | generator → runner | Логические байты, TCP split offsets, TLS record layout, TTL/SEQ/ACK/checksum |
| Запуск/останов capture | runner → capture | Точка захвата, путь файла, время окна |
| Отправка | runner → sender | Только из raw-пути, при установленном флаге и подтверждении; бюджет и kill switch — на стороне runner (`SAFETY.md` §3) |
| Серверные события | helper → observations | `helper_log` + server PCAP (пути вне git, `sha256` в отчёте) |
| `ClassificationResult` | analyzer ← observations + `classification_rule` | `confirmed` / `refuted` / `inconclusive` + `results` для отчёта |

`analyzer` читает только артефакты; обратной связи в sender нет.

## 5. Бинари и каталоги

- `cmd/dpi-prober` — клиент эксперимента (generator, runner, capture, sender).
- `cmd/dpi-helper` — сервер-приёмник.
- `cmd/dpi-analyze` — offline-классификатор (без привилегий и сети).
- `internal/` — все внутренние пакеты, включая `lab`.
- `testdata/` — размеченные fixtures с известными причинами.
- `experiments/` — планы, отчёты, метаданные (в git).
- `artifacts/` — сырые PCAP и логи (вне git; `SAFETY.md` §5).

## 6. Зависимости

- `github.com/google/gopacket` — парсинг и запись PCAP без cgo
  (`pcapgo`, `afpacket`); готовые слои TCP/TLS.
- `golang.org/x/sys/unix` — raw-сокеты и syscall-доступ на Linux.
- Обе — зафиксированные исключения в правило «новая зависимость —
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
