# testdata

Эталонные fixtures с известными причинами для классификатора (`H01`).

## Структура

```text
testdata/
  <cause>/
    <name>.pcap   # эталонная трасса
    <name>.md     # разметка и границы применимости — рядом с fixture
```

Причины (этап 1, подшаг 8 `docs/DEVELOPMENT.md`): `control`,
`drop`, `rst_injection`, `tls_alert`, `modification`, `throttling`.

## Регенерация PCAP

Трассы детерминированы (фиксированные адреса, seq, timestamp —
2026-11-05T10:00:00Z). Перегенерация:

```sh
DPISECT_REGEN_FIXTURES=1 go test ./internal/analyzer -run TestH01_RegenerateFixtures
```

Код генератора — `internal/analyzer/fixtures_test.go`; аннотации
`<name>.md` генератор не трогает, их пишет человек. Классификация
проверяется `TestH01_ClassifyFixtures` (тот же файл).

PCAP в `testdata/` входит в git: fixtures — часть тестов классификатора
(`docs/GO_STYLE.md` §6), в отличие от сырых артефактов опытов, которые
лежат в `artifacts/` и не коммитятся (`docs/SAFETY.md` §5). В
`.gitignore` для этого сделано исключение `!testdata/**/*.pcap`.
