# testdata

Эталонные fixtures с известными причинами для классификатора (`H01`).

## Структура

```text
testdata/
  <cause>/
    <name>.pcap   # эталонная трасса
    <name>.md     # разметка и границы применимости — рядом с fixture
```

Причины (этап 1, подшаг 8 `docs/DEVELOPMENT.md`): `drop`,
`rst_injection`, `tls_alert`, `throttling`; отдельно — control-трасса
без вмешательства.

PCAP в `testdata/` входит в git: fixtures — часть тестов классификатора
(`docs/GO_STYLE.md` §6), в отличие от сырых артефактов опытов, которые
лежат в `artifacts/` и не коммитятся (`docs/SAFETY.md` §5). В
`.gitignore` для этого сделано исключение `!testdata/**/*.pcap`.
