# Пакетная диагностика DNS, TCP и TLS

В `hosts.txt` укажите по одному домену на строку. Формат
`site.example=control.example` сравнивает обычные TLS-подключения к
именам с общим IPv4. Имена также можно передать аргументами вместо `-file`.

Из корня репозитория просмотрите список и проверьте цели по
[правилам сетевых проб](../../docs/SAFETY.md).

```bash
experiments/batch/run.sh -file hosts.txt
```

Подставьте свой интерфейс вместо `eth0`. Для остановки нажмите `Ctrl+C`.

```bash
go build -o bin/dpi-prober -ldflags "-X main.commit=$(git rev-parse HEAD)" ./cmd/dpi-prober
sudo setcap cap_net_raw+ep bin/dpi-prober
experiments/batch/run.sh -confirm-targets -iface eth0 -operator "$USER" -file hosts.txt
sudo setcap -r bin/dpi-prober
```

После прогона остаётся один короткий файл на домен —
`artifacts/batch-diagnostics/batch-*/<домен>.md`. В нём указан вывод и
четыре строки с настройками и результатами на одном IPv4.

- Только TCP.
- TLS сразу.
- TLS с задержкой ClientHello на 500 мс.
- TLS сразу, закрытие соединения через 1000 мс после рукопожатия.

Отчёт показывает таймауты, число попыток, результат контрольного SNI и
причины пропуска. Для чужих сайтов применяются обычные TCP/TLS-подключения
по [правилам проекта](../../docs/SAFETY.md). Временный захват удаляется.
