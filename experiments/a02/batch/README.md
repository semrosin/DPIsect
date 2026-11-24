# Пакетная диагностика DNS, TCP и TLS

В `hosts.txt` укажите по одному домену на строку. Формат
`site.example=control.example` сравнивает обычные TLS-подключения к
именам с общим IPv4. Имена также можно передать аргументами вместо `-file`.

Из корня репозитория просмотрите список и проверьте цели по
[правилам сетевых проб](../../../docs/SAFETY.md).

```bash
experiments/a02/batch/run.sh -file hosts.txt
```

Подставьте свой интерфейс вместо `eth0`. Для остановки нажмите `Ctrl+C`.

```bash
go build -o bin/dpi-prober -ldflags "-X main.commit=$(git rev-parse HEAD)" ./cmd/dpi-prober
sudo setcap cap_net_raw+ep bin/dpi-prober
experiments/a02/batch/run.sh -confirm-targets -iface eth0 -operator "$USER" -file hosts.txt
sudo setcap -r bin/dpi-prober
```

Диагноз по каждому домену — в `artifacts/a02-batch/batch-*/<домен>/report.md`.
PCAP лежит рядом. Проверка идёт до конца TLS-рукопожатия.
