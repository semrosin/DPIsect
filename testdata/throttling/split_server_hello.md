# throttling: split_server_hello

Ожидаемый классификатор: `throttling` (`CauseThrottling`).

Состав: ServerHello разорван на три TCP-сегмента с интервалами 80 ms
между ними; поток собирается обратно без разрывов, остальной обмен
(Certificate, ServerHelloDone, GET, HTTP 200) идёт штатно.

Границы применимости: порог `analyzer.ThrottleGapThreshold` = 50 ms
зафиксирован для этих fixtures; на реальной сети задержка и jitter
требуют своего порога — решение оператора (`A06`). Обычная потеря
сегмента без ретрансляции даёт разрыв потока (`StreamGap`) и уходит в
`inconclusive`, а не в `throttling`.
