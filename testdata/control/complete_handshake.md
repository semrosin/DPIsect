# control: complete_handshake

Ожидаемый классификатор: `none` (`CauseNone`).

Состав: SYN / SYN-ACK / ACK, ClientHello (`fixture.example`), ServerHello
(cipher `0x1301`), Certificate, ServerHelloDone, `GET`, HTTP 200,
аккуратное закрытие. Интервалы между пакетами 1 ms — ниже порога
`analyzer.ThrottleGapThreshold` (50 ms).

Границы применимости: трасса синтетическая, без retransmission и
out-of-order; реальная сеть добавляет потери и jitter. `none` означает
«сигнатуры перечисленных аномалий отсутствуют», а не отсутствие DPI —
сравнение всегда с control-пробой того же размера и маршрута (`H02`).
