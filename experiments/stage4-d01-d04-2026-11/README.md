# Stage 4 — D01–D04 packet-field lab

Raw probes only. The endpoint is the lab helper at `10.77.2.2:8443`;
the client is in its own network namespace, and a router namespace sits
between client and helper. This is required for D01: a TTL=1 packet
reaches the router (the potential observer) but not the helper.

## Topology

```text
client 10.77.1.2/24 -- veth -- 10.77.1.1 router 10.77.2.1 -- veth -- 10.77.2.2 helper
```

The helper runs in the server namespace with an accepting profile and
a server PCAP. The prober runs in the client namespace with
`-capture-iface veth-c`; raw sending and AF_PACKET capture therefore
see the same client wire.

## Arms

| arm | question | changed field |
| --- | --- | --- |
| `d01-control-2026-11` | D01 | none, TTL 64 |
| `d01-ttl1-2026-11` | D01 | TTL 1 |
| `d02-control-2026-11` | D02 | none, SEQ correct |
| `d02-out-of-order-2026-11` | D02 | SEQ out of order |
| `d02-old-2026-11` | D02 | SEQ old/outside window |
| `d03-control-2026-11` | D03 | none, ACK correct, fresh TCP |
| `d03-wrong-ack-2026-11` | D03 | ACK wrong, fresh TCP |
| `d04-control-2026-11` | D04 | none, checksum correct |
| `d04-corrupt-checksum-2026-11` | D04 | checksum corrupt |

`D03` uses a throwaway connection for the fake probe and a fresh
connection for the real ClientHello. The other questions keep the fake
and real ClientHello in one TCP connection.

## Run

Build the binaries first, then run as root. The script changes to the
repository root, so configs and run metadata use repo-relative paths. It
refuses to run without root because it creates namespaces, veth pairs and
raw sockets. It also refuses to overwrite an existing run or artifact
directory.

```sh
commit=$(git rev-parse --short HEAD)
ldflags="-X main.version=0.1.0-stage4 -X main.commit=$commit"
go build -ldflags "$ldflags" -o bin/dpi-prober ./cmd/dpi-prober
go build -ldflags "$ldflags" -o bin/dpi-helper ./cmd/dpi-helper
go build -ldflags "$ldflags" -o bin/dpi-analyze ./cmd/dpi-analyze
sudo experiments/stage4-d01-d04-2026-11/run.sh
# or one arm:
sudo experiments/stage4-d01-d04-2026-11/run.sh d01-ttl1-2026-11.yaml
```

Each arm gets:

- `experiments/stage4-d01-d04-2026-11/runs/<arm>/config.yaml`,
  `plan.yaml`, `raw-observations.json`, `run.json`;
- `artifacts/<arm>/client.pcap`, `server.pcap`, `helper.log`,
  `runner.log`, `analysis.json`, offload snapshots and `lab-meta.txt`.

`dpi-analyze -raw` writes `raw_actual_validation`: whether the fake
packet is present with the planned TTL/SEQ/ACK/checksum, whether the
real ClientHello follows, and whether the helper accepted, rejected or
never received the fake. The DPI reaction itself is not observable in
this single-host lab; the expected stage status is `inconclusive` for
the DPI question while endpoint behavior is confirmed.
