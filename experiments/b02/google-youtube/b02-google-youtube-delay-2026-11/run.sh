#!/usr/bin/env bash
set -Eeuo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.."
experiment=experiments/b02/google-youtube/b02-google-youtube-delay-2026-11
artifacts=artifacts/b02-google-youtube-delay-2026-11
prober=artifacts/stage2-sni-delay/dpi-prober
target=142.251.155.119
iface=eth0

if [[ -e docs/DO_NOT_SCAN.md ]]; then
  printf '%s\n' 'Do Not Scan list exists; review it and prepare a new approved plan before running.' >&2
  exit 1
fi
for path in "$experiment/plan.yaml" "$experiment/run.json" "$artifacts/client.pcap" "$artifacts/runner.log" "$artifacts/sni-observations.json"; do
  if [[ -e "$path" ]]; then
    printf 'Existing experiment file; refusing to overwrite: %s\n' "$path" >&2
    exit 1
  fi
done
if [[ ! -x "$prober" || -n "$(getcap "$prober")" ]]; then
  printf '%s\n' 'Prepared prober is missing or already has capabilities.' >&2
  exit 1
fi
if ! printf '%s  %s\n' \
  'e38ac3cb14fb9c2375067cf64e8c1eb2b187615cd4db677626b9420c98ec8f16' "$experiment/config.yaml" \
  'f91b1b61eed7fbee51825f181d6f35f3dca52400c4b3e7bafaac86fed56155ab' "$prober" | sha256sum -c --status; then
  printf '%s\n' 'Config or prober differs from the prepared plan; no probe started.' >&2
  exit 1
fi

route=$(ip -4 route get "$target")
printf '%s\n' "$route"
if [[ " $route " != *" dev $iface "* ]]; then
  printf 'Route does not use %s; no probe started.\n' "$iface" >&2
  exit 1
fi
features=$(ethtool -k "$iface")
feature() {
  awk -F': ' -v name="$1" '$1 == name { split($2, value, " "); print value[1] }' <<< "$features"
}
tso=$(feature tcp-segmentation-offload)
gso=$(feature generic-segmentation-offload)
gro=$(feature generic-receive-offload)
lro=$(feature large-receive-offload)
for value in "$tso" "$gso" "$gro" "$lro"; do
  if [[ "$value" != on && "$value" != off ]]; then
    printf '%s\n' 'Unable to determine the original offload settings.' >&2
    exit 1
  fi
done
printf 'Original offload: tso=%s gso=%s gro=%s lro=%s\n' "$tso" "$gso" "$gro" "$lro"
sudo -v

offload_changed=0
capability_added=0
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if (( capability_added )); then
    if [[ -n "$(getcap "$prober")" ]]; then
      sudo setcap -r "$prober" || { printf '%s\n' 'Failed to remove CAP_NET_RAW.' >&2; status=1; }
    fi
    if [[ -n "$(getcap "$prober")" ]]; then
      printf '%s\n' 'Capability remains on the prober.' >&2
      status=1
    fi
  fi
  if (( offload_changed )); then
    sudo ethtool -K "$iface" tso "$tso" gso "$gso" gro "$gro" lro "$lro" || {
      printf '%s\n' 'Failed to restore offload settings.' >&2
      status=1
    }
    ethtool -k "$iface" | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload):' || status=1
    features=$(ethtool -k "$iface") || status=1
    if [[ "$(feature tcp-segmentation-offload)" != "$tso" ||
          "$(feature generic-segmentation-offload)" != "$gso" ||
          "$(feature generic-receive-offload)" != "$gro" ||
          "$(feature large-receive-offload)" != "$lro" ]]; then
      printf '%s\n' 'Restored offload settings differ from the original values.' >&2
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

offload_changed=1
sudo ethtool -K "$iface" tso off gso off gro off lro off
features=$(ethtool -k "$iface")
for name in tcp-segmentation-offload generic-segmentation-offload generic-receive-offload large-receive-offload; do
  if [[ "$(feature "$name")" != off ]]; then
    printf 'Offload is not disabled: %s\n' "$name" >&2
    exit 1
  fi
done
capability_added=1
sudo setcap cap_net_raw+ep "$prober"

status=0
"$prober" -config "$experiment/config.yaml" -capture-iface "$iface" -operator "${USER:-unknown}" || status=$?
if [[ -f "$artifacts/sni-observations.json" ]]; then
  cat "$artifacts/sni-observations.json"
fi
exit "$status"
