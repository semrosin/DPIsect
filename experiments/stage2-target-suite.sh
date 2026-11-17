#!/usr/bin/env bash
set -Eeuo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
prober=artifacts/stage2-close-delay/dpi-prober
target=142.251.155.119
iface=eth0
offload_state=artifacts/stage2-offload-state.txt
experiments=(
  experiments/b07/google-youtube/b07-google-offset-paced-2026-11
  experiments/b07/google-youtube/b07-google-length-2026-11
  experiments/b04/google-youtube/b04-google-youtube-field-2026-11
  experiments/b01/google-youtube/b01-google-youtube-sni-2026-11
)
hashes=(
  d75b1b2d42bf43e1936112ad022fd96ff9349931cb673184fb7cf40b8529db29
  2083ee4dccd2803c13a3d4dcee82db96c355271011a2709044fa4cddabef8d99
  00cc7c297c14d206dfeb5f3ee926a9c33bf6f7eda8605c629db82bda4cc29a32
  08ec66314a63b4912957a15b852024a1520f576ddfd72108f1b3ba8da4798c90
)
usage() {
  printf 'Usage: bash %s --confirm-target %s [--b01-only]\n' "$0" "$target" >&2
  printf '       bash %s --restore\n' "$0" >&2
}

if [[ "${1:-}" == --restore ]]; then
  if [[ ! -f "$offload_state" ]]; then
    printf 'Offload state file is missing: %s\n' "$offload_state" >&2
    exit 1
  fi
  read -r iface tso gso gro lro < "$offload_state"
  sudo ethtool -K "$iface" tso "$tso" gso "$gso" gro "$gro" lro "$lro"
  rm -f "$offload_state"
  printf 'Offload settings restored on %s.\n' "$iface"
  exit 0
fi
if [[ "${1:-}" != --confirm-target || "${2:-}" != "$target" ]]; then
  printf 'Refusing: confirm the target IP explicitly with --confirm-target %s.\n' "$target" >&2
  usage
  exit 1
fi
shift 2
if [[ $# -eq 1 && $1 == --b01-only ]]; then
  experiments=("${experiments[3]}")
  hashes=("${hashes[3]}")
elif [[ $# -ne 0 ]]; then
  usage
  exit 1
fi
operator=${DPISECT_OPERATOR:?set DPISECT_OPERATOR to the operator full name}

if [[ -e docs/DO_NOT_SCAN.md ]]; then
  printf '%s\n' 'Do Not Scan list exists; review it and prepare a new approved plan.' >&2
  exit 1
fi
if [[ ! -x "$prober" || -n "$(getcap "$prober")" ]]; then
  printf '%s\n' 'Prepared prober is missing or already has capabilities.' >&2
  exit 1
fi
if ! printf '%s  %s\n' 49531f3b83b0d63fdad16af79e12389d39d30667702971377092cef0a954cd58 "$prober" | sha256sum -c --status; then
  printf '%s\n' 'Prober differs from the prepared binary; no probe started.' >&2
  exit 1
fi
for i in "${!experiments[@]}"; do
  experiment=${experiments[$i]}
  id=${experiment##*/}
  if ! printf '%s  %s\n' "${hashes[$i]}" "$experiment/config.yaml" | sha256sum -c --status; then
    printf 'Config differs from the prepared plan: %s\n' "$experiment" >&2
    exit 1
  fi
  for path in "$experiment/plan.yaml" "$experiment/run.json" "artifacts/$id/client.pcap" "artifacts/$id/runner.log" "artifacts/$id/sni-observations.json" "artifacts/$id/confirmations.log"; do
    if [[ -e "$path" ]]; then
      printf 'Existing experiment file; refusing to overwrite: %s\n' "$path" >&2
      exit 1
    fi
  done
done

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
    else
      rm -f "$offload_state"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

offload_changed=1
install -d -m 0700 "$(dirname -- "$offload_state")"
( umask 077; printf '%s %s %s %s %s\n' "$iface" "$tso" "$gso" "$gro" "$lro" > "$offload_state" )
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

for i in "${!experiments[@]}"; do
  experiment=${experiments[$i]}
  id=${experiment##*/}
  observation=artifacts/$id/sni-observations.json
  if [[ -e docs/DO_NOT_SCAN.md ]]; then
    printf '%s\n' 'Do Not Scan list appeared; remaining series will not run.' >&2
    exit 1
  fi
  printf 'Series %s sends probes to %s. Type the experiment id to confirm: ' "$id" "$target"
  answer=''
  if ! IFS= read -r answer </dev/tty; then
    printf '\nUnable to read the confirmation; the series was not started.\n' >&2
    exit 1
  fi
  if [[ "$answer" != "$id" ]]; then
    printf 'Series %s was not confirmed; remaining series will not run.\n' "$id" >&2
    exit 1
  fi
  install -d -m 0700 "artifacts/$id"
  printf 'confirmed_by=%s confirmed_utc=%s series=%s target=%s\n' \
    "${SUDO_USER:-${USER:-unknown}}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$id" "$target" \
    >> "artifacts/$id/confirmations.log"
  printf '\nSeries %s (%s/%s)\n' "$id" "$((i+1))" "${#experiments[@]}"
  status=0
  GODEBUG= "$prober" -config "$experiment/config.yaml" -capture-iface "$iface" -operator "$operator" || status=$?
  if [[ -f "$observation" ]]; then cat "$observation"; fi
  if (( status != 0 )); then
    printf 'Series stopped with code %s; remaining series will not run.\n' "$status" >&2
    exit "$status"
  fi
  if ! python3 - "$observation" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    observations = json.load(f)
trials = observations.get('trials', [])
if len(trials) != 2 or any(t.get('observation', {}).get('stage') != 'complete' for t in trials):
    print('TLS pair incomplete; remaining series will not run.', file=sys.stderr)
    raise SystemExit(1)
PY
  then
    exit 1
  fi
  if (( i+1 < ${#experiments[@]} )); then sleep 3; fi
done
