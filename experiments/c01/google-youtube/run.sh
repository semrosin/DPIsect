#!/usr/bin/env bash
set -Eeuo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
target=142.251.155.119
iface=eth0
state=artifacts/c01-offload-state.txt

if [[ ${1:-} == --restore && $# -eq 1 ]]; then
  [[ -f $state ]] || { printf 'Missing offload snapshot: %s\n' "$state" >&2; exit 1; }
  read -r saved_iface tso gso gro lro < "$state"
  sudo ethtool -K "$saved_iface" tso "$tso" gso "$gso" gro "$gro" lro "$lro"
  restored=$(ethtool -k "$saved_iface")
  for item in "tcp-segmentation-offload:$tso" "generic-segmentation-offload:$gso" "generic-receive-offload:$gro" "large-receive-offload:$lro"; do
    name=${item%%:*}
    expected=${item#*:}
    actual=$(awk -F': ' -v n="$name" '$1 == n {split($2, v, " "); print v[1]}' <<< "$restored")
    [[ $actual == "$expected" ]] || { printf 'Offload restore differs: %s\n' "$name" >&2; exit 1; }
  done
  rm -- "$state"
  exit 0
fi

if [[ $# -ne 3 || $1 != --confirm-target || $2 != "$target" || ! $3 =~ ^c01-[a-z0-9-]+-2026-11$ ]]; then
  printf 'Usage: bash %s --confirm-target %s <experiment_id>\n' "$0" "$target" >&2
  exit 2
fi
id=$3
operator=${DPISECT_OPERATOR:?set DPISECT_OPERATOR to the operator name}
config="experiments/c01/google-youtube/$id/config.yaml"
[[ -z $(git status --porcelain) ]] || { printf 'Working tree is not clean.\n' >&2; exit 1; }
[[ ! -e docs/DO_NOT_SCAN.md ]] || { printf 'Review Do Not Scan before preparing a new plan.\n' >&2; exit 1; }
[[ -f $config ]] || { printf 'Missing config: %s\n' "$config" >&2; exit 1; }
[[ $(git hash-object "$config") == "$(git rev-parse "HEAD:$config")" ]] || { printf 'Config differs from HEAD.\n' >&2; exit 1; }
grep -Fxq 'endpoint: {role: target, ip: 142.251.155.119, port: 443}' "$config" || { printf 'Unexpected endpoint in config.\n' >&2; exit 1; }
grep -Fxq "experiment_id: $id" "$config" || { printf 'Unexpected experiment id in config.\n' >&2; exit 1; }
for path in "experiments/c01/google-youtube/$id/plan.yaml" "experiments/c01/google-youtube/$id/run.json" "artifacts/$id" "$state"; do
  [[ ! -e $path ]] || { printf 'Existing data: %s\n' "$path" >&2; exit 1; }
done
route=$(ip -4 route get "$target")
printf '%s\n' "$route"
[[ " $route " == *" dev $iface "* ]] || { printf 'Route does not use %s.\n' "$iface" >&2; exit 1; }
features=$(ethtool -k "$iface")
feature() { awk -F': ' -v n="$1" '$1 == n {split($2, v, " "); print v[1]}' <<< "$features"; }
tso=$(feature tcp-segmentation-offload)
gso=$(feature generic-segmentation-offload)
gro=$(feature generic-receive-offload)
lro=$(feature large-receive-offload)
for value in "$tso" "$gso" "$gro" "$lro"; do
  [[ $value == on || $value == off ]] || { printf 'Cannot read offload state.\n' >&2; exit 1; }
done
install -d -m 0700 artifacts/c01-prober
binary=$(mktemp artifacts/c01-prober/dpi-prober.XXXXXXXX)
reference=$(mktemp artifacts/c01-prober/reference.XXXXXXXX)
capability=0
offload=0
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if (( capability )); then
    sudo setcap -r "$binary" || status=1
  fi
  rm -f -- "$binary" "$reference" || status=1
  if (( offload )); then
    if sudo ethtool -K "$iface" tso "$tso" gso "$gso" gro "$gro" lro "$lro"; then
      features=$(ethtool -k "$iface") || status=1
      if [[ $(feature tcp-segmentation-offload) == "$tso" && $(feature generic-segmentation-offload) == "$gso" && $(feature generic-receive-offload) == "$gro" && $(feature large-receive-offload) == "$lro" ]]; then
        rm -f -- "$state" || status=1
      else
        printf 'Offload differs from saved state; use --restore.\n' >&2
        status=1
      fi
    else
      printf 'Restore offload manually: bash experiments/c01/google-youtube/run.sh --restore\n' >&2
      status=1
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
commit=$(git rev-parse HEAD)
GOPROXY=off go build -trimpath -buildvcs=false -o "$binary" -ldflags "-X main.version=c01-pilot -X main.commit=$commit" ./cmd/dpi-prober
GOPROXY=off go build -trimpath -buildvcs=false -o "$reference" -ldflags "-X main.version=c01-pilot -X main.commit=$commit" ./cmd/dpi-prober
cmp -s "$binary" "$reference" || { printf 'Binary builds differ.\n' >&2; exit 1; }
binary_hash=$(sha256sum "$binary" | awk '{print $1}')
config_hash=$(sha256sum "$config" | awk '{print $1}')
[[ -z $(git status --porcelain) && $(git rev-parse HEAD) == "$commit" ]] || { printf 'Working tree changed during build.\n' >&2; exit 1; }
sudo -v
printf 'Type %s to confirm the series to %s: ' "$id" "$target"
IFS= read -r answer </dev/tty
[[ $answer == "$id" ]] || { printf 'Series not confirmed.\n' >&2; exit 1; }
[[ ! -e docs/DO_NOT_SCAN.md ]] || { printf 'Do Not Scan appeared.\n' >&2; exit 1; }
[[ $(sha256sum "$config" | awk '{print $1}') == "$config_hash" && $(sha256sum "$binary" | awk '{print $1}') == "$binary_hash" ]] || { printf 'Config or binary changed.\n' >&2; exit 1; }
install -d -m 0700 "artifacts/$id"
(umask 077; printf 'confirmed_by=%s confirmed_utc=%s series=%s target=%s config_sha256=%s binary_sha256=%s commit=%s\n' "$operator" "$(date -u +%FT%TZ)" "$id" "$target" "$config_hash" "$binary_hash" "$commit" > "artifacts/$id/confirmations.log")
(umask 077; printf '%s %s %s %s %s\n' "$iface" "$tso" "$gso" "$gro" "$lro" > "$state")
offload=1
sudo ethtool -K "$iface" tso off gso off gro off lro off
features=$(ethtool -k "$iface")
for name in tcp-segmentation-offload generic-segmentation-offload generic-receive-offload large-receive-offload; do
  [[ $(feature "$name") == off ]] || { printf 'Offload is not disabled: %s\n' "$name" >&2; exit 1; }
done
capability=1
sudo setcap cap_net_raw+ep "$binary"
"$binary" -config "$config" -capture-iface "$iface" -operator "$operator"
