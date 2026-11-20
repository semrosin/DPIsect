#!/usr/bin/env bash
set -Eeuo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
if [[ $# -ne 1 || ( $1 != split && $1 != control ) ]]; then
  printf 'Usage: bash %s split|control\n' "$0" >&2
  exit 2
fi
variant=$1
id="c01-youtube-$variant-2026-11"
config="experiments/c01/google-youtube/$id/config.yaml"
binary="artifacts/c01-prober/dpi-prober"
operator=${DPISECT_OPERATOR:-${USER:-unknown}}

for path in "experiments/c01/google-youtube/$id/plan.yaml" \
  "experiments/c01/google-youtube/$id/run.json" "artifacts/$id"; do
  if [[ -e $path ]]; then
    printf 'Existing experiment data: %s. Refusing to overwrite.\n' "$path" >&2
    exit 1
  fi
done
if [[ -e $binary ]] && [[ -n $(getcap "$binary") ]]; then
  printf 'Existing binary has capabilities; inspect it before continuing.\n' >&2
  exit 1
fi

route=$(ip -4 route get 142.251.155.119)
printf '%s\n' "$route"
if [[ " $route " != *' dev eth0 '* ]]; then
  printf 'Route does not use eth0.\n' >&2
  exit 1
fi
ethtool -k eth0 | grep -E '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|large-receive-offload):'
install -d -m 0700 artifacts/c01-prober
GOPROXY=off go build -o "$binary" -ldflags "-X main.version=c01-pilot -X main.commit=$(git rev-parse HEAD)" ./cmd/dpi-prober
sudo -v
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n $(getcap "$binary") ]]; then
    sudo setcap -r "$binary" || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
sudo setcap cap_net_raw+ep "$binary"
"$binary" -config "$config" -capture-iface eth0 -operator "$operator"
