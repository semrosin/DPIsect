#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../../.."
experiment=experiments/b01/google-youtube/b01-google-youtube-repeat-2026-11
artifact_dir=artifacts/b01-google-youtube-repeat-2026-11
prepared=$artifact_dir/prepared
prober=$prepared/dpi-prober
target=142.251.155.119

usage() {
  printf '%s\n' \
    'Usage: bash experiments/b01/google-youtube/b01-google-youtube-repeat-2026-11/run.sh --prepare | --run INTERFACE | --results' \
    '--prepare: offline build and schedule only; no probes or DNS queries.' \
    '--run: operator-only DNS check and one monitored four-connection TLS series.' \
    '--results: display saved observations without network access.'
}
fail() { printf '%s\n' "$*" >&2; exit 1; }
[[ $# -gt 0 ]] || { usage; exit 0; }

case "$1" in
  --prepare)
    [[ $# -eq 1 ]] || { usage; exit 1; }
    mkdir -p "$artifact_dir"
    [[ ! -e "$prepared" ]] || fail 'Preparation already exists; refusing to replace the binary or its manifest.'
    go_binary=${GO_BINARY:-go}
    required_go=$(awk '$1 == "go" {print $2}' go.mod)
    if [[ -z ${GO_BINARY:-} && "$(GOTOOLCHAIN=local go env GOVERSION)" != "go$required_go" ]]; then
      module_cache=$(GOTOOLCHAIN=local go env GOMODCACHE)
      host_os=$(GOTOOLCHAIN=local go env GOHOSTOS)
      host_arch=$(GOTOOLCHAIN=local go env GOHOSTARCH)
      cached_go=$module_cache/golang.org/toolchain@v0.0.1-go$required_go.$host_os-$host_arch/bin/go
      [[ ! -x "$cached_go" ]] || go_binary=$cached_go
    fi
    staging=$(mktemp -d "$artifact_dir/.prepare-XXXXXX")
    trap 'rm -rf -- "$staging"' EXIT
    # Use an installed toolchain; never download toolchains or dependencies.
    GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off "$go_binary" build \
      -ldflags "-X main.version=b01-repeat-prepared -X main.commit=$(git rev-parse HEAD)" \
      -o "$staging/dpi-prober" ./cmd/dpi-prober
    "$staging/dpi-prober" -prepare-sni -config "$experiment/config.yaml"
    mkdir "$prepared"
    mv "$staging/dpi-prober" "$prober"
    sha256sum "$prober" "$experiment/config.yaml" "$experiment/sni-schedule.yaml" \
      "$experiment/run.sh" "$experiment/report.md" > "$prepared/manifest.sha256"
    printf '%s\n' 'Prepared offline. No DNS queries or probes sent.'
    cat "$experiment/sni-schedule.yaml"
    exit 0
    ;;
  --results)
    [[ $# -eq 1 ]] || { usage; exit 1; }
    for path in "$artifact_dir/sni-observations.json" "$experiment/run.json"; do
      [[ -f "$path" ]] || fail "Results not available: $path"
      printf '\n%s\n' "$path"
      cat "$path"
    done
    exit 0
    ;;
  --run)
    [[ $# -eq 2 && -n "$2" ]] || { usage; exit 1; }
    iface=$2
    ;;
  *) usage; exit 1 ;;
esac

# Only the operator invokes this branch. No target checks run during preparation.
[[ $EUID -ne 0 ]] || fail 'Run as an ordinary user; sudo is used only for offload and capabilities.'
for tool in python3 ip ethtool getcap setcap sudo sha256sum awk; do
  command -v "$tool" >/dev/null || fail "Required tool is missing: $tool"
done
[[ -f "$prepared/manifest.sha256" && -x "$prober" ]] || fail 'Run --prepare first.'
sha256sum -c --status "$prepared/manifest.sha256" || fail 'Prepared inputs changed; no probe started.'
[[ ! -e docs/DO_NOT_SCAN.md ]] || fail 'Do Not Scan list exists; review it and prepare a new approved plan.'
[[ -z "$(getcap "$prober")" ]] || fail 'Prober already has capabilities; inspect before running.'
for path in "$experiment/plan.yaml" "$experiment/run.json" "$artifact_dir/client.pcap" \
  "$artifact_dir/runner.log" "$artifact_dir/sni-observations.json" "$artifact_dir/attempted"; do
  [[ ! -e "$path" ]] || fail "Existing experiment output; refusing to rerun: $path"
done

mkdir "$artifact_dir/run.lock" || fail 'Another run is active or its lock needs inspection.'
offload_changed=0
capability_added=0
feature() {
  awk -F': ' -v name="$1" '$1 == name { split($2, value, " "); print value[1] }' <<< "$features"
}
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if (( capability_added )); then
    sudo setcap -r "$prober" || { printf '%s\n' 'Failed to remove CAP_NET_RAW.' >&2; status=1; }
    local caps
    caps=$(getcap "$prober") || status=1
    if [[ -n "$caps" ]]; then
      printf '%s\n' 'Capability remains on the prober.' >&2
      status=1
    fi
  fi
  if (( offload_changed )); then
    sudo ethtool -K "$iface" tso "$tso" gso "$gso" gro "$gro" lro "$lro" || status=1
    features=$(ethtool -k "$iface") || status=1
    if [[ "$(feature tcp-segmentation-offload)" != "$tso" ||
          "$(feature generic-segmentation-offload)" != "$gso" ||
          "$(feature generic-receive-offload)" != "$gro" ||
          "$(feature large-receive-offload)" != "$lro" ]]; then
      printf '%s\n' 'Restored offload settings differ from the original values.' >&2
      status=1
    fi
    printf '%s\n' "$features" > "$artifact_dir/offload-after.txt"
  fi
  rmdir "$artifact_dir/run.lock" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

route=$(ip -4 route get "$target")
printf '%s\n' "$route" | tee "$artifact_dir/route.txt"
[[ " $route " == *" dev $iface "* ]] || fail "Route does not use $iface; no probe started."
ip -details link show dev "$iface" > "$artifact_dir/link.txt"
features=$(ethtool -k "$iface")
printf '%s\n' "$features" > "$artifact_dir/offload-before.txt"
tso=$(feature tcp-segmentation-offload)
gso=$(feature generic-segmentation-offload)
gro=$(feature generic-receive-offload)
lro=$(feature large-receive-offload)
for value in "$tso" "$gso" "$gro" "$lro"; do
  [[ "$value" == on || "$value" == off ]] || fail 'Cannot determine original offload settings.'
done

# The address is fixed by the plan. A changed DNS answer never changes the target automatically.
python3 - "$target" "$artifact_dir/dns.json" <<'PY'
import datetime
import json
import socket
import sys

addresses = sorted({item[4][0] for item in socket.getaddrinfo(
    'www.google.com', 443, socket.AF_INET, socket.SOCK_STREAM)})
with open(sys.argv[2], 'w', encoding='utf-8') as stream:
    json.dump({'host': 'www.google.com', 'ipv4': addresses,
               'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}, stream)
if sys.argv[1] not in addresses:
    raise SystemExit('Planned IP is absent from current DNS answers. Stop and revise the plan; no TLS probe started.')
PY

sudo -v
offload_changed=1
sudo ethtool -K "$iface" tso off gso off gro off lro off
features=$(ethtool -k "$iface")
for name in tcp-segmentation-offload generic-segmentation-offload generic-receive-offload large-receive-offload; do
  [[ "$(feature "$name")" == off ]] || fail "Offload remains enabled: $name"
done
[[ ! -e docs/DO_NOT_SCAN.md ]] || fail 'Do Not Scan list appeared; no probe started.'
sha256sum -c --status "$prepared/manifest.sha256" || fail 'Prepared inputs changed; no probe started.'
capability_added=1
sudo setcap cap_net_raw+ep "$prober"
# A permanent marker prevents retries even if startup fails before capture is created.
(set -o noclobber; date -u +%FT%TZ > "$artifact_dir/attempted")
status=0
GODEBUG= "$prober" -config "$experiment/config.yaml" -capture-iface "$iface" \
  -operator "${USER:-operator}" || status=$?
if [[ -f "$artifact_dir/sni-observations.json" ]]; then
  cat "$artifact_dir/sni-observations.json"
fi
if (( status != 0 )); then
  printf '%s\n' 'Series stopped. No automatic retry; inspect artifacts before planning another run.' >&2
fi
exit "$status"
