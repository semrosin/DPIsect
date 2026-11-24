#!/usr/bin/env bash
# D01–D04 lab harness: three network namespaces with a routed client →
# router → helper path. Run as root: sudo experiments/stage4-d01-d04-2026-11/run.sh [arm ...]
#
# The router is what makes D01 meaningful: a TTL=1 fake packet reaches
# the router (potential observer) but not the helper. Raw probes are
# sent only to the lab endpoint; this script never accepts a target.
set -euo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$repo_dir"
suite_dir="experiments/stage4-d01-d04-2026-11"
prober="$repo_dir/bin/dpi-prober"
helper="$repo_dir/bin/dpi-helper"
analyzer="$repo_dir/bin/dpi-analyze"

ns_c=dpisect4-c
ns_r=dpisect4-r
ns_s=dpisect4-s
helper_pid=''
created_ns=false

die() { echo "stage4: $*" >&2; exit 1; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  die "run as root (netns, veth and raw sockets need privileges)"
fi
for binary in "$prober" "$helper" "$analyzer"; do
  [[ -x "$binary" ]] || die "missing $binary; run: go build -o bin ./cmd/..."
done
for ns in "$ns_c" "$ns_r" "$ns_s"; do
  if ip netns list | grep -qx "$ns"; then
    die "namespace $ns already exists; refusing to delete someone else's lab"
  fi
done

cleanup() {
  if [[ -n "$helper_pid" ]]; then
    kill -INT "$helper_pid" 2>/dev/null || true
    wait "$helper_pid" 2>/dev/null || true
    helper_pid=''
  fi
  if [[ "$created_ns" == true ]]; then
    ip netns del "$ns_c" 2>/dev/null || true
    ip netns del "$ns_r" 2>/dev/null || true
    ip netns del "$ns_s" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

setup_lab() {
  ip netns add "$ns_c"
  ip netns add "$ns_r"
  ip netns add "$ns_s"
  created_ns=true

  ip link add veth-c netns "$ns_c" type veth peer name veth-cr netns "$ns_r"
  ip link add veth-s netns "$ns_s" type veth peer name veth-rs netns "$ns_r"

  for ns in "$ns_c" "$ns_r" "$ns_s"; do
    ip -n "$ns" link set lo up
  done
  ip -n "$ns_c" addr add 10.77.1.2/24 dev veth-c
  ip -n "$ns_r" addr add 10.77.1.1/24 dev veth-cr
  ip -n "$ns_r" addr add 10.77.2.1/24 dev veth-rs
  ip -n "$ns_s" addr add 10.77.2.2/24 dev veth-s
  ip -n "$ns_c" link set veth-c up
  ip -n "$ns_r" link set veth-cr up
  ip -n "$ns_r" link set veth-rs up
  ip -n "$ns_s" link set veth-s up

  ip -n "$ns_c" route add default via 10.77.1.1
  ip -n "$ns_s" route add default via 10.77.2.1
  ip netns exec "$ns_r" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns_r" sysctl -qw net.ipv4.conf.all.send_redirects=0
  ip netns exec "$ns_r" sysctl -qw net.ipv4.conf.all.accept_redirects=0
}

# Disable checksum/segmentation offload on both veth ends so D04 is
# judged on the wire checksum, not on a NIC that silently fixes it.
disable_offload() {
  local artifact_dir=$1
  local ns dev tag
  for spec in "$ns_c:veth-c:client" "$ns_s:veth-s:server"; do
    IFS=: read -r ns dev tag <<<"$spec"
    ip netns exec "$ns" ethtool -k "$dev" > "$artifact_dir/offload-$tag-before.txt" 2>&1 || true
    ip netns exec "$ns" ethtool -K "$dev" tx off rx off tso off gso off gro off \
      > "$artifact_dir/offload-$tag-set.txt" 2>&1 || true
    ip netns exec "$ns" ethtool -k "$dev" > "$artifact_dir/offload-$tag-after.txt" 2>&1 || true
  done
}

run_arm() {
  local arm_file=$1
  local arm_id
  arm_id=$(basename "$arm_file" .yaml)
  local run_dir="$suite_dir/runs/$arm_id"
  local artifact_dir="artifacts/$arm_id"
  if [[ -e "$run_dir" ]]; then
    die "run directory already exists: $run_dir"
  fi
  if [[ -e "$artifact_dir" ]]; then
    die "artifact directory already exists: $artifact_dir"
  fi
  mkdir -m 700 -p "$run_dir" "$artifact_dir"
  cp -- "$arm_file" "$run_dir/config.yaml"
  cp -- "$arm_file" "$artifact_dir/source-config.yaml"

  echo "stage4: arm $arm_id"
  setup_lab
  disable_offload "$artifact_dir"
  {
    date -u '+started_utc: %Y-%m-%dT%H:%M:%SZ'
    printf 'operator: %s\n' "${SUDO_USER:-root}"
    printf 'arm: %s\n' "$arm_id"
    printf 'tool_commit: '; git -C "$repo_dir" rev-parse --short HEAD
    if git -C "$repo_dir" diff --quiet -- .; then
      printf 'tool_dirty: false\n'
    else
      printf 'tool_dirty: true\n'
    fi
    printf 'kernel: '; uname -r
  } > "$artifact_dir/lab-meta.txt"
  ip -n "$ns_c" -o link show > "$artifact_dir/client-links.txt"
  ip -n "$ns_r" -o link show > "$artifact_dir/router-links.txt"
  ip -n "$ns_s" -o link show > "$artifact_dir/server-links.txt"

  "$repo_dir/bin/dpi-helper" --version > /dev/null 2>&1 || true
  ip netns exec "$ns_s" "$helper" -addr 0.0.0.0:8443 -profile accepting \
    -log "$artifact_dir/helper.log" \
    -capture-iface veth-s -capture-pcap "$artifact_dir/server.pcap" \
    > "$artifact_dir/helper-stderr.log" 2>&1 &
  helper_pid=$!

  local ready=false
  for _ in {1..100}; do
    if [[ -f "$artifact_dir/helper.log" ]] &&
      grep -q '"event":"start"' "$artifact_dir/helper.log"; then
      ready=true
      break
    fi
    if ! kill -0 "$helper_pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if [[ "$ready" != true ]]; then
    cat "$artifact_dir/helper-stderr.log" >&2 || true
    die "helper did not start for $arm_id"
  fi

  local prober_status=0
  ip netns exec "$ns_c" "$prober" \
    -config "$run_dir/config.yaml" \
    -allow-raw \
    -operator "${SUDO_USER:-root}" \
    -capture-iface veth-c || prober_status=$?

  kill -INT "$helper_pid" 2>/dev/null || true
  wait "$helper_pid" 2>/dev/null || true
  helper_pid=''

  ip netns del "$ns_c" 2>/dev/null || true
  ip netns del "$ns_r" 2>/dev/null || true
  ip netns del "$ns_s" 2>/dev/null || true
  created_ns=false

  {
    printf 'prober_exit_code: %s\n' "$prober_status"
    date -u '+finished_utc: %Y-%m-%dT%H:%M:%SZ'
  } >> "$artifact_dir/lab-meta.txt"

  if [[ -f "$run_dir/run.json" ]]; then
    "$prober" -finalize -config "$run_dir/config.yaml" \
      > "$artifact_dir/finalize-stdout.txt" 2> "$artifact_dir/finalize-stderr.txt" || true
  fi

  if [[ -f "$artifact_dir/client.pcap" ]]; then
    "$analyzer" -config "$run_dir/config.yaml" -raw \
      > "$artifact_dir/analysis.json" 2> "$artifact_dir/analysis-stderr.txt" || true
  fi
  echo "stage4: arm $arm_id exit=$prober_status artifacts=$artifact_dir"
  return "$prober_status"
}

if [[ $# -gt 0 ]]; then
  arms=("$@")
else
  mapfile -t arms < <(find "$suite_dir/arms" -maxdepth 1 -name '*.yaml' -print | sort)
fi
[[ ${#arms[@]} -gt 0 ]] || die "no arm configs found"

failed=0
for arm in "${arms[@]}"; do
  if [[ "$arm" != /* ]]; then arm="$suite_dir/arms/$arm"; fi
  if [[ "$arm" != *.yaml && -f "$arm.yaml" ]]; then arm="$arm.yaml"; fi
  if [[ ! -f "$arm" ]]; then
    echo "stage4: missing arm $arm" >&2
    failed=1
    continue
  fi
  run_arm "$arm" || failed=1
done
exit "$failed"
