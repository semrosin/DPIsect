#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
[[ $# -eq 1 && -n "$1" ]] || { printf '%s\n' 'Usage: bash experiments/b01/google-youtube/restore-offload.sh INTERFACE' >&2; exit 1; }
iface=$1
artifact_dir=artifacts/b01-google-youtube-repeat-2026-11
before=$artifact_dir/offload-before.txt
[[ -f "$before" ]] || { printf '%s\n' 'Original offload snapshot is missing.' >&2; exit 1; }
[[ "$(head -n 1 "$before")" == "Features for $iface:" ]] || {
  printf '%s\n' 'Interface differs from the original snapshot.' >&2
  exit 1
}
work=$(mktemp -d "$artifact_dir/.restore-XXXXXX")
trap 'rm -rf -- "$work"' EXIT

settings() {
  awk '$1 ~ /:$/ && ($2 == "on" || $2 == "off") && $0 !~ /\[fixed\]/ {
    sub(/:$/, "", $1); print $1, $2
  }' "$1"
}
# Restore parents first and children afterward, in the order of the snapshot.
# Changing a parent can also change its child flags.
settings "$before" > "$work/expected"
while read -r name value; do
  ethtool -k "$iface" > "$work/current"
  actual=$(awk -v name="$name:" '$1 == name {print $2}' "$work/current")
  [[ "$actual" == on || "$actual" == off ]] || {
    printf 'Cannot read feature: %s\n' "$name" >&2
    exit 1
  }
  if [[ "$actual" != "$value" ]]; then
    printf 'Restoring %s: %s -> %s\n' "$name" "$actual" "$value"
    sudo ethtool -K "$iface" "$name" "$value"
  fi
done < "$work/expected"
ethtool -k "$iface" > "$work/final"
settings "$work/final" > "$work/actual"
diff -u "$work/expected" "$work/actual"
cp "$work/final" "$artifact_dir/offload-restored.txt"
printf '%s\n' 'All mutable offload features match the original snapshot. No network probes sent.'
