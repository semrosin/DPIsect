#!/usr/bin/env bash
set -Eeuo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
[[ $# -eq 0 ]] || { printf '%s\n' 'Usage: bash experiments/b01/google-youtube/review-stage2.sh (offline only)' >&2; exit 1; }

export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
go_binary=$(command -v go)
required=$(awk '$1 == "go" {print $2}' go.mod)
if [[ "$(go env GOVERSION)" != "go$required" ]]; then
  module_cache=$(go env GOMODCACHE)
  host_os=$(go env GOHOSTOS)
  host_arch=$(go env GOHOSTARCH)
  cached=$module_cache/golang.org/toolchain@v0.0.1-go$required.$host_os-$host_arch/bin/go
  [[ ! -x "$cached" ]] || go_binary=$cached
fi

# This program only reads plans, metadata, logs and PCAP files. It has no sender.
exec "$go_binary" run ./experiments/b01/google-youtube/review \
  experiments/b01/google-youtube/b01-google-youtube-sni-2026-11 \
  experiments/b01/google-youtube/b01-google-youtube-repeat-2026-11 \
  experiments/b02/google-youtube/b02-google-youtube-compact-2026-11 \
  experiments/b04/google-youtube/b04-google-youtube-field-2026-11 \
  experiments/b07/google-youtube/b07-google-offset-paced-2026-11 \
  experiments/b07/google-youtube/b07-google-length-2026-11
