#!/usr/bin/env bash
set -u
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." || exit 1

exp_dir=experiments/h03-capture-retry-2026-11
artifact_dir=artifacts/h03-capture-retry-2026-11
prober="${HOME}/.local/bin/dpi-prober-h03"
helper="${HOME}/.local/bin/dpi-helper-h03"
if [[ -e "$artifact_dir" || -e "$exp_dir/plan.yaml" || -e "$exp_dir/run.json" ]]; then
  echo 'Артефакты уже существуют; остановлено для защиты предыдущего запуска.' >&2
  exit 1
fi
for binary in "$prober" "$helper"; do
  if [[ ! -x "$binary" ]] || ! getcap "$binary" | grep -q cap_net_raw; then
    echo "Нужны готовый бинарь и cap_net_raw: $binary" >&2
    exit 1
  fi
done
mkdir -m 700 -p "$artifact_dir" || exit 1
helper_pid=''
cleanup() {
  if [[ -n "$helper_pid" ]]; then
    kill -INT "$helper_pid" 2>/dev/null || true
    wait "$helper_pid" 2>/dev/null || true
    helper_pid=''
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

"$helper" -addr 127.0.0.1:18443 -profile accepting \
  -log "$artifact_dir/helper.log" -capture-iface lo \
  -capture-pcap "$artifact_dir/server.pcap" \
  > "$artifact_dir/helper-stderr.log" 2>&1 &
helper_pid=$!
ready=false
for _ in {1..100}; do
  if [[ -f "$artifact_dir/helper.log" ]] && grep -q '"event":"start"' "$artifact_dir/helper.log"; then
    ready=true
    break
  fi
  if ! kill -0 "$helper_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo 'Локальный helper не запустился; проба не отправлялась.' >&2
  cat "$artifact_dir/helper-stderr.log" >&2
  exit 1
fi

echo 'Локальный helper готов. Запускается одна проба.'
"$prober" -config "$exp_dir/config.yaml" -operator "${USER:-unknown}" -capture-iface lo
result=$?
cleanup
echo "Пробер завершился с кодом $result. Артефакты: $artifact_dir"
exit "$result"
