#!/usr/bin/env bash
set -u
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
tcpdump_bin="${HOME}/.local/bin/dpisect-tcpdump"
target_ip=149.154.167.99
artifact_base="$repo_dir/artifacts/a02-telegram-web-2026-11"

if [[ ! -x "$tcpdump_bin" ]] || ! getcap "$tcpdump_bin" | grep -q cap_net_raw; then
  echo 'Для захвата сначала настрой dpisect-tcpdump командой из инструкции.' >&2
  exit 1
fi
route=$(ip -4 route get "$target_ip") || exit 1
iface=$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route")
if [[ -z "$iface" ]]; then
  echo 'Не удалось определить сетевой интерфейс.' >&2
  exit 1
fi
mkdir -p -- "$artifact_base" || exit 1
chmod 700 -- "$artifact_base" || exit 1
run_dir=$(mktemp -d "$artifact_base/capture-XXXXXXXX") || exit 1
printf '%s\n' "$route" > "$run_dir/route.txt"
{
  printf 'started_utc: '; date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf 'operator: %s\n' "${USER:-unknown}"
  printf 'hostname: web.telegram.org\ndestination_ipv4: %s\nport: 443\ninterface: %s\n' "$target_ip" "$iface"
  printf 'openssl: '; openssl version
} > "$run_dir/metadata.txt"
echo "Результаты: $run_dir"

capture_pid=''
cleanup() {
  if [[ -n "$capture_pid" ]]; then
    kill -INT "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
    capture_pid=''
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

"$tcpdump_bin" -n -p -U -i "$iface" -w "$run_dir/client.pcap" \
  "ip and tcp and host $target_ip and port 443" > "$run_dir/capture.log" 2>&1 &
capture_pid=$!
ready=false
for _ in {1..50}; do
  if grep -q 'listening on' "$run_dir/capture.log"; then
    ready=true
    break
  fi
  if ! kill -0 "$capture_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo 'Не удалось запустить захват; подключение не выполнялось.' >&2
  cat "$run_dir/capture.log" >&2
  exit 1
fi

echo "Захват включён на $iface. Одна попытка TLS к $target_ip:443..."
timeout 20s stdbuf -oL -eL openssl s_client -connect "$target_ip:443" \
  -servername web.telegram.org -verify_hostname web.telegram.org \
  -verify_return_error -state -msg </dev/null > "$run_dir/tls.txt" 2>&1
tls_status=$?
cleanup
{
  printf 'openssl_exit_code: %s\n' "$tls_status"
  printf 'finished_utc: '; date -u '+%Y-%m-%dT%H:%M:%SZ'
} >> "$run_dir/metadata.txt"
echo "Код OpenSSL: $tls_status (124 означает таймаут)."
echo "Готово. Сообщи ассистенту путь: $run_dir"
exit "$tls_status"
