#!/usr/bin/env bash
set -u
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
artifact_base="$repo_dir/artifacts/a02-telegram-web-2026-11"
mkdir -p -- "$artifact_base" || exit 1
chmod 700 -- "$artifact_base" || exit 1
run_dir=$(mktemp -d "$artifact_base/run-XXXXXXXX") || exit 1
echo "Результаты: $run_dir"

{
  printf 'started_utc: '; date -u '+%Y-%m-%dT%H:%M:%SZ'
  printf 'operator: %s\n' "${USER:-unknown}"
  printf 'hostname: web.telegram.org\nport: 443\n'
  printf 'openssl: '; openssl version
  printf 'timeout_seconds: 20\n'
} > "$run_dir/metadata.txt"

echo 'Определяю адрес web.telegram.org...'
if ! timeout 10s getent ahostsv4 web.telegram.org > "$run_dir/dns.txt" 2> "$run_dir/dns-error.txt"; then
  echo 'Не удалось получить IPv4 через системный DNS. Дальнейшее подключение не выполнялось.'
  exit 1
fi
target_ip=$(awk 'NR == 1 {print $1}' "$run_dir/dns.txt")
if [[ ! "$target_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo 'DNS не вернул подходящий IPv4. Подключение не выполнялось.'
  exit 1
fi
printf 'destination_ipv4: %s\n' "$target_ip" >> "$run_dir/metadata.txt"
ip -4 route get "$target_ip" > "$run_dir/route.txt" 2>&1 || true
echo "Подключаюсь к $target_ip:443 с SNI web.telegram.org (одна попытка, до 20 секунд)..."

timeout 20s openssl s_client -connect "$target_ip:443" \
  -servername web.telegram.org -verify_hostname web.telegram.org \
  -verify_return_error -state -msg </dev/null > "$run_dir/tls.txt" 2>&1
tls_status=$?
{
  printf 'openssl_exit_code: %s\n' "$tls_status"
  printf 'finished_utc: '; date -u '+%Y-%m-%dT%H:%M:%SZ'
} >> "$run_dir/metadata.txt"

if [[ $tls_status -eq 0 ]]; then
  echo 'OpenSSL завершил TLS-подключение с проверкой сертификата.'
elif [[ $tls_status -eq 124 ]]; then
  echo 'Истёк таймаут; для вывода нужны детали журнала.'
else
  echo "OpenSSL завершился с кодом $tls_status; для вывода нужны детали журнала."
fi
echo "Готово. Сообщи ассистенту путь: $run_dir"
exit "$tls_status"
