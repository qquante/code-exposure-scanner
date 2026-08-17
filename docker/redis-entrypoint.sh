#!/bin/sh
set -eu

password_file="${REDIS_PASSWORD_FILE:-/run/secrets/redis_evidence_password}"
if [ ! -s "$password_file" ]; then
  echo "senha do Redis ausente" >&2
  exit 1
fi

password="$(tr -d '\r\n' < "$password_file")"
case "$password" in
  *[!0-9a-fA-F]*|'')
    echo "senha do Redis deve ser hexadecimal" >&2
    exit 1
    ;;
esac

if [ "${#password}" -lt 32 ]; then
  echo "senha do Redis deve ter ao menos 32 caracteres" >&2
  exit 1
fi

config_file=/tmp/secret-hunter-redis.conf
umask 077
cat > "$config_file" <<EOF
bind 0.0.0.0
protected-mode yes
port 6379
requirepass $password
dir /data
appendonly yes
appendfsync everysec
aof-use-rdb-preamble yes
save 300 10
maxmemory-policy noeviction
daemonize no
EOF

exec redis-server "$config_file"
