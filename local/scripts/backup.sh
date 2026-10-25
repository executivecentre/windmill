#!/bin/sh
# Dumps the whole Postgres cluster (Windmill and the gateway database) to
# local/backups/windmill-custom-<UTC time>.sql.gz and checks the dump before reporting success.
# Run it before every image switch or upgrade. Back up local/secrets/ separately.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
dc() { docker compose --env-file local/.env -f docker-compose.yml -f docker-compose.local.yml "$@"; }

umask 077
mkdir -p local/backups
out="local/backups/windmill-custom-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
fail() {
	rm -f "$out.tmp"
	echo "backup.sh: $1" >&2
	exit 1
}

# POSIX sh has no pipefail: a failed pg_dumpall shows up as a missing header or trailer below.
dc exec -T db pg_dumpall -U postgres | gzip >"$out.tmp"
gzip -t "$out.tmp" || fail "dump is not valid gzip"
gzip -dc "$out.tmp" | head -n 5 | grep -q 'PostgreSQL database cluster dump' || fail "dump has no cluster header"
gzip -dc "$out.tmp" | tail -n 5 | grep -q 'PostgreSQL database cluster dump complete' || fail "dump is truncated"
gzip -dc "$out.tmp" | grep -q 'CREATE TABLE public.v2_job ' || fail "dump does not contain Windmill's tables"
mv "$out.tmp" "$out"

size=$(wc -c <"$out" | tr -d ' ')
echo "backup.sh: wrote $out ($size bytes compressed)"
