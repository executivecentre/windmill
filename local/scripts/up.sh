#!/bin/sh
# Starts (or updates) the stack. Extra arguments are passed to `docker compose up -d`, e.g.
#   local/scripts/up.sh                      # every service
#   local/scripts/up.sh windmill_server      # recreate one service
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

if [ ! -f local/.env ]; then
	echo "up.sh: local/.env is missing; copy local/.env.example and fill it in" >&2
	exit 1
fi
if grep -q '^NO_AUTH' local/.env; then
	echo "up.sh: NO_AUTH must never be set" >&2
	exit 1
fi
for s in postgres_password windmill_database_url windmill_superadmin_secret \
	entra_gateway_db_password gateway_database_url cookie_key; do
	if [ ! -s "local/secrets/$s" ]; then
		echo "up.sh: local/secrets/$s is missing; run local/scripts/init-secrets.sh" >&2
		exit 1
	fi
done
if [ $# -eq 0 ] || printf '%s\n' "$@" | grep -qx entra_gateway; then
	for f in local/secrets/entra_client_secret local/group-mappings.yaml; do
		if [ ! -s "$f" ]; then
			echo "up.sh: $f is missing (needed by entra_gateway; see local/README.md)" >&2
			exit 1
		fi
	done
fi

docker compose --env-file local/.env -f docker-compose.yml -f docker-compose.local.yml up -d "$@"
