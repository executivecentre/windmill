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

# File secrets keep their host owner and mode inside containers, so run the gateway as their
# owner, never as root: root-owned secrets must be handed to the image's user 65532.
owner=$(ls -n local/secrets/gateway_database_url | awk '{print $3 ":" $4}')
case "$owner" in
0:*)
	for f in local/secrets/gateway_database_url local/secrets/cookie_key \
		local/secrets/windmill_superadmin_secret local/secrets/entra_client_secret; do
		if [ -e "$f" ] && [ "$(ls -n "$f" | awk '{print $3}')" != 65532 ]; then
			echo "up.sh: $f is owned by root; the gateway cannot read it. Run:" >&2
			echo "  sudo chown 65532:65532 local/secrets/{gateway_database_url,cookie_key,windmill_superadmin_secret,entra_client_secret}" >&2
			exit 1
		fi
	done
	GATEWAY_USER=65532:65532
	;;
*) GATEWAY_USER=$owner ;;
esac
export GATEWAY_USER

docker compose --env-file local/.env -f docker-compose.yml -f docker-compose.local.yml up -d "$@"
