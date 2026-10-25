#!/bin/sh
# Entrypoint for every windmill-custom server and worker container.
set -eu

# NO_AUTH turns authentication off at runtime whatever its value; refuse to start with it.
if [ -n "${NO_AUTH+x}" ]; then
	echo "windmill-entrypoint: NO_AUTH is set; refusing to start" >&2
	exit 1
fi

# Windmill reads SUPERADMIN_SECRET only from the environment; keep it out of the compose
# file and `docker inspect` by loading it from a secret file here.
if [ -n "${SUPERADMIN_SECRET_FILE:-}" ]; then
	if [ ! -s "$SUPERADMIN_SECRET_FILE" ]; then
		echo "windmill-entrypoint: SUPERADMIN_SECRET_FILE is empty or unreadable" >&2
		exit 1
	fi
	SUPERADMIN_SECRET=$(cat "$SUPERADMIN_SECRET_FILE")
	export SUPERADMIN_SECRET
	unset SUPERADMIN_SECRET_FILE
fi

exec windmill "$@"
