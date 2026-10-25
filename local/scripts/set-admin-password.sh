#!/bin/sh
# Gives the break-glass account admin@windmill.dev the password in
# local/secrets/windmill_admin_password. Windmill seeds that account in every new database with
# the well-known password `changeme`; this replaces it, and does nothing once the seeded password
# no longer works. Runs inside windmill_server as the superadmin secret, and the new password
# travels on stdin, never on a command line. The STACK_* variables exist for local/test/e2e.sh.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
env_file=${STACK_ENV_FILE:-local/.env}
compose_files=${STACK_COMPOSE_FILES:-"docker-compose.yml docker-compose.local.yml"}
pw_file=${ADMIN_PASSWORD_FILE:-local/secrets/windmill_admin_password}
dc() {
	set -- --env-file "$env_file" $(printf -- '-f %s ' $compose_files) "$@"
	docker compose "$@"
}

if [ ! -s "$pw_file" ]; then
	echo "set-admin-password.sh: $pw_file is missing; run local/scripts/init-secrets.sh" >&2
	exit 1
fi

code=$(dc exec -T windmill_server curl -s -o /dev/null -w '%{http_code}' -X POST \
	-H 'Content-Type: application/json' -d '{"email":"admin@windmill.dev","password":"changeme"}' \
	http://localhost:8000/api/auth/login || echo 000)
case "$code" in
200) ;;
4??)
	echo "set-admin-password.sh: admin@windmill.dev no longer accepts the seeded password; nothing to do"
	exit 0
	;;
*)
	echo "set-admin-password.sh: Windmill did not answer the login probe (HTTP $code); is windmill_server up?" >&2
	exit 1
	;;
esac

printf '{"password":"%s"}' "$(cat "$pw_file")" | dc exec -T windmill_server sh -c \
	'curl -sf -o /dev/null -X POST -H "Authorization: Bearer $(cat /run/secrets/windmill_superadmin_secret)" \
		-H "Content-Type: application/json" --data-binary @- \
		http://localhost:8000/api/users/set_password_of/admin@windmill.dev'
echo "set-admin-password.sh: replaced the seeded password of admin@windmill.dev"
