#!/bin/sh
# TEST ONLY: end-to-end SSO run through Caddy against mock-entra, as the separate compose project
# windmill-custom-e2e (docker-compose.test.yml) on https://localhost:3443. Its database is in
# tmpfs; its secrets, test CA and certificates are generated in local/test/run/ (git-ignored).
#
#   local/test/e2e.sh          up + test
#   local/test/e2e.sh up       build mock-entra, generate test material, start the project
#   local/test/e2e.sh test     smoke.sh, the E2E driver, then log scans for credentials
#   local/test/e2e.sh down     stop and remove the project's containers (volumes are kept)
#
# Needs windmill-custom:local and windmill-entra:local (local/scripts/build.sh).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
run=local/test/run
env_file=local/test/e2e.env
files="docker-compose.yml docker-compose.local.yml docker-compose.test.yml"
dc() {
	set -- --env-file "$env_file" $(printf -- '-f %s ' $files) "$@"
	docker compose "$@"
}
env_value() { sed -n "s/^$1=//p" "$env_file" | tail -n 1; }
base=$(env_value PUBLIC_BASE_URL)

gen_material() {
	umask 077
	mkdir -p "$run/secrets" "$run/tls"
	s="$run/secrets"
	for f in postgres_password windmill_superadmin_secret entra_gateway_db_password cookie_key; do
		[ -s "$s/$f" ] || openssl rand -hex 32 >"$s/$f"
	done
	[ -s "$s/entra_client_secret" ] || openssl rand -hex 24 >"$s/entra_client_secret"
	printf 'postgres://postgres:%s@db:5432/windmill?sslmode=disable' "$(cat "$s/postgres_password")" >"$s/windmill_database_url"
	printf 'postgres://entra_gateway:%s@db:5432/entra_gateway?sslmode=disable' "$(cat "$s/entra_gateway_db_password")" >"$s/gateway_database_url"

	t="$run/tls"
	if [ ! -s "$t/mock-entra.crt" ]; then
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=windmill-custom e2e test CA" \
			-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
			-keyout "$t/ca.key" -out "$t/ca.crt" 2>/dev/null
		printf 'subjectAltName=DNS:mock-entra,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' >"$t/ext.cnf"
		openssl req -newkey rsa:2048 -nodes -subj "/CN=mock-entra" -keyout "$t/mock-entra.key" -out "$t/mock-entra.csr" 2>/dev/null
		openssl x509 -req -days 2 -in "$t/mock-entra.csr" -CA "$t/ca.crt" -CAkey "$t/ca.key" -CAcreateserial \
			-extfile "$t/ext.cnf" -out "$t/mock-entra.crt" 2>/dev/null
		rm -f "$t/mock-entra.csr" "$t/ext.cnf" "$t/ca.srl"
	fi
}

wait_for() { # description seconds command...
	what=$1 secs=$2
	shift 2
	i=0
	until "$@" >/dev/null 2>&1; do
		i=$((i + 2))
		if [ "$i" -gt "$secs" ]; then
			echo "e2e.sh: timed out waiting for $what" >&2
			exit 1
		fi
		sleep 2
	done
}

up() {
	for img in windmill-custom:local windmill-entra:local; do
		docker image inspect "$img" >/dev/null 2>&1 || {
			echo "e2e.sh: $img missing; run local/scripts/build.sh" >&2
			exit 1
		}
	done
	gen_material
	DOCKER_BUILDKIT=1 docker build -q -t windmill-mock-entra:test local/test/mock-entra >/dev/null
	GATEWAY_USER=$(ls -n "$run/secrets/gateway_database_url" | awk '{print $3 ":" $4}')
	export GATEWAY_USER
	dc up -d
	wait_for "Caddy's root certificate" 60 dc exec -T caddy test -s /data/caddy/pki/authorities/local/root.crt
	dc exec -T caddy cat /data/caddy/pki/authorities/local/root.crt >"$run/caddy-root.crt"
	wait_for "Windmill through Caddy" 240 curl -fsS --cacert "$run/caddy-root.crt" "$base/api/version"
	wait_for "entra_gateway healthy" 180 sh -c \
		'[ "$(docker inspect --format "{{.State.Health.Status}}" "$1")" = healthy ]' _ "$(dc ps -q entra_gateway)"
	echo "e2e.sh: windmill-custom-e2e is up at $base"
}

# Every credential the stack handles must stay out of every container log.
scan_logs() {
	dc logs --no-color >"$run/all.log" 2>&1
	bad=0
	n=$(grep -cE '/api/auth/login_link/[A-Za-z0-9_-]' "$run/all.log" || true)
	if [ "$n" = 0 ]; then echo "PASS  no login-link URL in any container log"; else
		echo "FAIL  login-link URLs in container logs: $n lines"
		bad=1
	fi
	n=$(grep -cE '[?&]code=[A-Za-z0-9_-]{16,}' "$run/all.log" || true)
	if [ "$n" = 0 ]; then echo "PASS  no authorization code in any container log"; else
		echo "FAIL  authorization codes in container logs: $n lines"
		bad=1
	fi
	n=$(grep -cE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ' "$run/all.log" || true)
	if [ "$n" = 0 ]; then echo "PASS  no JWT in any container log"; else
		echo "FAIL  JWTs in container logs: $n lines"
		bad=1
	fi
	for f in "$run"/secrets/*; do
		if grep -qF "$(cat "$f")" "$run/all.log"; then
			echo "FAIL  secret $(basename "$f") appears in container logs"
			bad=1
		else
			echo "PASS  secret $(basename "$f") absent from container logs"
		fi
	done
	if [ -s "$run/tokens.txt" ]; then
		leaked=0
		while read -r tok; do grep -qF "$tok" "$run/all.log" && leaked=$((leaked + 1)); done <"$run/tokens.txt"
		if [ "$leaked" = 0 ]; then echo "PASS  no Windmill session or API token in container logs"; else
			echo "FAIL  $leaked Windmill tokens appear in container logs"
			bad=1
		fi
	fi
	rm -f "$run/tokens.txt"
	return "$bad"
}

test_all() {
	status=0
	echo "== smoke.sh against the e2e project"
	SMOKE_ENV_FILE="$env_file" SMOKE_COMPOSE_FILES="$files" SMOKE_AUTHORITY_URL=https://mock-entra:8443 \
		SMOKE_PUBLISHED_OK="caddy mock_entra" sh local/scripts/smoke.sh || status=1
	echo "== SSO end-to-end driver"
	python3 -I local/test/e2e_driver.py --base "$base" --env "$env_file" --run "$run" \
		--compose "$(printf -- '-f %s ' $files)" || status=1
	echo "== credential scan of all container logs"
	scan_logs || status=1
	return "$status"
}

case "${1:-all}" in
up) up ;;
test) test_all ;;
down) dc down ;;
all)
	up
	test_all
	;;
*)
	echo "usage: $0 [up|test|down|all]" >&2
	exit 2
	;;
esac
