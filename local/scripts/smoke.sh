#!/bin/sh
# Post-deploy smoke test through Caddy at PUBLIC_BASE_URL. Unauthenticated: it checks routing
# and the security boundaries, not workloads. Prints PASS/FAIL/SKIP per check and exits non-zero
# if anything failed. The SMOKE_* variables exist for local/test/e2e.sh; a deployment leaves
# them unset.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
env_file=${SMOKE_ENV_FILE:-local/.env}
compose_files=${SMOKE_COMPOSE_FILES:-"docker-compose.yml docker-compose.local.yml"}
authority=${SMOKE_AUTHORITY_URL:-https://login.microsoftonline.com}
published_ok=${SMOKE_PUBLISHED_OK:-caddy}
dc() {
	set -- --env-file "$env_file" $(printf -- '-f %s ' $compose_files) "$@"
	docker compose "$@"
}
env_value() { sed -n "s/^$1=//p" "$env_file" | tail -n 1; }

base=$(env_value PUBLIC_BASE_URL)
host=$(env_value PUBLIC_HOST)
[ -n "$base" ] && [ -n "$host" ] || {
	echo "smoke.sh: PUBLIC_BASE_URL and PUBLIC_HOST must be set in local/.env" >&2
	exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl_tls=""
if [ "$(env_value CADDY_TLS)" = "internal" ]; then
	dc exec -T caddy cat /data/caddy/pki/authorities/local/root.crt >"$tmp/ca.crt" 2>/dev/null
	curl_tls="--cacert $tmp/ca.crt"
fi

failed=0
pass() { echo "PASS  $1"; }
fail() {
	echo "FAIL  $1"
	failed=1
}
skip() { echo "SKIP  $1"; }
# req METHOD PATH -> prints "<status> <location>", body in $tmp/body
req() {
	# shellcheck disable=SC2086
	curl -sS $curl_tls -o "$tmp/body" -X "$1" -w '%{http_code} %{redirect_url}' "$base$2" 2>"$tmp/err" || echo "000 "
}
expect() { # description METHOD PATH STATUS
	got=$(req "$2" "$3" | cut -d' ' -f1)
	if [ "$got" = "$4" ]; then pass "$1 ($2 $3 -> $got)"; else fail "$1 ($2 $3 -> $got, want $4)"; fi
}

# --- containers -------------------------------------------------------------------------------
for svc in db windmill_server windmill_worker windmill_worker_native caddy; do
	if dc ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx "$svc"; then
		pass "service $svc running"
	else
		fail "service $svc running"
	fi
done
# Only Caddy may publish host ports; everything else, windmill_server:8000 included, is internal.
dc ps --format '{{.Service}} {{.Ports}}' 2>/dev/null >"$tmp/ports"
while read -r svc ports; do
	case " $published_ok " in *" $svc "*) continue ;; esac
	case "$ports" in
	*"->"*) fail "service $svc publishes host ports: $ports" ;;
	*) pass "service $svc publishes no host port" ;;
	esac
done <"$tmp/ports"
if dc exec -T windmill_server sh -c '[ -z "${NO_AUTH+x}" ]' 2>/dev/null; then
	pass "NO_AUTH unset in windmill_server"
else
	fail "NO_AUTH unset in windmill_server"
fi

# --- Windmill through Caddy -------------------------------------------------------------------
out=$(req GET /api/version)
case "$out" in
"200 "*) grep -q '^CE ' "$tmp/body" && pass "version is CE: $(cat "$tmp/body")" || fail "version is not CE: $(cat "$tmp/body")" ;;
*) fail "GET /api/version -> ${out%% *}" ;;
esac
expect "unauthenticated API call refused" GET /api/users/whoami 401
expect "login links only from the gateway" POST /api/users/login_links 403
expect "account creation only from the gateway" POST /api/users/create 403
expect "account overwrite only from the gateway" POST /api/users/overwrite 403
out=$(req GET '/user/login?rd=%2Fscripts')
case "$out" in
"302 $base/sso/login?rd=%2Fscripts") pass "/user/login redirects to SSO" ;;
*) fail "/user/login redirects to SSO (got: $out)" ;;
esac
expect "login-link error page still reaches Windmill" GET /user/login_link_expired 200
expect "language servers refuse unauthenticated requests" GET /ws/health 401

# --- break-glass password login ----------------------------------------------------------------
# From inside the compose network the caller is a container address, which must not be in
# ADMIN_ALLOWED_CIDRS. -k: this probe checks a status code from Caddy, reached by service name.
code=$(dc exec -T windmill_server curl -sk -o /dev/null -w '%{http_code}' -X POST \
	-H 'Content-Type: application/json' -d '{}' \
	--connect-to "$host:443:caddy:443" "https://$host/api/auth/login" 2>/dev/null || echo 000)
if [ "$code" = 403 ]; then
	pass "password login refused from a non-admin address (-> 403)"
else
	fail "password login refused from a non-admin address (-> $code, want 403)"
fi

codes=$(dc exec -T windmill_server sh -c 's=$(cat /run/secrets/windmill_superadmin_secret)
	c() { curl -sk -o /dev/null -w "%{http_code} " --connect-to "$h:443:caddy:443" "$@"; }
	h=$1
	c -H "Authorization: Bearer $s" "https://$h/api/users/whoami"
	c --cookie "token=$s" "https://$h/api/users/whoami"
	c "https://$h/api/users/whoami?token=$s"' _ "$host" 2>/dev/null || echo 000)
if [ "$codes" = "403 403 403 " ]; then
	pass "SUPERADMIN_SECRET refused from a non-admin address (header, cookie, query -> 403)"
else
	fail "SUPERADMIN_SECRET refused from a non-admin address (got: $codes, want 403 403 403)"
fi

code=$(dc exec -T windmill_server curl -s -o /dev/null -w '%{http_code}' -X POST \
	-H 'Content-Type: application/json' -d '{"email":"admin@windmill.dev","password":"changeme"}' \
	http://localhost:8000/api/auth/login 2>/dev/null || echo 000)
case "$code" in
4??) pass "admin@windmill.dev refuses the seeded password (-> $code)" ;;
*) fail "admin@windmill.dev refuses the seeded password (-> $code; run local/scripts/set-admin-password.sh)" ;;
esac

# --- AGPL source offer -------------------------------------------------------------------------
out=$(req GET /source/)
if [ "${out%% *}" = 200 ] && grep -q 'windmill-custom-src-' "$tmp/body"; then
	pass "source offer served at /source/"
else
	fail "source offer served at /source/ (run local/scripts/make-source-bundle.sh)"
fi

# --- Entra gateway ------------------------------------------------------------------------------
if dc ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx entra_gateway; then
	health=$(docker inspect --format '{{.State.Health.Status}}' "$(dc ps -q entra_gateway)")
	[ "$health" = healthy ] && pass "entra_gateway healthy" || fail "entra_gateway health: $health"
	out=$(req GET /sso/login)
	idp="$authority/$(env_value ENTRA_TENANT_ID)/oauth2/v2.0/authorize?"
	case "$out" in
	"302 $idp"*) pass "/sso/login redirects to ${idp}…" ;;
	*) fail "/sso/login redirects to ${idp}… (got: ${out%%\?*})" ;;
	esac
else
	skip "entra_gateway not running (Entra values not configured?)"
	expect "SSO unavailable page while the gateway is down" GET /sso/login 503
fi

exit "$failed"
