#!/bin/sh
# Creates every missing generated secret in local/secrets/. Never overwrites an existing file.
# The Entra client secret is not generated: write it yourself (see local/secrets/README.md).
set -eu
cd "$(dirname "$0")/../secrets"
umask 077

gen() { # name command...
	name=$1
	shift
	if [ -s "$name" ]; then
		echo "keep     $name"
		return
	fi
	"$@" >"$name.tmp"
	mv "$name.tmp" "$name"
	echo "created  $name"
}

gen postgres_password openssl rand -hex 32
gen windmill_superadmin_secret openssl rand -hex 32
gen entra_gateway_db_password openssl rand -hex 32
gen cookie_key openssl rand -hex 32
gen windmill_database_url sh -c 'printf "postgres://postgres:%s@db:5432/windmill?sslmode=disable" "$(cat postgres_password)"'
gen gateway_database_url sh -c 'printf "postgres://entra_gateway:%s@db:5432/entra_gateway?sslmode=disable" "$(cat entra_gateway_db_password)"'

if [ ! -s entra_client_secret ]; then
	echo "missing  entra_client_secret (needed only by entra_gateway; see README.md)"
fi
