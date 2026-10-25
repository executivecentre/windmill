#!/bin/sh
# Fresh volumes only. Every role may CONNECT to a new database by default (PUBLIC), so stop the
# gateway role from opening any database but its own. pg_hba.conf is first-match.
set -eu
hba="$PGDATA/pg_hba.conf"
{
	echo "# windmill-custom: entra_gateway may only reach its own database"
	echo "host    entra_gateway   entra_gateway   all     scram-sha-256"
	echo "host    all             entra_gateway   all     reject"
	echo "local   all             entra_gateway           reject"
	cat "$hba"
} >"$hba.new"
mv "$hba.new" "$hba"
