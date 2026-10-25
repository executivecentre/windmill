# local/secrets

Docker secrets for the stack, one value per file. Everything in this directory except this
README is git-ignored. Keep the files mode `600`, and back them up alongside the database: a
database backup without `postgres_password` and `entra_gateway_db_password` cannot be used
with this stack.

`local/scripts/init-secrets.sh` creates every generated file that is missing and never
overwrites one. To create them by hand instead:

```sh
cd local/secrets
umask 077
openssl rand -hex 32 > postgres_password
openssl rand -hex 32 > windmill_superadmin_secret
openssl rand -hex 32 > entra_gateway_db_password
openssl rand -hex 32 > cookie_key
printf 'postgres://postgres:%s@db:5432/windmill?sslmode=disable' "$(cat postgres_password)" > windmill_database_url
printf 'postgres://entra_gateway:%s@db:5432/entra_gateway?sslmode=disable' "$(cat entra_gateway_db_password)" > gateway_database_url
```

| File | Used by | What it is |
| --- | --- | --- |
| `postgres_password` | db | Password of the `postgres` superuser. Read only when the volume is first created. |
| `windmill_database_url` | Windmill server and workers | Connection URL using `postgres_password` |
| `windmill_superadmin_secret` | Windmill server, gateway | Windmill's `SUPERADMIN_SECRET`: a bearer token with instance-superadmin rights. Only the gateway uses it. |
| `entra_gateway_db_password` | db (init), gateway | Password of the `entra_gateway` role. Read by the db init scripts on a fresh volume. |
| `gateway_database_url` | gateway | Connection URL using `entra_gateway_db_password` |
| `cookie_key` | gateway | 32 random bytes, hex: encrypts the short-lived sign-in state cookie |
| `entra_client_secret` | gateway | The client secret **value** from the Entra app registration. Not generated, so write it yourself: `printf '%s' '<value>' > entra_client_secret` |

## Rotation

- **`windmill_superadmin_secret` or `cookie_key`:** write a new value, then recreate
  `windmill_server` and `entra_gateway` (`local/scripts/up.sh --force-recreate windmill_server
  entra_gateway`). Rotating `cookie_key` only cancels sign-ins that are in progress.
- **`entra_client_secret`:** create a new secret in Entra, write it here, recreate
  `entra_gateway`, then delete the old secret in Entra.
- **Database passwords:** the files are read only when the volume is created. Change the
  password in Postgres first (`ALTER ROLE … PASSWORD …`), then update both the password file
  and the URL file, and recreate the services that use them.
