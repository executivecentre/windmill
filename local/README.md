# windmill-custom

A self-hosted build of open-source Windmill (AGPLv3, Community Edition code only) with two
changes:

1. **No CE numeric quotas:** unlimited users, groups, workspaces and archived workspaces.
2. **Microsoft Entra ID sign-in**, through a separate login gateway
   ([`entra-gateway/`](entra-gateway/README.md)) that provisions accounts and syncs workspace
   roles and groups from Entra groups.

No Enterprise code is built, and no Enterprise license is used: the cargo features are
`oss_core,all_languages,jemalloc`, and `build.sh` refuses `private`, `enterprise`, `no_auth` and
`oss`. Every upstream file this fork changes is listed with its reason in
[`PATCHES.md`](PATCHES.md).

## What runs

| Service | Image | Reachable from |
| --- | --- | --- |
| `caddy` | `caddy:2.11.4` (pinned) | host: `CADDY_HTTPS_BIND` (443) and `CADDY_HTTP_BIND` (80, redirects to https) |
| `windmill_server` | `windmill-custom:local` | Caddy only |
| `windmill_worker` ×3, `windmill_worker_native` | `windmill-custom:local` | no inbound |
| `entra_gateway` | `windmill-entra:local` | Caddy only (`/sso/*`) |
| `db` | `postgres:18` (pinned) | internal only. Holds databases `windmill` and `entra_gateway`. |
| `windmill_extra` | official `windmill-extra` (pinned) | Caddy (`/ws/*`): language servers only. Debugger and multiplayer are off. `WINDMILL_EXTRA_REPLICAS=0` runs no official image at all, at the cost of editor code intelligence. |

The indexer (full-text job search) is Enterprise-only and runs with 0 replicas. Caddy is the only
service that publishes host ports.

Caddy's routing (`Caddyfile`):

- `/user/login` goes to `/sso/login`, so every interactive sign-in is via Entra.
  `/user/login?local=1` (the password form) and `/api/auth/login` are allowed only from
  `ADMIN_ALLOWED_CIDRS` and get 403 from anywhere else. This is the break-glass path. The
  Windmill frontend does the same redirect for in-app navigations, which never reach Caddy
  (see `PATCHES.md`).
- `SUPERADMIN_SECRET` (in the `Authorization` header, the `token` cookie or `?token=`) gets 403
  from outside `ADMIN_ALLOWED_CIDRS`. The gateway uses it on the internal network only. Caddy
  reads the secret file for this, so `windmill_superadmin_secret` is also mounted into `caddy`.
- `/ws/*` (`windmill_extra`'s language servers, which do no authentication of their own) needs
  a valid Windmill session or token: Caddy checks it with `/api/users/whoami` first.
- `/api/users/login_links`, `/api/users/create` and `/api/users/overwrite` always get 403
  through Caddy. Only the gateway calls them, on the internal network.
- `/source/` serves the source code (see [Source code offer](#source-code-offer-agplv3-13)).
- Caddy writes no access log. Its error log is excluded, because error entries carry request
  URIs, and two of those URIs are credentials (`/api/auth/login_link/*` and
  `/sso/callback?code=…`).

## First-time setup

All commands run from the repository root.

1. **Configuration.** `cp local/.env.example local/.env`, then fill in `PUBLIC_HOST`,
   `PUBLIC_BASE_URL`, `ADMIN_ALLOWED_CIDRS`, `CADDY_TLS` (see [TLS](#tls)) and the Entra
   values.
2. **Secrets.** `local/scripts/init-secrets.sh` generates every random secret into
   `local/secrets/` ([details](secrets/README.md)). Then write the Entra client secret to
   `local/secrets/entra_client_secret`.
3. **Entra app registration and group mapping.** Follow
   [entra-gateway/README.md](entra-gateway/README.md#entra-app-registration). Then
   `cp local/entra-gateway/group-mappings.example.yaml local/group-mappings.yaml` and put your
   group Object IDs and workspace ids in it.
4. **Build.** `local/scripts/build.sh` builds both images from the current commit; the Windmill
   image took 17 minutes with 18 CPUs and 16 GB of RAM given to Docker (arm64). Build from a clean tree: images built with
   uncommitted changes are labelled `<sha>-dirty`, and those can't be published as source.
5. **Source bundle.** `local/scripts/make-source-bundle.sh`.
6. **Start.** `local/scripts/up.sh`. It refuses to start while a secret or the mapping file is
   missing. Compose mounts file secrets with their host owner and mode, so `up.sh` runs the
   gateway as the owner of `local/secrets/` (`GATEWAY_USER`); if that owner is root, it asks you
   to `chown 65532:65532` the gateway's four secret files instead. Before the Entra values exist you can start everything except the gateway:
   `local/scripts/up.sh db windmill_server windmill_worker windmill_worker_native windmill_extra caddy`.
   `/sso/*` then shows a "single sign-on is unavailable" page. Windmill and the gateway apply
   their own database migrations at start.
7. **Break-glass admin.** Windmill seeds `admin@windmill.dev` with the password `changeme` in
   every new database. `local/scripts/set-admin-password.sh` replaces it with
   `local/secrets/windmill_admin_password` (it does nothing once the seeded password stops
   working). Then, from an address in `ADMIN_ALLOWED_CIDRS`, open
   `${PUBLIC_BASE_URL}/user/login?local=1`, sign in as `admin@windmill.dev` with that password,
   and create the workspaces your mapping file names. The gateway never creates workspaces.
8. **Check.** `local/scripts/smoke.sh` should print only PASS lines, plus one SKIP if the
   gateway is not running yet.

Entra users who sign in are created as `entra` accounts. They are never instance superadmins,
and Windmill refuses to set a password on an `entra` account. Give instance administration to
the break-glass account only.

## Access changes and sign-out

- **Sign out** in Windmill ends at the gateway's `/sso/logout`, which ends the Entra session
  too, so the next visit asks Entra to sign in again.
- **Removing a user from an Entra group** takes effect at their next sign-in, or at the next
  reconcile run (`RECONCILE_INTERVAL`, default 15m), whichever comes first. Windmill caches a
  session's permissions for up to 120 s, so an open session can keep a removed workspace that
  long after the reconcile. In the E2E run (1-minute interval) it took 45 s to disable the
  membership and 70 s more for the open session to lose it.
- **Disabling the account in Entra** disables the Windmill account at the next reconcile run,
  and its sessions stop working at once.

## TLS

`CADDY_TLS` picks one of three modes:

| Value | Use |
| --- | --- |
| an e-mail address, e.g. `ops@corp.example` | Public certificate from Let's Encrypt (automatic HTTPS). `PUBLIC_HOST` must resolve to this host from the internet, and ports 80 and 443 must be reachable. |
| `internal` | Caddy's own CA, for LAN or test use. Browsers must trust its root, which you export with `docker compose … exec caddy cat /data/caddy/pki/authorities/local/root.crt`. |
| `/certs/cert.pem /certs/key.pem` | Your own certificate. Uncomment the `./local/certs:/certs:ro` volume of `caddy` in `docker-compose.local.yml` and put the PEM files in `local/certs/` (git-ignored). |

`PUBLIC_BASE_URL` must be `https://…`, and include the port when it isn't 443. Windmill marks
its session cookie `Secure` only for an https base URL.

## Everyday operations

`docker compose` must always get both files and the env file. The scripts do this for you:

```sh
docker compose --env-file local/.env -f docker-compose.yml -f docker-compose.local.yml <command>
```

| Task | Command |
| --- | --- |
| Start or update | `local/scripts/up.sh` (`up -d`; extra arguments are passed on, e.g. a service name or `--force-recreate`) |
| Smoke test | `local/scripts/smoke.sh` |
| Backup | `local/scripts/backup.sh`: a full `pg_dumpall` to `local/backups/`, checked before it reports success. Copy `local/secrets/` with it. |
| Gateway audit trail | see [entra-gateway/README.md](entra-gateway/README.md#behaviour) (`sync_event`) |
| Logs | `docker compose … logs -f windmill_server entra_gateway` |

**Restoring a backup** onto a new, empty `db` volume:

1. Put the `local/secrets/` from the backup's time back in place. The dump restores the roles'
   old passwords, so the URL secrets must match.
2. `local/scripts/up.sh db`, and wait until it is healthy.
3. `gzip -dc local/backups/<file>.sql.gz | docker compose … exec -T -u postgres db psql -U postgres -q`
4. `local/scripts/up.sh`

Step 3 prints four expected errors, because the fresh volume already has the `postgres` and
`entra_gateway` roles and both databases. Every other statement must succeed.

## Testing

`local/test/` holds a TEST-ONLY end-to-end run against a mock Entra ID (OIDC with PKCE, and
Microsoft Graph), as the separate compose project `windmill-custom-e2e` on
https://localhost:3443. Its database lives in tmpfs, and its secrets and certificates are generated
into `local/test/run/` (git-ignored). It never touches the main stack's volumes.

| Command | What it does |
| --- | --- |
| `local/test/e2e.sh` | start the project, then `smoke.sh`, the SSO driver (sign-in, roles, groups, jobs, tokens, webhooks, `wmill` CLI, replay and denial cases, reconcile), and a scan of every container log for credentials |
| `local/test/e2e.sh browser` | a real browser (Playwright from `frontend/node_modules`) through the SPA's sign-in, sign-out and session-expiry paths |
| `local/test/e2e.sh down` | remove the project's containers (named volumes are kept) |

A real Entra tenant is not part of these tests.

## Existing database volumes

`local/db-init/` runs only when the `db` volume is created. When you switch an existing
Windmill database to this stack, first run `local/scripts/backup.sh` (or `pg_dumpall` with your
old stack) and check that the dump is non-empty. Then create the gateway's database and role by
hand, with the same files:

```sh
dc() { docker compose --env-file local/.env -f docker-compose.yml -f docker-compose.local.yml "$@"; }
dc up -d db
dc exec -T -u postgres db psql -U postgres -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/10-entra-gateway.sql
dc exec -T -u postgres db sh /docker-entrypoint-initdb.d/20-entra-gateway-hba.sh
dc exec -T -u postgres db psql -U postgres -c 'select pg_reload_conf()'
```

The SQL reads the role's password from the `entra_gateway_db_password` secret, which compose
mounts into `db`. The hba script lets the `entra_gateway` role connect only to its own database.
Run each step once.

## Upgrading to a newer upstream release

1. Back up (`local/scripts/backup.sh`, plus a copy of `local/secrets/`).
2. `git fetch origin`, then rebase `custom/unlimited-entra` onto the release commit or tag.
   Resolve conflicts with the **Re-apply** notes in `PATCHES.md`. Then rerun the edition-limit
   sweep recorded there, to catch any new cap.
3. Run the fork's tests:
   - `oss_user_management` and `login_link` in `backend/windmill-api-integration-tests`;
   - `go test -race ./...` for the gateway;
   - the frontend type check;
   - `local/test/e2e.sh` and `local/test/e2e.sh browser` (after the build in step 4).
4. `local/scripts/build.sh`. The previous images stay available as `windmill-custom:prev` and
   `windmill-entra:prev`.
5. `local/scripts/make-source-bundle.sh`, then `local/scripts/up.sh`, then
   `local/scripts/smoke.sh`.
6. Record the new baseline commit in `PATCHES.md`.

**Rollback:** Windmill migrations only move forward. Going back means restoring the backup
from step 1 *and* retagging `:prev` as `:local`. Swapping the image alone is not enough.

## Source code offer (AGPLv3 §13)

Windmill is licensed under the GNU AGPLv3, and this deployment runs a modified version. Users
can download its source code from `${PUBLIC_BASE_URL}/source/`: one archive per commit an image
was built from, plus `README.txt` and `SHA256SUMS`. Every page the sign-in gateway shows links
to it. `make-source-bundle.sh` writes the archives with `git archive` from the images' revision
labels, so the archives always match what runs, and git-ignored files (`local/.env`,
`local/secrets/`) are never included. Rerun it after every build.

## Limits of the Community Edition

Building from OSS code means the Enterprise features are absent. Among them:

- custom workspace roles (only admin, developer and operator exist);
- audit logs (the gateway keeps its own `sync_event` trail);
- SCIM and SAML;
- the full-text job indexer;
- the multiplayer editor.

`CE_MAX_RETENTION_PERIOD_SECS` still caps job retention at 30 days. Cloud-only quotas don't
apply to a self-hosted instance. `PATCHES.md` lists what was deliberately left untouched.
