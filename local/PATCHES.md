# Local patches against upstream Windmill

This branch (`custom/unlimited-entra`) carries a small set of patches on top of the official
OSS repository (`origin` = `https://github.com/windmill-labs/windmill.git`, read-only). Everything
local lives under `local/` and `docker-compose.local.yml`; every upstream file that is modified is
listed in [Modified upstream files](#modified-upstream-files) with the reason and how to re-apply
it after an upstream change.

## Baseline

| Item | Value |
|---|---|
| Upstream commit | `a72484b2aaeccbd5a2d19e71ee75d21494ea74f4` (`chore(main): release 1.849.0 (#12002)`) |
| Upstream commit date | 2026-10-25T16:57:47+01:00 |
| Branch created | 2026-10-26 |
| Build features | `oss_core,all_languages,jemalloc` (never `private`, `enterprise`, `no_auth`, `oss`) |

### `backend/Cargo.toml` edition features (at baseline)

- `oss_core` = `embedding, parquet, openidconnect, license, http_trigger, zip, oauth2,
  postgres_trigger, mqtt_trigger, amqp_trigger, websocket, smtp, native_trigger, static_frontend,
  mcp, bedrock, run_inline, quickjs`
- `oss` = `oss_core + all_languages + no_auth` (not used: it compiles auth off)
- `ce_core` = `oss_core + private + operator`; `ce` = `ce_rpi + jemalloc + dind + agent_worker_server`
- `ee` = `ce + ee_core + ee_server + kafka-gssapi`
- `tantivy` (search indexer) implies `enterprise` + `parquet`
- `license` is part of `oss_core`; it only compiles the license-key plumbing, it does not require
  or fake a key.

### Dockerfile build args (at baseline)

`DEBIAN_IMAGE=debian:trixie-slim`, `RUST_IMAGE=rust:1.97-slim-trixie`, `features=""`,
`WM_BUILD_VERSION=""`, `POWERSHELL_VERSION=7.5.0`, `KUBECTL_VERSION=1.37.1`, `HELM_VERSION=3.21.4`,
`GO_VERSION=1.27.1`, `NODE_VERSION=24.22.1`, `WITH_POWERSHELL|WITH_KUBECTL|WITH_HELM|WITH_GIT=true`,
`LATEST_STABLE_PY=3.12`, `NEW_INSTANCE_PY=3.13`, `CRANE_VERSION=v0.22.1`. The build sets
`SQLX_OFFLINE=true` and uses `backend/.sqlx`.

### Upstream `docker-compose.yml` services (at baseline)

`db` (postgres:18), `windmill_server`, `windmill_worker` (3 replicas), `windmill_worker_native`,
`windmill_indexer` (replicas 0, EE), `windmill_extra` (`ghcr.io/windmill-labs/windmill-extra`,
LSP + debugger), `caddy` (`ghcr.io/windmill-labs/caddy-l4:2.11.4-1`, ports 80 and 25).
`DATABASE_URL` and `WM_IMAGE` come from the env file; upstream hard-codes
`POSTGRES_PASSWORD: changeme`.

## Facts re-verified at the baseline commit

All rows of the brief's section 1 hold at `a72484b2`. Additional details found while verifying:

- `NO_AUTH` (env) is ignored when `CLOUD_HOSTED` is set (`windmill-common/src/worker.rs`).
- `SUPERADMIN_SECRET` authenticates as `superadmin_secret@windmill.dev` with `is_admin = true` and
  `job_id = None` (`windmill-api-auth/src/auth.rs`); `is_super_admin_email` returns true for that
  address, so `require_super_admin` passes. The comparison with the configured secret is a plain
  `==` (upstream).
- `create_group` adds the caller to the new group (`usr_to_group` row for `authed.username`).
- The `set_password` / `set_password_of` route wrappers in `windmill-api/src/users.rs` already
  delete sessions and revoke MCP OAuth grants after calling `users_oss::set_password`.
- `reset_password` (unauthenticated, SMTP-based) also calls `users_oss::hash_password`.
- Login links: default TTL 600 s, clamped to 1..=900 s; URL is built from the `BASE_URL` global
  (`base_url` global setting if non-empty, else the `BASE_URL` env var, else `http://localhost`).
  The session cookie is `Secure` only when that base URL starts with `https://`.
- `update_user` with `disabled: true` deletes all of the user's `token` rows; the DB trigger only
  notifies cache invalidation for `label = 'session'` rows, so other tokens stay valid in
  `AUTH_CACHE` for up to 120 s.
- `CREATE_WORKSPACE_REQUIRE_SUPERADMIN` / `DISABLE_WORKSPACE_FORK`: only the literal `"true"`
  enables them when set.

### Edition-limit sweep

`rg -n "without an enterprise license|maximum number of|CE_MAX|Community edition is limited|Limited to [0-9]+" backend frontend/src`

Patched (the four requested quotas and their UI):

| Hit | Limit |
|---|---|
| `backend/windmill-api-groups/src/groups.rs` `_check_nb_of_groups` | 3 groups |
| `backend/windmill-api-workspaces/src/workspaces.rs` `_check_nb_of_workspaces` | 2 workspaces |
| `backend/windmill-api-workspaces/src/workspaces.rs` `_check_nb_of_archived_workspaces` | 1 archived |
| `backend/windmill-api/src/oauth2_oss.rs` `check_nb_of_user` (dead code in OSS) | 10 SSO / 50 users |
| `frontend/src/lib/components/sessions/sessionState.svelte.ts` `CE_MAX_NON_ADMIN_WORKSPACES` | UI cap |
| `frontend/src/lib/components/sessions/WorkspaceFamilyPicker.svelte` `CE_MAX_NON_ADMIN_WORKSPACES` | UI cap |
| `frontend/src/lib/components/AuthSettings.svelte` "Limited to 10 SSO users" | UI notice |

Left untouched (not one of the four quotas):

- Cloud-only quotas behind `*CLOUD_HOSTED`: scripts (5000), flows (1000), apps (1000),
  resources/variables (10000), tokens (10000), workspaces (10).
- `CE_MAX_RETENTION_PERIOD_SECS` (30-day job retention clamp on CE builds,
  `windmill-common/src/instance_config.rs`, mirrored in `frontend/.../instanceSettings.ts`).
- "The admins workspace is reserved for superadmins" membership rule (`workspaces.rs`).
- `WORKSPACE_MAX_QUEUED_JOBS` (an instance setting, not an edition limit).
- Unrelated strings (AI token limit message, a dbt test assertion, DOM typings, UI help text).

## Modified upstream files

### `.gitignore`

- **Change**: one line `!/local/` right after the upstream `local/` rule.
- **Reason**: upstream ignores every directory named `local`; this fork keeps its deployment and
  gateway sources in the root `local/`. `local/.gitignore` then excludes `.env`, `secrets/*`,
  `dist/`, `backups/` and the operator's `group-mappings.yaml`.
- **Re-apply**: if upstream moves or removes its `local/` rule, keep `!/local/` immediately after
  whatever rule would match the root `local/` directory.
