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

### Lint and format state of the baseline

Measured on the host toolchain (cargo/rustfmt 1.99 / rustfmt 1.10.0, newer than the Dockerfile's
`rust:1.97`), on files this fork does not touch:

- `cargo fmt --check` (from `backend/`) reports diffs in 40 upstream files (parsers, `tests/`,
  ...). None of the fork's Rust files are among them; each fork file is checked with `rustfmt
  --check` individually.
- `cargo clippy` stops on deny-by-default lints in untouched crates:
  `windmill-queue/src/jobs.rs:7525` (`absurd_extreme_comparisons`) and
  `windmill-worker/src/bun_executor.rs:2588` (`ifs_same_cond`). Run with `-- --cap-lints warn`
  to reach the fork's crates; the fork's files then show only the codebase-wide
  `result_large_err` (from `windmill_common::error::Error`) and one `unnecessary_to_owned` in the
  untouched `submit_onboarding_data` stub of `users_oss.rs`.
- The integration-test crate links `rdkafka`, whose build script needs `cmake`.

## Modified upstream files

### `.gitignore`

- **Change**: one line `!/local/` right after the upstream `local/` rule.
- **Reason**: upstream ignores every directory named `local`; this fork keeps its deployment and
  gateway sources in the root `local/`. `local/.gitignore` then excludes `.env`, `secrets/*`,
  `dist/`, `backups/` and the operator's `group-mappings.yaml`.
- **Re-apply**: if upstream moves or removes its `local/` rule, keep `!/local/` immediately after
  whatever rule would match the root `local/` directory.

### `backend/windmill-api-groups/src/groups.rs`

- **Change**: body of `_check_nb_of_groups` replaced with `Ok(())`; parameter renamed `_db`.
- **Reason**: removes the CE cap of 3 non-native groups. The call site in `create_group`
  (`#[cfg(not(feature = "enterprise"))]`) is left as is, as are reserved group names and
  `check_name_conflict`.
- **Re-apply**: keep the function signature, replace its body with `Ok(())`. If upstream renames
  it or inlines the count, neutralise the count/threshold check only.

### `backend/windmill-api-workspaces/src/workspaces.rs`

- **Change**: bodies of `_check_nb_of_workspaces` and `_check_nb_of_archived_workspaces` replaced
  with `Ok(())`; parameters renamed `_db`.
- **Reason**: removes the CE caps of 2 non-`admins` workspaces and 1 archived workspace. Call
  sites (`create_workspace`, the fork creation path, `archive_workspace`, `unarchive_workspace`)
  stay. `CLOUD_HOSTED` quotas, `CREATE_WORKSPACE_REQUIRE_SUPERADMIN`, `DISABLE_WORKSPACE_FORK`,
  `MAX_FORK_DEPTH`, the `admins` membership rule and name validation are untouched.
- **Re-apply**: same as above, per function.

### `backend/windmill-api/src/oauth2_oss.rs`

- **Change**: body of `check_nb_of_user` replaced with `Ok(())`; parameter renamed `_db`.
- **Reason**: consistency (10 SSO / 50 users cap). No OSS code calls it, so this is a no-op.
- **Re-apply**: replace the body with `Ok(())`.

### `backend/windmill-api/src/users_oss.rs`

- **Change**: the three `#[cfg(not(feature = "private"))]` stubs that returned "not implemented"
  are implemented with runtime `sqlx::query*` (no `query!` macros, so `backend/.sqlx` is
  unchanged):
  - `hash_password`: refuses passwords shorter than 12 characters (`BadRequest`), then hashes
    with the shared `Argon2::default()` (Argon2id, PHC string). Also covers `reset_password`.
  - `create_user`: superadmin only (`require_super_admin`; the route wrapper already refuses job
    tokens). Email is trimmed and lowercased, checked with `VALID_EMAIL` and `usr_accepts_email`.
    `login_type` defaults to `password` and must be one of `password`, `pending_oauth`, `entra`;
    `password` requires a password, the other two must not carry one and store a NULL hash. `has_any_account` and the `password` primary key both map to 409, so
    concurrent duplicates leave one row. Instance username follows `automate_username_creation`
    (reuse the `pending_user` reservation or generate one, then drop the reservation; NULL when
    automation is off). Inserts with `verified = true`, writes the `users.add_global` audit entry
    (no-op in OSS) and sends the `UserAdded` instance webhook. `skip_email` is ignored: OSS sends
    no welcome email.
  - `set_password`: the caller must be the target or a superadmin. Only `password` and
    `pending_oauth` rows are updated (the latter becomes `password`); identity-provider accounts
    get 400 and never gain a password. Session deletion and MCP grant revocation stay in the
    route wrappers in `windmill-api/src/users.rs`, which are unchanged.
- **Reason**: OSS has no way to create users or set passwords otherwise; the Entra gateway and
  the break-glass admin need both.
- **Tests**: `backend/windmill-api-integration-tests/tests/oss_user_management.rs` (new file),
  including an ungated port of `test_set_password_revokes_mcp_oauth_grants`, whose upstream copy
  in `tests/users.rs` is gated on `enterprise` + `private`.
- **Re-apply**: if upstream changes the stub signatures, adapt the bodies; if upstream ever ships
  an OSS implementation, drop this patch and the new test file and rerun the tests against it.

### `frontend/src/lib/components/sessions/sessionState.svelte.ts`

- **Change**: removed the `CE_MAX_NON_ADMIN_WORKSPACES` guard that threw before materialising a
  pending fork, and the now-unused `enterpriseLicense` import.
- **Reason**: UI mirror of the removed backend workspace cap.
- **Re-apply**: delete the block that compares the non-`admins` workspace count with
  `CE_MAX_NON_ADMIN_WORKSPACES`; drop `enterpriseLicense` from the import if nothing else uses it.
  The `enterpriseLicense` store itself is not changed.

### `frontend/src/lib/components/sessions/WorkspaceFamilyPicker.svelte`

- **Change**: removed `CE_MAX_NON_ADMIN_WORKSPACES`, `nonAdminWorkspaceCount`,
  `ceWorkspaceCapReached`, `forkAffordanceOpen` and `showForkUpsell`, the disabled
  "Workspace limit reached" row, and the unused `enterpriseLicense` import. `showCreateFork` is now
  the former `forkAffordanceOpen` condition.
- **Reason**: UI mirror of the removed backend workspace cap.
- **Re-apply**: make `showCreateFork` equal to the structural gate (`allowCreateFork &&
  forksGateOpen && (onCreateFork || onRequestCreateFork) && root`) and delete the upsell branch.

### `frontend/src/lib/components/AuthSettings.svelte`

- **Change**: the SSO tab content (the "Limited to 10 SSO users" alert, the
  require-preexisting-user toggle, all built-in and custom SSO provider forms and the
  "Add custom SSO client" popover) is replaced by one `Alert` stating that SSO is provided by the
  Microsoft Entra ID gateway at `/sso/login`. Imports and helpers used only by that tab
  (`OktaSetting`, `Auth0Setting`, `KeycloakSetting`, `CustomSso`, `AuthentikSetting`,
  `AutheliaSetting`, `PocketIdSetting`, `KanidmSetting`, `ZitadelSetting`, `NextcloudSetting`,
  `Popover`, the `sso*` state and handlers) are removed because the frontend type check runs with
  `noUnusedLocals` and `--threshold warning`.
- **Reason**: OSS `build_oauth_clients`/`list_logins` return no login clients, so that form
  configured nothing. The OAuth (resource connect) and SCIM/SAML tabs and every other
  license-gated control are unchanged.
- **Re-apply**: replace the body of the `{#if tab === 'sso'}` branch (after the
  `SettingsPageHeader`) with the alert, then remove whatever the type check reports as unused.

### `backend/windmill-api-workspaces/src/remote_deploy.rs`

- **Change**: `RedactedUri` (the request URI that `windmill-api/src/tracing_init.rs` writes into
  the request span and request record) also masks the segment after `/api/auth/login_link/` and
  the value of any `token` query parameter (`token=***`). New unit test
  `redacted_uri_masks_login_links_and_token_queries`.
- **Reason**: the server logged every request URI at INFO, so the single-use login-link token
  the gateway hands to the browser, and `?token=` credentials accepted by `extract_token`, landed
  in container logs. Found by the credential scan in `local/test/e2e.sh`.
- **Re-apply**: keep `RedactedUri` as the only thing that formats request URIs for logs; extend
  its prefix list and query masking. If upstream moves `RedactedUri` or stops using it in
  `tracing_init.rs`, apply the same masking wherever the request URI is logged.

### `frontend/src/routes/(root)/(logged)/user/(user)/login/+page.svelte`

- **Change**: unless the URL has `local=1`, the page calls
  `window.location.replace('/sso/login?<same query>')` (adding the `rd` it takes from
  `localStorage`, if the query has none) and skips its own session check and redirects.
- **Reason**: Caddy sends full page loads of `/user/login` to the gateway, but sign-out, session
  expiry and the 404 handler reach this route by client-side navigation, which never reaches
  Caddy, and would leave Entra users on a password form they cannot use. The route file is
  patched, not `Login.svelte`, which is also embedded in approval and public-app pages.
- **Re-apply**: at the top of the route's script, before anything navigates, redirect every
  visit without `local=1` to `/sso/login` with the query string.

### `frontend/src/lib/logoutKit.ts`

- **Change**: `logout()` clears the Windmill session as before, then does
  `window.location.replace('/sso/logout')` instead of `goto('/user/login')` and a toast; the
  `sendUserToast` import is dropped. `logoutWithRedirect` is unchanged (it lands on
  `/user/login`, which now goes to the gateway).
- **Reason**: the gateway's `/sso/logout` also ends the Entra session. Without it, the sign-in
  that follows a sign-out would complete silently against the live Entra session.
- **Re-apply**: make the user-initiated sign-out end with a full navigation to `/sso/logout`.
