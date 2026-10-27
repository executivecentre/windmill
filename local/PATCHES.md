# Local patches against upstream Windmill

This branch, `custom/unlimited-entra`, is Windmill's open-source code with a few patches:

- no Community Edition quotas on users, SSO users, groups and workspaces;
- SSO sign-in (Microsoft and the other providers of Instance settings → SSO), which the
  open-source code leaves as a stub;
- user creation and password changes, also stubs;
- no credentials in the request log.

It is built from Community Edition code only, with the cargo features
`oss_core,all_languages,jemalloc` (never `private`, `enterprise`, `no_auth` or `oss`), and uses no
Enterprise license. Remotes: `origin` is this fork (`https://github.com/executivecentre/windmill`),
`upstream` is Windmill (`https://github.com/windmill-labs/windmill`, read-only).

## Baseline

Upstream commit `a72484b2aaeccbd5a2d19e71ee75d21494ea74f4` (`chore(main): release 1.849.0`).

## Building and testing

- Image: upstream's `Dockerfile` with `--build-arg features=oss_core,all_languages,jemalloc`.
- From `backend/`, with `DATABASE_URL` naming a Postgres in which the tests may create databases:
  `cargo test -p windmill-api-integration-tests --test oss_sso_login --test oss_user_management
  --test users --test login_link`, and `cargo test -p windmill-api-workspaces --lib redacted_uri`.
- From `frontend/`: `npm run check` and `npx vitest run src/lib/components/sessions/`.

## Upgrading to a newer upstream release

1. `git fetch upstream --tags`, then rebase a copy of the branch:
   `git switch -c upgrade/<tag> custom/unlimited-entra && git rebase --onto <tag> <baseline>`.
   A conflict means upstream changed a patched spot: the file's **Re-apply** note says what to keep.
2. Run `local/scripts/check-upstream.sh <tag>` ([Checking the patch set](#checking-the-patch-set)),
   then the tests, and update the baseline above.
3. Tag the commit being replaced, which deployments' submodule pointers name and a force push would
   orphan: `git tag deployed/<old-version> custom/unlimited-entra`, and push the tag. Then move the
   branch to `upgrade/<tag>` and `git push --force-with-lease origin custom/unlimited-entra`.

Windmill's migrations only move forward: back up the database before a new release first runs.

## Modified upstream files

### `.gitignore`

- **Change**: `!/local/` right after upstream's `local/` rule.
- **Reason**: upstream ignores every directory named `local`; this fork keeps its notes and checks
  in the root `local/`.
- **Re-apply**: keep `!/local/` right after whatever rule matches the root `local/`.

### `backend/windmill-api-groups/src/groups.rs`

- **Change**: `_check_nb_of_groups` returns `Ok(())`.
- **Reason**: removes the cap of 3 groups. Its call site, reserved names and conflict checks stay.
- **Re-apply**: keep the signature, with `Ok(())` as the body.

### `backend/windmill-api-workspaces/src/workspaces.rs`

- **Change**: `_check_nb_of_workspaces` and `_check_nb_of_archived_workspaces` return `Ok(())`.
- **Reason**: removes the caps of 2 workspaces besides `admins` and 1 archived workspace.
  `CREATE_WORKSPACE_REQUIRE_SUPERADMIN` (on unless set to something other than `true`) still
  decides who may create workspaces.
- **Re-apply**: as for groups, per function.

### `frontend/src/lib/components/sessions/sessionState.svelte.ts`

- **Change**: `CE_MAX_NON_ADMIN_WORKSPACES` is `Number.POSITIVE_INFINITY` instead of `2`.
- **Reason**: the UI's copy of the workspace cap.
- **Re-apply**: the same value; if upstream moves the cap, neutralise its comparison only.

### `frontend/src/lib/components/sessions/WorkspaceFamilyPicker.svelte`

- **Change**: `CE_MAX_NON_ADMIN_WORKSPACES` is `Number.POSITIVE_INFINITY` instead of `2`, so the
  "Workspace limit reached" row never shows.
- **Reason**: the UI's copy of the workspace cap.
- **Re-apply**: as for `sessionState.svelte.ts`.

### `frontend/src/lib/components/sessions/sessionState.test.ts`

- **Change**: the test that expected the cap to refuse a fork now expects the fork to be created.
- **Reason**: pins the removal of the cap.
- **Re-apply**: keep upstream's setup and assert that `createWorkspaceFork` is called.

### `frontend/src/lib/components/AuthSettings.svelte`

- **Change**: the SSO tab's "Limited to 10 SSO users" notice is removed.
- **Reason**: this build has no such limit. The rest of the tab is upstream's, and configures the
  sign-in of `oauth2_oss_local.rs`.
- **Re-apply**: remove the notice again.

### `backend/windmill-api/src/oauth2_oss.rs`

- **Change**: `build_oauth_clients` fills `logins` from `oauth2_oss_local.rs` instead of leaving it
  empty; `global_service` serves that file's routes (`/list_logins`, `/login/{client}`,
  `/login_callback/{client}`) instead of the empty `list_logins` stub, which stays with
  `#[allow(dead_code)]`; `check_nb_of_user` (10 SSO accounts, 50 accounts) returns `Ok(())`.
- **Reason**: the open-source build has no SSO sign-in; the official images get it, and those
  caps, from Enterprise code.
- **Re-apply**: re-add the `mod local` declaration and the two calls, and keep `check_nb_of_user`
  a no-op. If upstream ever ships open-source SSO sign-in, use it and drop `oauth2_oss_local.rs`.

### `backend/windmill-api/src/users_oss.rs`

- **Change**: the stubs `create_user`, `set_password` and `hash_password`, which returned "not
  implemented", delegate to `users_oss_local.rs`, declared `pub(crate) mod local` so that SSO
  sign-in shares its account insertion.
- **Reason**: without them nobody can create a user or change a password, the default admin's
  `changeme` included.
- **Re-apply**: re-add the declaration and the three one-line delegations. If upstream changes a
  stub's signature, change the matching function in `users_oss_local.rs`.

### `backend/windmill-api-workspaces/src/remote_deploy.rs`

- **Change**: `RedactedUri`, which formats every request URI the server logs
  (`windmill-api/src/tracing_init.rs`), also masks the token in `/api/auth/login_link/<token>` and
  the values of the `token` and `code` query parameters. Unit test
  `redacted_uri_masks_login_links_and_credential_queries`.
- **Reason**: the server logs every request at INFO, static pages included, so the authorization
  code of each SSO sign-in (`/user/login_callback/<provider>?code=`), login-link tokens and
  `?token=` credentials would land in the logs.
- **Re-apply**: keep `RedactedUri` the only formatter of logged URIs and extend its lists.

### `backend/windmill-api-integration-tests/Cargo.toml`

- **Change**: depends on `windmill-api` with the `oauth2` feature.
- **Reason**: `tests/oss_sso_login.rs` loads SSO clients into the test server.
- **Re-apply**: re-add the dependency.

### `backend/Cargo.lock`

- **Change**: the `windmill-api` entry this adds to the dependencies of
  `windmill-api-integration-tests`.
- **Re-apply**: let cargo regenerate it.

## Files added outside `local/`

They sit next to upstream code because the build and test layout needs them there, and they
conflict with nothing on rebase.

- `backend/windmill-api/src/oauth2_oss_local.rs`: SSO sign-in. Providers come from the `oauths`
  instance setting (Instance settings → SSO): one with a `login_config` (Microsoft with its tenant,
  Okta, Auth0, custom) uses it, the others `backend/oauth_login.json`, and Microsoft without a
  tenant is not offered, since its fallback `/common` admits any Microsoft account. The callback
  matches the account by lower-cased e-mail (`docs/auth-surface.md`): an account of the same
  provider signs in, a `pending_oauth` one is claimed, a new e-mail gets an account unless
  pre-existing users are required, superadmin, devops and disabled accounts are refused, and so
  are accounts of another login type unless pre-existing users are required.
- `backend/windmill-api/src/users_oss_local.rs`: user creation, password changes (Argon2id) and
  the account insertion SSO sign-in shares.
- `backend/windmill-api-integration-tests/tests/oss_sso_login.rs`: SSO sign-in against a mock
  provider.
- `backend/windmill-api-integration-tests/tests/oss_user_management.rs`: user creation and
  password changes.

## Checking the patch set

`local/scripts/check-upstream.sh <upstream-ref>` compares the committed branch with
`<upstream-ref>`: the files outside `local/` that differ must be exactly the entries of the two
sections above, and a `git grep` for edition-limit wording (`without an enterprise license`,
`maximum number of`, `CE_MAX`, `check_nb_of`, `Community edition is limited`, `limited to <n>`)
must find exactly the hits recorded in `local/edition-limits.txt`. A new hit after an upgrade is
upstream code to review: a new cap to patch, or an unrelated string. Record the reviewed state with
`local/scripts/check-upstream.sh --print-limits > local/edition-limits.txt`.

Left unpatched on purpose: the cloud-only quotas (behind `CLOUD_HOSTED`), the 30-day cap on job
retention (`CE_MAX_RETENTION_PERIOD_SECS`), and the rule that only superadmins join the `admins`
workspace.
