# Local patches against upstream Windmill

This branch, `feature/custom-unlimited`, is Windmill's open-source code with a few patches:

- no Community Edition quotas on users, SSO users, groups and workspaces;
- SSO sign-in (Microsoft and the other providers of Instance settings → SSO), which the
  open-source code leaves as a stub;
- user creation and password changes, also stubs;
- workspace auto-add and auto-invite of instance accounts, also a stub;
- no credentials in the request log;
- Cargo's version where the build cannot describe a release tag, so version-gated features stay
  on;
- AI Portal branding: its mark as the favicon and on the sidebar and login page, "AI Portal" as
  the name there and in page titles, and no "Powered by Windmill" badge on shared apps.

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
  --test oss_auto_invite --test users --test login_link --test workspaces`, and
  `cargo test -p windmill-api-workspaces --lib redacted_uri`.
- From `frontend/`: `npm run check` and `npx vitest run src/lib/components/sessions/`.

## Upgrading to a newer upstream release

1. `git fetch upstream --tags`, then rebase a copy of the branch:
   `git switch -c upgrade/<tag> feature/custom-unlimited && git rebase --onto <tag> <baseline>`.
   A conflict means upstream changed a patched spot: the file's **Re-apply** note says what to keep.
2. Run `local/scripts/check-upstream.sh <tag>` ([Checking the patch set](#checking-the-patch-set)),
   then the tests, and update the baseline above.
3. Tag the commit being replaced, which deployments' submodule pointers name and a force push would
   orphan: `git tag deployed/<old-version> feature/custom-unlimited`, and push the tag. Then move
   the branch to `upgrade/<tag>` and `git push --force-with-lease origin feature/custom-unlimited`.

Windmill's migrations only move forward: back up the database before a new release first runs.

## Modified upstream files

### `.gitignore`

- **Change**: `!/local/` right after upstream's `local/` rule.
- **Reason**: upstream ignores every directory named `local`; this fork keeps its notes and checks
  in the root `local/`.
- **Re-apply**: keep `!/local/` right after whatever rule matches the root `local/`.

### `backend/windmill-common/src/utils.rs`

- **Change**: the `git_version!` call that defines `GIT_VERSION` drops `--always` and takes
  `cargo_prefix = "v"`, so a build in which `git describe` finds no tag, or cannot run, reports
  `v<Cargo version>`, not a bare commit hash or `unknown-version`.
- **Reason**: this fork has no tags, and the image is built from it as a submodule of the
  deployment repository, whose `.git` file names a directory outside the build context, so
  `git describe` fails there. A bare hash or `unknown-version` parses as 0.1.0, which
  `min_version.rs` takes for the oldest worker: every version-gated feature turns off (token
  hashes, AES-GCM secrets, ...), and the raw-app bundler asks npm for `windmill-cli@0.1.0`.
- **Re-apply**: keep `cargo_prefix = "v"`, and no `--always`, on whatever defines `GIT_VERSION`,
  and check that `windmill --version` in a built image prints the release.

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

### `frontend/static/logo.svg`

- **Change**: the brand mark (`BRAND_MARK_PATH` of `src/lib/branding.ts`) in `BRAND_COLOR`, white
  under a dark colour scheme, instead of Windmill's.
- **Reason**: the favicon (`app.html`, `favicon.ts`). It is also the manifest's SVG icon and the
  default source of a new low-code image component. A static file cannot import `branding.ts`,
  so this copy changes with it.
- **Re-apply**: overwrite upstream's file with this one.

### `frontend/src/lib/favicon.ts`

- **Change**: the status favicon of a run page draws the brand mark (`LOGO_MARK`, built from
  `branding.ts` and scaled to the 256-unit canvas, white under a dark colour scheme) instead of
  Windmill's polygons.
- **Reason**: otherwise a run page swaps the favicon back to Windmill's mark.
- **Re-apply**: replace whatever inlines Windmill's logo with `LOGO_MARK`.

### `frontend/src/routes/(root)/(logged)/+layout.svelte`

- **Change**: the sidebar's brand row (the Home link) shows `BrandIcon` and `BRAND_NAME` instead
  of `WindmillIcon` and "Windmill" (a whitelabel license name still takes precedence), and
  `apple-mobile-web-app-title` is `BRAND_NAME`.
- **Reason**: the console's brand.
- **Re-apply**: on whatever renders the sidebar brand, swap the icon and the fallback name; set
  the meta tag again.

### `frontend/src/routes/+layout.svelte`

- **Change**: the default page title ends in `BRAND_NAME` instead of "Windmill".
- **Reason**: the browser tab's title on most pages.
- **Re-apply**: replace "Windmill" in the `<title>` template.

### `frontend/src/routes/(root)/(logged)/pipeline/+page.svelte`

- **Change**: the `<title>` ends in `BRAND_NAME` instead of "Windmill".
- **Reason**: this page sets its own tab title.
- **Re-apply**: as for the root layout.

### `frontend/src/routes/(root)/(logged)/pipeline/[folder]/+page.svelte`

- **Change**: the `<title>` ends in `BRAND_NAME` instead of "Windmill".
- **Reason**: this page sets its own tab title.
- **Re-apply**: as for the root layout.

### `frontend/src/routes/(styled)/public_run/[workspace]/[id]/+page.svelte`

- **Change**: the `<title>` ends in `BRAND_NAME` instead of "Windmill".
- **Reason**: this page sets its own tab title.
- **Re-apply**: as for the root layout.

### `frontend/src/routes/(root)/(logged)/user/(user)/login/+page.svelte`

- **Change**: the login page's centred mark is `BrandIcon`, spinning slowly, instead of
  `WindmillIcon`. A whitelabel license name still hides it.
- **Reason**: the login page's brand.
- **Re-apply**: swap the icon above the login heading.

### `frontend/src/lib/components/LoginHeading.svelte`

- **Change**: the instance name falls back to `BRAND_NAME` instead of "Windmill", so the heading
  reads "Log in to AI Portal" ("Log in or sign up to AI Portal" with third-party sign-in).
- **Reason**: the login page's brand.
- **Re-apply**: change the fallback name again.

### `frontend/src/lib/components/apps/editor/PublicApp.svelte`

- **Change**: the "Powered by Windmill" badge at the bottom right of shared apps (public, custom
  path and embed routes) is removed, with the imports only it used and its mention in the props'
  comments.
- **Reason**: shared apps carry no Windmill attribution.
- **Re-apply**: remove the badge again; `license` stays, it still gates a low-code app's custom
  CSS.

### `frontend/src/lib/components/apps/editor/publicAppApi.ts`

- **Change**: `getLicenseOrUndefined`'s comment no longer mentions the badge.
- **Reason**: follows the badge's removal.
- **Re-apply**: drop the badge from the comment.

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

### `backend/windmill-api-workspaces/src/workspaces_oss.rs`

- **Change**: the stub `edit_auto_invite`, which returned "Not implemented on OSS", delegates to
  `workspaces_oss_local.rs`, declared `pub mod local` so that account creation in `windmill-api`
  can call its `join_auto_invite_workspaces`.
- **Reason**: without it, Workspace settings → Users cannot switch on auto-add or auto-invite. The
  official images get both from Enterprise code.
- **Re-apply**: re-add the declaration and the one-line delegation. If upstream changes the stub's
  signature or `EditAutoInvite`, change `workspaces_oss_local.rs` to match.

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
conflict with nothing on rebase. They do build upstream types, though: a field upstream adds to
one breaks the build, not the merge, and neither git nor `check-upstream.sh` notices it, only a
compile.

- `backend/windmill-api/src/oauth2_oss_local.rs`: SSO sign-in. Providers come from the `oauths`
  instance setting (Instance settings → SSO): one with a `login_config` (Microsoft with its tenant,
  Okta, Auth0, custom) uses it, the others `backend/oauth_login.json`, and Microsoft without a
  tenant is not offered, since its fallback `/common` admits any Microsoft account. The callback
  matches the account by lower-cased e-mail (`docs/auth-surface.md`): an account of the same
  provider signs in, a `pending_oauth` one is claimed, a new e-mail gets an account unless
  pre-existing users are required, superadmin, devops and disabled accounts are refused, and so
  are accounts of another login type unless pre-existing users are required. It sends no PKCE:
  the SSO tab's "Send PKCE" toggle, switched on for a new provider, has no effect in this build,
  and a provider that requires PKCE cannot sign users in.
- `backend/windmill-api/src/users_oss_local.rs`: user creation, password changes (Argon2id) and
  the account insertion SSO sign-in shares, which also joins each new account to the workspaces
  that auto-add or auto-invite it.
- `backend/windmill-api-workspaces/src/workspaces_oss_local.rs`: workspace auto-add and
  auto-invite. The setting is `workspace_settings.auto_invite` in the shape the frontend reads
  (`enabled`, `domain`, `operator`, `role`, `mode`), beside the Enterprise instance-group keys,
  which every write keeps. Switching it on applies it to the existing accounts: all of them for
  "anyone joining the instance" (`domain` `*`), else those of the admin's e-mail domain. Every
  account created afterwards, by an admin or by a first SSO sign-in, joins in the transaction that
  creates it, with `added_via` `{"source": "domain"}` (the UI's "Auto-add" badge). A workspace
  whose setting cannot be applied, such as one naming a deleted role, is skipped with a warning
  and never fails the account's creation. Auto-add needs instance-wide usernames (automated
  username creation, on by default), and sends no `UserAddedWorkspace` instance event, which a
  manual add sends.
- `frontend/src/lib/branding.ts`: the brand in one place, `BRAND_NAME`, `BRAND_COLOR` and the
  mark (`BRAND_MARK_PATH` in a `BRAND_MARK_SIZE` square). Every patched brand spot reads it;
  `static/logo.svg` repeats the mark and colour. Rebranding means editing these two files.
- `frontend/src/lib/components/icons/BrandIcon.svelte`: the brand mark as an inline SVG, in
  `BRAND_COLOR` under the light theme and white under the dark one, whatever text colour the
  caller passes. It accepts `WindmillIcon`'s props, `spin` included (off under reduced motion).
- `backend/windmill-api-integration-tests/tests/oss_sso_login.rs`: SSO sign-in against a mock
  provider.
- `backend/windmill-api-integration-tests/tests/oss_user_management.rs`: user creation and
  password changes.
- `backend/windmill-api-integration-tests/tests/oss_auto_invite.rs`: auto-add and auto-invite,
  with the request bodies the frontend sends.

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
