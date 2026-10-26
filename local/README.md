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

## Repository layout

This repository holds the code and the image build. How the images run (compose files for
development and production, Caddy, secrets, the deploy scripts and the end-to-end tests) lives
in the deployment repository, which includes this one as the submodule `windmill-custom/`; see
its `deploy/README.md`.

| Path | What it is |
| --- | --- |
| upstream files listed in `PATCHES.md` | the patches (kept to a few lines each) |
| `Dockerfile` | upstream's, unchanged; `build.sh` passes the features |
| `local/entra-gateway/` | the sign-in gateway (Go), with its own `Dockerfile` |
| `local/scripts/build.sh` | builds `windmill-custom:local` and `windmill-entra:local` |
| `local/scripts/make-source-bundle.sh` | AGPL source archives into `local/dist/` |
| `local/scripts/check-upstream.sh`, `local/edition-limits.txt` | checks the patch set against upstream |

Remotes: `origin` is this fork (`https://github.com/executivecentre/windmill.git`), `upstream`
is Windmill (`https://github.com/windmill-labs/windmill.git`, read-only). The fork's `main`
tracks upstream (GitHub's **Sync fork**), and `custom/unlimited-entra` is `main` at a release
plus the patches.

## Building

`local/scripts/build.sh` builds both images from the current commit; the Windmill image took 17
minutes with 18 CPUs and 16 GB of RAM given to Docker (arm64). Build from a clean tree: images
built with uncommitted changes are labelled `<sha>-dirty`, and those can't be published as
source. The previous images stay available as `windmill-custom:prev` and `windmill-entra:prev`.
Then run `local/scripts/make-source-bundle.sh`.

## Testing

- `oss_user_management`, `oss_entra_gateway_flow`, `users` and `login_link` in
  `backend/windmill-api-integration-tests`;
- `go test -race ./...` in `local/entra-gateway` (the integration tests need
  `GATEWAY_TEST_DATABASE_URL`);
- the frontend type check (`npm run check`) and `npx vitest run src/lib/components/sessions/`
  from `frontend/`;
- the deployment repository's `deploy/test/e2e.sh` and `deploy/test/e2e.sh browser`, against
  the built images.

## Upgrading to a newer upstream release

1. Back up the deployment (its `deploy/scripts/backup.sh`, plus a copy of `deploy/secrets/`).
2. Rebase a copy of the branch, so the deployed one stays intact until the new one passes:
   ```sh
   git fetch upstream --tags
   local/scripts/check-upstream.sh <current-base>     # the commit in PATCHES.md "Baseline"
   git switch -c upgrade/<tag> custom/unlimited-entra
   git rebase --onto <tag> <current-base>
   ```
   Most fork changes live in fork-owned files (`local/`, the files under "Files added outside
   `local/`"), which never conflict. The upstream patches are kept to a few lines each, so a
   conflict means upstream edited that exact spot. Resolve it with the file's **Re-apply** note in
   `PATCHES.md`. Then run `local/scripts/check-upstream.sh <tag>`. It fails on a lost or
   unrecorded patch, and on any new edition-limit hit (possibly a new cap) until it is reviewed
   and recorded, as `PATCHES.md` "Checking the patch set" describes.
3. Run the [tests](#testing) (the e2e run after the build in step 4).
4. `local/scripts/build.sh`, then `local/scripts/make-source-bundle.sh`.
5. Publish. The rebase rewrites the branch, so first tag the commit it replaces: the
   deployment's older submodule pointers name it, and an untagged commit disappears from the
   fork after a force push.
   ```sh
   git tag deployed/<old-version> custom/unlimited-entra && git push origin deployed/<old-version>
   git branch -f custom/unlimited-entra upgrade/<tag>    # while upgrade/<tag> is checked out
   git push --force-with-lease origin custom/unlimited-entra
   ```
6. In the deployment repository: check out the new commit in `windmill-custom/`, run
   `deploy/scripts/up.sh` and `deploy/scripts/smoke.sh`, and commit the new submodule pointer.
7. Record the new baseline commit in `PATCHES.md`.

**Rollback:** Windmill migrations only move forward. Going back means restoring the backup
from step 1 *and* retagging `:prev` as `:local`. Swapping the image alone is not enough.

## Source code offer (AGPLv3 §13)

Windmill is licensed under the GNU AGPLv3, and a deployment of this build runs a modified
version, so it must offer users the source. `make-source-bundle.sh` writes one archive per
commit an image was built from, plus `README.txt` and `SHA256SUMS`, into `local/dist/`, using
`git archive` on the images' revision labels: the archives always match what runs, and
git-ignored files are never included. The deployment's Caddy serves the directory at
`${PUBLIC_BASE_URL}/source/`, and every page the sign-in gateway shows links to it. Rerun it
after every build.

## Limits of the Community Edition

Building from OSS code means the Enterprise features are absent. Among them:

- custom workspace roles (only admin, developer and operator exist);
- audit logs (the gateway keeps its own `sync_event` trail);
- SCIM and SAML;
- the full-text job indexer;
- the multiplayer editor.

`CE_MAX_RETENTION_PERIOD_SECS` still caps job retention at 30 days. Cloud-only quotas don't
apply to a self-hosted instance. `PATCHES.md` lists what was deliberately left untouched.
