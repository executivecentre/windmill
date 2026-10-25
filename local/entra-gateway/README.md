# entra-gateway

Signs users in to Windmill with Microsoft Entra ID, and keeps their Windmill accounts,
workspace memberships and groups in line with their Entra group membership.

It is a **login broker**, not an authenticating proxy. Windmill keeps authenticating every API
call with its own session cookie. The gateway's only job is to decide whether a person may
have a session, and then hand them one through a single-use Windmill login link. Caddy routes
`/sso/*` to the gateway and sends `/user/login` there too. Every other path goes to Windmill
unchanged.

```
browser ──/user/login──▶ Caddy ──302──▶ /sso/login ──▶ Entra (auth code + PKCE)
                                                         │
browser ◀──302 to rd── /sso/callback ◀──────────────────┘
          (Windmill session)  │ 1. verify ID token (iss, aud, tid, nonce, signature)
                              │ 2. Graph: user + transitive groups (app-only)
                              │ 3. create/link the Windmill account, sync memberships
                              │ 4. mint a single-use Windmill login link, follow it
```

## Behaviour

- **Identity:** keyed by Entra `tid` + `oid`, never by email. The Windmill account's email is
  taken from the Graph `mail` attribute, or `userPrincipalName` when `mail` is empty. If that
  address changes in Entra, the account stays linked to its first address.
- **Access:** a user needs at least one mapped group (see `group-mappings.example.yaml`), an
  enabled Entra account and an email domain in `ALLOWED_EMAIL_DOMAINS`. Anyone else is denied
  with a reason page and no Windmill session. If Graph is unreachable, sign-in is denied; there
  is no cached decision to fall back on.
- **Roles:** only `admin`, `developer` and `operator` within a workspace. Entra users are never
  instance superadmins or devops, and the gateway refuses to sign anyone in to an account
  that is either.
- **Existing accounts:** an existing Windmill account with the same email is refused
  (`existing_account`) unless `ADOPT_EXISTING_ACCOUNTS=true`. Adoption switches the account's
  login type to `entra`, which ends its password sign-in. Accounts disabled by an
  administrator are never adopted, and an email already linked to a different Entra object is
  never handed over.
- **Deprovisioning:** when a user loses every mapping, or is disabled or deleted in Entra, the
  gateway disables their memberships, or their whole account, at their next sign-in attempt
  or the next reconcile run (`RECONCILE_INTERVAL`, default 15m). It re-enables only what it
  disabled itself. If a reconcile run hits a Graph error, that run changes nothing.
- **Managed state only:** the gateway changes memberships and group members it created, and
  leaves anything an administrator added by hand alone.
- **Logout:** `/sso/logout` ends the Windmill session server-side, clears the cookie and
  redirects to Entra's end-session endpoint.
- **Graph lag:** group memberships are read through Graph's advanced-query index
  (`ConsistencyLevel: eventual`), which can trail recent changes. A user just added to a group
  may be denied until the index catches up.

Every change is recorded in the gateway database's `sync_event` table, because Windmill OSS
audit logging records nothing. The table never holds tokens or secrets:

```sh
docker compose … exec db psql -U postgres -d entra_gateway \
  -c "select at, object_id, action, detail from sync_event order by id desc limit 50"
```

## Entra app registration

1. **Entra admin center → App registrations → New registration.** Supported account types:
   *Accounts in this organizational directory only* (single tenant).
2. **Authentication → Add a platform → Web.** Add both redirect URIs:
   - `${PUBLIC_BASE_URL}/sso/callback`
   - `${PUBLIC_BASE_URL}/sso/logged-out` (Entra only redirects there after sign-out if it is
     registered)

   Leave *Implicit grant* (ID tokens / access tokens) **unticked**: the gateway uses the
   authorization-code flow with PKCE. Leave *Front-channel logout URL* empty.
3. **Certificates & secrets → New client secret.** Put the value in
   `local/secrets/entra_client_secret`, and note the expiry date: sign-in stops when the
   secret expires.
4. **API permissions → Add → Microsoft Graph → Application permissions → `User.Read.All`**,
   then **Grant admin consent**. This is the only permission needed. Graph returns each group
   in a user's transitive memberships with its `id`, which is all the gateway reads. Groups
   with hidden membership need `Member.Read.Hidden` as well. No `groups` claim and no
   delegated permission beyond the default `openid profile` are needed.
5. Optional: **Enterprise applications → the app → Properties → Assignment required = Yes**.
   With this set, Entra itself blocks unassigned users before they reach the gateway.
6. Copy the **Directory (tenant) ID** to `ENTRA_TENANT_ID` and the **Application (client) ID**
   to `ENTRA_CLIENT_ID`.
7. For each group you want to map, copy its **Object ID** (Groups → the group → Overview)
   into `local/group-mappings.yaml`.

## Configuration

All values are read at start-up and validated together. The gateway refuses to start and lists
every problem.

| Variable | Required | Meaning |
| --- | --- | --- |
| `PUBLIC_BASE_URL` | yes | Public `https://` origin of Windmill, no path or trailing slash |
| `ENTRA_TENANT_ID` | yes | Directory (tenant) ID, a GUID |
| `ENTRA_CLIENT_ID` | yes | Application (client) ID |
| `ENTRA_CLIENT_SECRET_FILE` | yes¹ | File holding the client secret |
| `WINDMILL_INTERNAL_URL` | yes | Windmill server on the internal network, e.g. `http://windmill_server:8000` |
| `WINDMILL_SUPERADMIN_SECRET_FILE` | yes¹ | File holding Windmill's `SUPERADMIN_SECRET` |
| `GATEWAY_DATABASE_URL_FILE` | yes¹ | File holding the URL of the gateway's own database |
| `COOKIE_KEY_FILE` | yes¹ | File holding 32 random bytes, hex-encoded (64 characters) |
| `GROUP_MAPPINGS_PATH` | yes | Group mapping YAML |
| `ALLOWED_EMAIL_DOMAINS` | yes | Comma-separated domains; subdomains match too |
| `ADOPT_EXISTING_ACCOUNTS` | no | `true` to link pre-existing Windmill accounts (default `false`) |
| `RECONCILE_INTERVAL` | no | Go duration, at least `1m` (default `15m`) |
| `LOGIN_LINK_TTL_SECONDS` | no | Lifetime of the login link, at most 900 (default 60) |
| `ENTRA_AUTHORITY_URL` | no | For national clouds (default `https://login.microsoftonline.com`) |
| `GRAPH_BASE_URL` | no | For national clouds (default `https://graph.microsoft.com`) |
| `LISTEN_ADDR` | no | Default `:8080` |

¹ Each `*_FILE` variable can be replaced by the variable without `_FILE` holding the value
directly. Setting both is an error. Prefer the files: compose mounts them as secrets.

The gateway logs JSON to stdout. It never logs client secrets, authorization codes, ID or
access tokens, Windmill tokens, the superadmin secret or login-link URLs.

## Build and test

```sh
local/scripts/build.sh                      # builds windmill-entra:local with the other images
docker build -t windmill-entra:local local/entra-gateway   # gateway only
```

The tests run against a real Postgres database, with an in-process mock OIDC provider, a Graph
mock and a Windmill fake. The tests in `gatewaytest` skip when `GATEWAY_TEST_DATABASE_URL` is
unset.

```sh
docker run --rm -v "$PWD/local/entra-gateway":/src -w /src \
  -e GATEWAY_TEST_DATABASE_URL='postgres://…/gateway_test?sslmode=disable' \
  golang:1.27.1-trixie go test -race ./...
```

The test database is truncated between tests, so never point it at a live gateway database.
