"""TEST ONLY: SSO end-to-end checks through Caddy against mock-entra (run by local/test/e2e.sh).

The driver plays the browser: it keeps cookies per origin, follows redirects hop by hop, and
reaches mock-entra's published port for the host name the gateway redirects to. It never
prints a token, code, login link or secret; tokens it sees are written to <run>/tokens.txt so
e2e.sh can check that none of them reached a container log.
"""
import argparse
import http.client
import json
import os
import secrets
import shlex
import ssl
import subprocess
import sys
import time
import urllib.parse

ap = argparse.ArgumentParser()
ap.add_argument("--base", required=True)
ap.add_argument("--env", required=True)
ap.add_argument("--run", required=True)
ap.add_argument("--compose", required=True)
args = ap.parse_args()

ENV = dict(l.split("=", 1) for l in open(args.env).read().splitlines() if "=" in l and not l.startswith("#"))
BASE = args.base
ORIGIN = urllib.parse.urlsplit(BASE).netloc
MOCK = "mock-entra:8443"
CONNECT = {MOCK: ("127.0.0.1", int(ENV["MOCK_ENTRA_BIND_PORT"]))}
SUPER = open(f"{args.run}/secrets/windmill_superadmin_secret").read().strip()
CTX = ssl.create_default_context(cafile=f"{args.run}/caddy-root.crt")
CTX.load_verify_locations(f"{args.run}/tls/ca.crt")
TENANT = ENV["ENTRA_TENANT_ID"]
G = {k: f"0e2e0000-0000-4000-8000-0000000000{k}" for k in ("a1", "a2", "a3", "f1", "f2")}
seen_tokens = set()
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + (f"  [{detail}]" if detail else ""), flush=True)
    return ok


def request(method, url, body=None, headers=None, cookies=None):
    u = urllib.parse.urlsplit(url)
    host, port = CONNECT.get(u.netloc, (u.hostname, u.port or 443))
    conn = http.client.HTTPSConnection(host, port, context=CTX, timeout=120)
    h = {"Host": u.netloc, **(headers or {})}
    if cookies:
        h["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    conn.request(method, u.path + (f"?{u.query}" if u.query else ""), data, h)
    r = conn.getresponse()
    out = r.status, r.getheader("Location"), r.headers.get_all("Set-Cookie") or [], r.read().decode(errors="replace")
    conn.close()
    return out


def parse(text):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return text


class Browser:
    def __init__(self):
        self.jar = {}  # origin -> {name: value}
        self.hops = []

    def _store(self, origin, set_cookies):
        jar = self.jar.setdefault(origin, {})
        for sc in set_cookies:
            name, _, rest = sc.partition("=")
            value = rest.split(";", 1)[0]
            attrs = sc.lower()
            if value == "" or "max-age=0" in attrs or "expires=thu, 01 jan 1970" in attrs:
                jar.pop(name, None)
            else:
                jar[name] = value
                if name == "token":
                    seen_tokens.add(value)

    def get(self, url, max_hops=12):
        """Follows redirects; returns (status, final_url, body). Hops are kept in self.hops."""
        self.hops = []
        for _ in range(max_hops):
            origin = urllib.parse.urlsplit(url).netloc
            st, loc, sc, text = request("GET", url, cookies=self.jar.get(origin))
            self._store(origin, sc)
            self.hops.append((st, url))
            if st not in (301, 302, 303, 307, 308) or not loc:
                return st, url, text
            url = urllib.parse.urljoin(url, loc)
        raise RuntimeError("too many redirects")

    def api(self, method, path, body=None):
        st, _, _, text = request(method, BASE + path, body, cookies=self.jar.get(ORIGIN))
        return st, parse(text)

    @property
    def session(self):
        return self.jar.get(ORIGIN, {}).get("token")


def sup(method, path, body=None):
    st, _, _, text = request(method, BASE + path, body, {"Authorization": "Bearer " + SUPER})
    return st, parse(text)


def internal(method, path, body):
    """Calls windmill_server:8000 from inside the network, for routes Caddy refuses."""
    inner = ("curl -s -o /dev/null -w '%{http_code}' -X " + method + " -H 'Content-Type: application/json' "
             "-H \"Authorization: Bearer $(cat /run/secrets/windmill_superadmin_secret)\" "
             "--data-binary @- http://localhost:8000" + path)
    cmd = (f"docker compose --env-file {shlex.quote(args.env)} {args.compose} "
           f"exec -T windmill_server sh -c {shlex.quote(inner)}")
    p = subprocess.run(cmd, shell=True, input=json.dumps(body), capture_output=True, text=True)
    return int(p.stdout or 0)


def mock(method, path, body=None):
    return request(method, f"https://{MOCK}{path}", body)[0]


def mock_user(oid, local, enabled=True, groups=(), domain="e2e.example.org"):
    email = f"{local}@{domain}"
    return mock("PUT", f"/_mock/users/{oid}",
                {"upn": email, "mail": email, "display_name": local.title(), "enabled": enabled, "groups": list(groups)})


def sign_in(oid, rd="/"):
    mock("POST", f"/_mock/next/{oid}")
    b = Browser()
    st, final, text = b.get(f"{BASE}/sso/login?rd={urllib.parse.quote(rd, safe='')}")
    return b, st, final, text


def oid(n):
    return f"0e2e0000-0000-4000-8000-00000000{n:04x}"


def wait_until(fn, seconds=180, step=5):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(step)
    return bool(fn())


def global_user(email):
    st, users = sup("GET", "/api/users/list_as_super_admin?per_page=1000")
    return next((u for u in users if u["email"] == email), {}) if st == 200 else {}


def timed(name, fn):
    t0 = time.time()
    return check(name, wait_until(fn), f"{time.time() - t0:.0f}s")


ALICE, BOB, CAROL, DAVE, ERIN = oid(1), oid(2), oid(3), oid(4), oid(5)

# ---------------------------------------------------------------- setup ----
for ws in ("e2e-alpha", "e2e-beta", "e2e-gamma"):
    st, _ = sup("POST", "/api/workspaces/create", {"id": ws, "name": ws})
    check(f"superadmin creates workspace {ws}", st in (200, 201), f"HTTP {st}")
# Alice's four groups come back over two Graph pages, so the gateway must follow nextLink.
mock_user(ALICE, "alice", groups=[G["a1"], G["f1"], G["a3"], G["f2"]])
mock_user(BOB, "bob", groups=[G["f1"]])
mock_user(CAROL, "carol", enabled=False, groups=[G["a1"]])
mock_user(DAVE, "dave", groups=[G["a1"]], domain="evil.example.org")
mock_user(ERIN, "erin", groups=[G["a1"]])
st = internal("POST", "/api/users/create",
              {"email": "erin@e2e.example.org", "password": secrets.token_urlsafe(18), "super_admin": False})
check("pre-existing password account erin created inside the network", st in (200, 201), f"HTTP {st}")

# ---------------------------------------------------------------- sign-in ----
b, st, final, text = sign_in(ALICE, rd="/scripts/add?x=1")
paths = [urllib.parse.urlsplit(u).path for _, u in b.hops]
expected = ["/sso/login", f"/{TENANT}/oauth2/v2.0/authorize", "/sso/callback"]
check("alice: /sso/login -> Entra -> /sso/callback -> login link -> rd",
      paths[:3] == expected and len(paths) == 5 and paths[3].startswith("/api/auth/login_link/")
      and final == f"{BASE}/scripts/add?x=1" and st == 200,
      " -> ".join("/api/auth/login_link/…" if p.startswith("/api/auth/login_link/") else p for p in paths))
callback_url = next((u for _, u in b.hops if urllib.parse.urlsplit(u).path == "/sso/callback"), None)
link_url = next((u for _, u in b.hops if "/api/auth/login_link/" in u), None)
check("alice: Windmill session cookie set", b.session is not None)
check("alice: sign-in state cookie cleared after the callback", "__Host-wm_sso" not in b.jar.get(ORIGIN, {}))

st, me = b.api("GET", "/api/users/whoami")
check("alice: an entra account, not a superadmin",
      st == 200 and me["email"] == "alice@e2e.example.org" and me["login_type"] == "entra" and not me["super_admin"],
      f"HTTP {st} login_type={me.get('login_type') if isinstance(me, dict) else me}")
st, wss = b.api("GET", "/api/workspaces/list")
ids = sorted(w["id"] for w in wss) if st == 200 else wss
check("alice: workspaces are exactly the mapped ones", ids == ["e2e-alpha", "e2e-beta"], str(ids))
st, wa = b.api("GET", "/api/w/e2e-alpha/users/whoami")
alice_user = wa.get("username") if st == 200 else None
check("alice: developer in e2e-alpha", st == 200 and not wa["is_admin"] and not wa["operator"],
      f"is_admin={wa.get('is_admin')} operator={wa.get('operator')} role={wa.get('role')}" if st == 200 else f"HTTP {st}")
st, wb = b.api("GET", "/api/w/e2e-beta/users/whoami")
check("alice: operator in e2e-beta", st == 200 and wb["operator"] and not wb["is_admin"],
      f"operator={wb.get('operator')} role={wb.get('role')}" if st == 200 else f"HTTP {st}")
st, grp = sup("GET", "/api/w/e2e-alpha/groups/get/backend")
check("alice: member of group backend in e2e-alpha", st == 200 and alice_user in grp.get("members", []), f"HTTP {st}")
st, grp = sup("GET", "/api/w/e2e-beta/groups/get/oncall")
check("alice: member of group oncall in e2e-beta", st == 200 and alice_user in grp.get("members", []), f"HTTP {st}")

# ------------------------------------------------- the session is a normal one ----
st, res = b.api("POST", "/api/w/e2e-alpha/jobs/run_wait_result/preview",
                {"content": "echo -n \"sso $((6 * 7))\"", "language": "bash", "args": {}})
check("alice: runs a bash script in e2e-alpha on a worker", st == 200 and res == "sso 42", f"HTTP {st} {res!r}")
st, res = b.api("POST", "/api/w/e2e-beta/jobs/run_wait_result/preview",
                {"content": "echo -n x", "language": "bash", "args": {}})
check("alice: as operator, cannot run an ad-hoc script in e2e-beta", st >= 400, f"HTTP {st}")
for path in ("/api/w/e2e-gamma/users/whoami", "/api/w/e2e-gamma/scripts/list", "/api/w/admins/scripts/list"):
    st, _ = b.api("GET", path)
    check(f"alice: refused {path}", st in (401, 403, 404), f"HTTP {st}")

script = {"path": f"u/{alice_user}/e2e_echo", "summary": "e2e", "description": "", "language": "python3",
          "content": "def main(msg: str):\n    return msg[::-1]\n"}
st, _ = b.api("POST", "/api/w/e2e-alpha/scripts/create", script)
check("alice: deploys a python script", st in (200, 201), f"HTTP {st}")
st, api_token = b.api("POST", "/api/users/tokens/create", {"label": "e2e-webhook"})
check("alice: creates an API token from the SSO session", st in (200, 201) and isinstance(api_token, str), f"HTTP {st}")
if isinstance(api_token, str):
    seen_tokens.add(api_token)
    res = None
    for _ in range(60):
        st, _, _, text = request("POST", f"{BASE}/api/w/e2e-alpha/jobs/run_wait_result/p/u/{alice_user}/e2e_echo",
                                 {"msg": "kooh"}, {"Authorization": "Bearer " + api_token})
        if st != 404:
            res = parse(text)
            break
        time.sleep(1)
    check("webhook with alice's API token runs her script", st == 200 and res == "hook", f"HTTP {st} {res!r}")
    os.makedirs(f"{args.run}/cli-home", exist_ok=True)
    cli = subprocess.run(["npx", "--yes", "windmill-cli@1.849.0", "script", "list",
                          "--base-url", BASE + "/", "--workspace", "e2e-alpha", "--token", api_token],
                         capture_output=True, text=True, timeout=600,
                         env={"PATH": os.environ["PATH"], "HOME": f"{args.run}/cli-home",
                              "NODE_EXTRA_CA_CERTS": f"{args.run}/caddy-root.crt", "NO_COLOR": "1"})
    last = (cli.stderr or cli.stdout).strip().splitlines()
    check("wmill CLI 1.849.0 lists alice's script with her API token", cli.returncode == 0 and "e2e_echo" in cli.stdout,
          f"exit {cli.returncode} {last[-1][:150] if last else ''}")

if link_url:
    st, final, _ = Browser().get(link_url)
    check("a used login link cannot be replayed", "/user/login_link_expired" in final, urllib.parse.urlsplit(final).path)
if callback_url:
    replay = Browser()
    st, final, _ = replay.get(callback_url)
    check("a replayed /sso/callback is refused", 400 <= st < 500 and replay.session is None, f"HTTP {st}")

# --------------------------------------------------------------- WebSocket ----
st, _, _, text = request("GET", f"{BASE}/ws/health", cookies={"token": b.session})
check("LSP health through Caddy (windmill_extra)", st == 200 and "lsp" in text, f"HTTP {st}")
ws_headers = {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
              "Sec-WebSocket-Key": "ZTJlLXdlYnNvY2tldC1rZXk="}
st, _, _, _ = request("GET", f"{BASE}/ws/pyright", headers=ws_headers, cookies={"token": b.session})
check("LSP WebSocket upgrade with alice's session", st == 101, f"HTTP {st}")
st, _, _, _ = request("GET", f"{BASE}/ws/pyright", headers=ws_headers)
check("LSP WebSocket upgrade refused without a session", st == 401, f"HTTP {st}")
st, _, _, _ = request("GET", f"{BASE}/ws/pyright", headers=ws_headers, cookies={"token": "not-a-session"})
check("LSP WebSocket upgrade refused with an invalid token", st == 401, f"HTTP {st}")

# ----------------------------------------------------------------- denials ----
for who, o, reason in (("bob (no mapped group)", BOB, "not in any group"),
                       ("carol (disabled in Entra)", CAROL, "disabled"),
                       ("dave (domain not allowed)", DAVE, "domain"),
                       ("erin (pre-existing password account)", ERIN, "already exists"),
                       ("unknown user (Entra refuses)", oid(99), "")):
    x, st, final, text = sign_in(o)
    check(f"{who} is denied without a Windmill session",
          400 <= st < 500 and x.session is None and reason in text.lower(), f"HTTP {st}")
check("no account created for denied users",
      not any(global_user(e) for e in ("bob@e2e.example.org", "carol@e2e.example.org", "dave@evil.example.org")))
check("erin's password account untouched", global_user("erin@e2e.example.org").get("login_type") == "password")

# --------------------------------------------------- role change at sign-in ----
mock_user(ALICE, "alice", groups=[G["a1"], G["f1"], G["a3"], G["f2"], G["a2"]])
b2, st, final, _ = sign_in(ALICE)
st, wa = b2.api("GET", "/api/w/e2e-alpha/users/whoami")
check("alice: joins the admin group -> admin of e2e-alpha at next sign-in", st == 200 and wa["is_admin"],
      f"is_admin={wa.get('is_admin')}" if st == 200 else f"HTTP {st}")

# ----------------------------------------------------------------- logout ----
old = b2.session
st, final, _ = b2.get(f"{BASE}/sso/logout")
check("logout ends at /sso/logged-out via Entra end-session", final == f"{BASE}/sso/logged-out" and st == 200,
      urllib.parse.urlsplit(final).path)
st, _, _, _ = request("GET", BASE + "/api/users/whoami", cookies={"token": old})
check("the Windmill session is revoked server-side after logout", st == 401, f"HTTP {st}")

# ---------------------------------------------------------------- reconcile ----
mock_user(ALICE, "alice", groups=[G["a1"], G["f1"], G["f2"], G["a2"]])  # leaves the e2e-beta group
timed("reconcile disables alice's e2e-beta membership after she leaves the group",
      lambda: sup("GET", f"/api/w/e2e-beta/users/get/{alice_user}")[1].get("disabled"))
timed("alice's existing session loses e2e-beta", lambda: b.api("GET", "/api/w/e2e-beta/scripts/list")[0] in (401, 403, 404))
st, _ = b.api("GET", "/api/w/e2e-alpha/scripts/list")
check("alice's existing session keeps e2e-alpha", st == 200, f"HTTP {st}")

mock_user(ALICE, "alice", enabled=False, groups=[G["a1"], G["f1"], G["f2"], G["a2"]])
timed("reconcile disables alice's account after Entra disables her",
      lambda: global_user("alice@e2e.example.org").get("disabled"))
timed("alice's existing session stops working", lambda: b.api("GET", "/api/users/whoami")[0] == 401)
st, ma = sup("GET", f"/api/w/e2e-alpha/users/get/{alice_user}")
check("disabling the account also disables alice's e2e-alpha membership (stops her schedules)",
      st == 200 and ma.get("disabled") is True, f"HTTP {st} disabled={ma.get('disabled') if st == 200 else None}")
x, st, _, _ = sign_in(ALICE)
check("alice cannot sign in while disabled in Entra", 400 <= st < 500 and x.session is None, f"HTTP {st}")

mock_user(ALICE, "alice", groups=[G["a1"], G["a3"]])
b3, st, final, _ = sign_in(ALICE)
st, wb = b3.api("GET", "/api/w/e2e-beta/users/whoami")
check("re-enabled in Entra: alice signs in again and gets e2e-beta back", b3.session is not None and st == 200, f"HTTP {st}")
st, wa = b3.api("GET", "/api/w/e2e-alpha/users/whoami")
check("left the admin group: alice is no longer admin of e2e-alpha", st == 200 and not wa["is_admin"],
      f"is_admin={wa.get('is_admin')}" if st == 200 else f"HTTP {st}")

counts = parse(request("GET", f"https://{MOCK}/_mock/counts")[3])
check("mock-entra saw authorize, code exchange, client credentials and paged Graph calls",
      all(counts.get(k) for k in ("authorize", "authorization_code", "client_credentials", "graph_groups")), str(counts))

with open(f"{args.run}/tokens.txt", "w") as f:
    f.write("\n".join(sorted(t for t in seen_tokens if t)) + "\n")
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
