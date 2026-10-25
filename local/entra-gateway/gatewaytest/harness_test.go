package gatewaytest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"entra-gateway/internal/config"
	"entra-gateway/internal/graph"
	"entra-gateway/internal/httpserver"
	"entra-gateway/internal/oidc"
	"entra-gateway/internal/store"
	"entra-gateway/internal/sync"
	"entra-gateway/internal/windmill"
	"entra-gateway/migrations"
)

// Entra group object IDs used by the mapping below.
const (
	grpEng      = "0a000000-0000-4000-8000-000000000001" // eng: developer, groups engineering
	grpEngAdmin = "0a000000-0000-4000-8000-000000000002" // eng: admin
	grpOps      = "0a000000-0000-4000-8000-000000000003" // ops: operator, groups oncall
	grpResearch = "0a000000-0000-4000-8000-000000000004" // research: developer (reached only via nesting)
	grpGhost    = "0a000000-0000-4000-8000-000000000005" // ghost: workspace that does not exist
	grpUnmapped = "0a000000-0000-4000-8000-0000000000ff"
)

const mappingYAML = `
group_mappings:
  ` + grpEng + `: {workspace: eng, role: developer, groups: [engineering]}
  ` + grpEngAdmin + `: {workspace: eng, role: admin}
  ` + grpOps + `: {workspace: ops, role: operator, groups: [oncall]}
  ` + grpResearch + `: {workspace: research, role: developer}
  ` + grpGhost + `: {workspace: ghost, role: developer}
`

const publicBase = "https://windmill.test"

type harness struct {
	t      *testing.T
	sec    *secrets
	idp    *idp
	graph  *graphMock
	wm     *windmillFake
	store  *store.Store
	engine *sync.Engine
	auth   *oidc.Client
	h      http.Handler
	logs   *logBuffer

	clockMu gosync.Mutex
	offset  time.Duration
}

type harnessOpts struct{ adopt bool }

func withAdoption(o *harnessOpts) { o.adopt = true }

func testDB(t *testing.T) string {
	dsn := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL is not set")
	}
	return dsn
}

func resetDB(t *testing.T, dsn string) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `DO $$ BEGIN
		IF to_regclass('identity') IS NOT NULL THEN
			TRUNCATE identity, managed_membership, managed_group_membership, sync_event RESTART IDENTITY;
		END IF; END $$`); err != nil {
		t.Fatal(err)
	}
}

func newHarness(t *testing.T, opts ...func(*harnessOpts)) *harness {
	var o harnessOpts
	for _, f := range opts {
		f(&o)
	}
	dsn := testDB(t)
	resetDB(t, dsn)
	ctx := context.Background()

	h := &harness{t: t, sec: &secrets{}, logs: &logBuffer{}}
	h.idp = newIDP(t, h.sec)
	h.idp.now = h.now
	h.graph = newGraph(t, h.idp)
	h.wm = newWindmill(t, h.sec, "eng", "ops", "research")
	log := slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx, migrations.FS); err != nil {
		t.Fatal(err)
	}
	h.store = st

	mappings, err := config.ParseMappings([]byte(mappingYAML))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AllowedDomains: []string{"corp.example"}}
	client := h.idp.srv.Client() // trusts every httptest TLS server
	h.auth = oidc.New(oidc.Settings{Issuer: h.idp.issuer(), TenantID: h.idp.tenant, ClientID: h.idp.clientID,
		ClientSecret: h.idp.clientSecret, RedirectURL: publicBase + "/sso/callback", HTTPClient: client, Now: h.now})
	if err := h.auth.Discover(ctx); err != nil {
		t.Fatal(err)
	}
	g, err := graph.New(graph.Settings{BaseURL: h.graph.srv.URL, TokenURL: h.idp.tokenURL(),
		ClientID: h.idp.clientID, ClientSecret: h.idp.clientSecret, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	wm := windmill.New(h.wm.srv.URL, h.wm.secret, nil)
	h.engine = sync.New(sync.Settings{Mappings: mappings, DomainAllowed: cfg.DomainAllowed, AdoptExisting: o.adopt},
		g, wm, st, log)
	pub, _ := url.Parse(publicBase)
	srv, err := httpserver.New(httpserver.Settings{PublicBaseURL: pub, CookieKey: []byte(strings.Repeat("k", 32)),
		LoginLinkTTL: 60, Now: h.now}, h.auth, h.engine, wm, st, log)
	if err != nil {
		t.Fatal(err)
	}
	h.h = srv.Handler()
	return h
}

func (h *harness) now() time.Time {
	h.clockMu.Lock()
	defer h.clockMu.Unlock()
	return time.Now().Add(h.offset)
}

func (h *harness) advance(d time.Duration) {
	h.clockMu.Lock()
	h.offset += d
	h.clockMu.Unlock()
}

func oid(n int) string { return fmt.Sprintf("b0000000-0000-4000-8000-%012d", n) }

// addEntraUser registers a directory user in Graph.
func (h *harness) addEntraUser(objectID, email string, groups ...string) {
	h.graph.setUser(graphUser{ID: objectID, AccountEnabled: true, UPN: email, Mail: email, DisplayName: "Test " + email}, groups...)
}

func (h *harness) get(target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// startLogin hits /sso/login and returns the flow cookie and the authorization URL.
func (h *harness) startLogin(rd string) (*http.Cookie, string) {
	h.t.Helper()
	target := publicBase + "/sso/login"
	if rd != "" {
		target += "?rd=" + url.QueryEscape(rd)
	}
	rec := h.get(target)
	if rec.Code != http.StatusFound {
		h.t.Fatalf("/sso/login: HTTP %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-wm_sso" {
			if !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
				h.t.Fatalf("flow cookie attributes %+v", c)
			}
			return c, rec.Header().Get("Location")
		}
	}
	h.t.Fatal("no flow cookie")
	return nil, ""
}

// login runs a whole sign-in for the directory user and returns the callback response.
func (h *harness) login(objectID, rd string) *httptest.ResponseRecorder {
	c, authURL := h.startLogin(rd)
	return h.get(h.idp.authorize(authURL, objectID), c)
}

// signedIn asserts a successful callback and returns the login link Windmill minted.
func (h *harness) signedIn(rec *httptest.ResponseRecorder) wmLink {
	h.t.Helper()
	loc := rec.Header().Get("Location")
	const prefix = "/api/auth/login_link/"
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, prefix) {
		h.t.Fatalf("expected redirect to a login link, got HTTP %d Location=%q body=%s", rec.Code, loc, rec.Body.String())
	}
	l, ok := h.wm.link(strings.TrimPrefix(loc, prefix))
	if !ok {
		h.t.Fatalf("redirected to a login link Windmill never issued")
	}
	return l
}

func (h *harness) denied(rec *httptest.ResponseRecorder, status int, text string) {
	h.t.Helper()
	if rec.Code != status || !strings.Contains(rec.Body.String(), text) {
		h.t.Fatalf("expected HTTP %d containing %q, got %d: %s", status, text, rec.Code, rec.Body.String())
	}
	if strings.HasPrefix(rec.Header().Get("Location"), "/api/auth/login_link/") {
		h.t.Fatal("denied response still redirects to a login link")
	}
}

func (h *harness) events(objectID string) []string {
	ev, err := h.store.Events(context.Background(), objectID)
	if err != nil {
		h.t.Fatal(err)
	}
	return ev
}

func (h *harness) identity(objectID string) *store.Identity {
	id, err := h.store.GetIdentity(context.Background(), h.idp.tenant, objectID)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func (h *harness) reconcile() sync.CycleResult {
	res, err := h.engine.ReconcileOnce(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}
