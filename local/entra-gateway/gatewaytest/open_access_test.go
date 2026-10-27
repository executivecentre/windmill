package gatewaytest

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"entra-gateway/internal/windmill"
)

// Without group mappings any user of the tenant signs in, gets an `entra` account and no
// workspace, and the gateway never uses an app-only Graph token.
func TestOpenAccessSignsInAnyTenantUser(t *testing.T) {
	h := newHarness(t, withOpenAccess)
	h.addEntraUser(oid(1), "Pat@Any.Example") // in no group

	_, authURL := h.startLogin("")
	u, _ := url.Parse(authURL)
	if scopes := strings.Fields(u.Query().Get("scope")); !slices.Contains(scopes, "User.Read") {
		t.Fatalf("authorize scopes %v lack User.Read", scopes)
	}
	link := h.signedIn(h.login(oid(1), "/scripts"))
	if link.email != "pat@any.example" || link.rd != "/scripts" {
		t.Fatalf("login link for %q rd %q", link.email, link.rd)
	}
	acct := h.wm.user("pat@any.example")
	if acct == nil || acct.LoginType != "entra" || acct.SuperAdmin {
		t.Fatalf("windmill account %+v", acct)
	}
	for _, ws := range []string{"eng", "ops", "research"} {
		if m := h.wm.member(ws, "pat@any.example"); m != nil {
			t.Fatalf("open access added a %s membership %+v", ws, m)
		}
	}
	if got := h.events(oid(1)); !slices.Equal(got, []string{"account_created"}) {
		t.Fatalf("events %v", got)
	}
	h.signedIn(h.login(oid(1), ""))
	if h.wm.creates() != 1 {
		t.Fatalf("second sign-in created another account: %d", h.wm.creates())
	}
	if h.idp.currentGraphToken() != "" {
		t.Fatal("open access requested an app-only (client-credentials) Graph token")
	}
}

func TestOpenAccessRefusals(t *testing.T) {
	t.Run("no directory entry for the token's user", func(t *testing.T) {
		h := newHarness(t, withOpenAccess)
		h.denied(h.login(oid(1), ""), http.StatusServiceUnavailable, "temporarily unavailable")
		if h.wm.creates() != 0 {
			t.Fatal("account created without a directory entry")
		}
	})
	t.Run("token from another tenant", func(t *testing.T) {
		h := newHarness(t, withOpenAccess)
		h.addEntraUser(oid(1), "pat@any.example")
		h.idp.setMutate(func(c map[string]any) { c["tid"] = "99999999-2222-3333-4444-555555555555" })
		h.denied(h.login(oid(1), ""), http.StatusUnauthorized, "could not be verified")
		if h.wm.creates() != 0 {
			t.Fatal("a foreign tenant's token provisioned an account")
		}
	})
	t.Run("account disabled by a Windmill admin", func(t *testing.T) {
		h := newHarness(t, withOpenAccess)
		h.addEntraUser(oid(1), "pat@any.example")
		h.signedIn(h.login(oid(1), ""))
		h.wm.setUserDisabled("pat@any.example", true)
		h.denied(h.login(oid(1), ""), http.StatusForbidden, "disabled by an administrator")
	})
	t.Run("superadmin account is never signed in", func(t *testing.T) {
		h := newHarness(t, withOpenAccess)
		h.addEntraUser(oid(1), "admin@any.example")
		h.wm.addUser(wmUser{Email: "admin@any.example", LoginType: "password", SuperAdmin: true, Username: "admin"})
		h.denied(h.login(oid(1), ""), http.StatusForbidden, "instance-level privileges")
	})
}

func TestMicrosoftAppFromWindmillSettings(t *testing.T) {
	h := newHarness(t)
	wm := windmill.New(h.wm.srv.URL, h.wm.secret, nil)
	ctx := context.Background()
	teams := map[string]any{"id": "c-teams", "secret": "s-teams", "tenant": "t-teams"}

	if app, err := wm.MicrosoftApp(ctx); err != nil || app != nil {
		t.Fatalf("no oauths: %+v %v", app, err)
	}
	h.wm.setOAuths(map[string]any{"github": map[string]any{"id": "x"}, "ms_teams": teams})
	if app, err := wm.MicrosoftApp(ctx); err != nil || app == nil || app.Key != "ms_teams" ||
		app.ClientID != "c-teams" || app.Secret != "s-teams" || app.TenantID != "t-teams" {
		t.Fatalf("ms_teams: %+v %v", app, err)
	}
	h.wm.setOAuths(map[string]any{"ms_teams": teams,
		"microsoft": map[string]any{"id": "c-ms", "secret": "s-ms", "tenant": "t-ms"}})
	if app, err := wm.MicrosoftApp(ctx); err != nil || app == nil || app.Key != "microsoft" || app.ClientID != "c-ms" {
		t.Fatalf("microsoft first: %+v %v", app, err)
	}
	h.wm.setOAuths(map[string]any{"microsoft": "secret-in-a-string"})
	if _, err := wm.MicrosoftApp(ctx); err == nil || strings.Contains(err.Error(), "secret-in-a-string") {
		t.Fatalf("malformed entry: %v", err)
	}
}
