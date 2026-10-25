package gatewaytest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"entra-gateway/internal/oidc"
)

func TestLoginProvisionsAccountMembershipAndGroups(t *testing.T) {
	h := newHarness(t)
	h.addEntraUser(oid(1), "Alice@Corp.Example", grpEng)

	link := h.signedIn(h.login(oid(1), "/scripts/get/f/u/alice/x?tab=runs"))
	if link.email != "alice@corp.example" || link.rd != "/scripts/get/f/u/alice/x?tab=runs" {
		t.Fatalf("login link for %q rd %q", link.email, link.rd)
	}
	u := h.wm.user("alice@corp.example")
	if u == nil || u.LoginType != "entra" || u.SuperAdmin {
		t.Fatalf("windmill account %+v", u)
	}
	m := h.wm.member("eng", "alice@corp.example")
	if m == nil || m.IsAdmin || m.Operator || m.Role != "developer" || m.Disabled {
		t.Fatalf("eng membership %+v", m)
	}
	if got := h.wm.groupMembers("eng", "engineering"); !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("engineering members %v (the creating superadmin_secret must be removed)", got)
	}
	id := h.identity(oid(1))
	if id == nil || id.Email != "alice@corp.example" {
		t.Fatalf("identity %+v", id)
	}
	want := []string{"account_created", "membership_added:eng", "group_created:eng", "group_member_added:eng"}
	if got := h.events(oid(1)); !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	// A second sign-in is idempotent.
	h.signedIn(h.login(oid(1), ""))
	if h.wm.creates() != 1 || len(h.events(oid(1))) != len(want) {
		t.Fatalf("second login changed state: creates=%d events=%v", h.wm.creates(), h.events(oid(1)))
	}
}

func TestOpenRedirectVariantsFallBackToRoot(t *testing.T) {
	h := newHarness(t)
	h.addEntraUser(oid(1), "alice@corp.example", grpEng)
	for _, rd := range []string{"//evil.example", "/\\evil.example", "https://evil.example/x", "/\t/evil.example",
		"/x\ny", "javascript:alert(1)", "evil.example", "///evil.example", "/ /evil.example"} {
		if link := h.signedIn(h.login(oid(1), rd)); link.rd != "/" {
			t.Fatalf("rd %q was passed on as %q", rd, link.rd)
		}
	}
	if link := h.signedIn(h.login(oid(1), "/flows/edit/f/x?a=b")); link.rd != "/flows/edit/f/x?a=b" {
		t.Fatalf("same-origin rd became %q", link.rd)
	}
}

func TestCallbackStateAndCookieChecks(t *testing.T) {
	h := newHarness(t)
	h.addEntraUser(oid(1), "alice@corp.example", grpEng)

	withState := func(cb, state string, drop bool) string {
		u, _ := url.Parse(cb)
		q := u.Query()
		if drop {
			q.Del("state")
		} else {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		return u.String()
	}
	t.Run("wrong state", func(t *testing.T) {
		c, authURL := h.startLogin("")
		h.denied(h.get(withState(h.idp.authorize(authURL, oid(1)), "forged", false), c), http.StatusBadRequest, "expired")
	})
	t.Run("missing state", func(t *testing.T) {
		c, authURL := h.startLogin("")
		h.denied(h.get(withState(h.idp.authorize(authURL, oid(1)), "", true), c), http.StatusBadRequest, "expired")
	})
	t.Run("missing flow cookie", func(t *testing.T) {
		_, authURL := h.startLogin("")
		h.denied(h.get(h.idp.authorize(authURL, oid(1))), http.StatusBadRequest, "expired")
	})
	t.Run("cookie from another attempt", func(t *testing.T) {
		c1, _ := h.startLogin("")
		_, authURL2 := h.startLogin("")
		h.denied(h.get(h.idp.authorize(authURL2, oid(1)), c1), http.StatusBadRequest, "expired")
	})
	t.Run("tampered cookie", func(t *testing.T) {
		c, authURL := h.startLogin("")
		c.Value = c.Value[:len(c.Value)-2] + "AA"
		h.denied(h.get(h.idp.authorize(authURL, oid(1)), c), http.StatusBadRequest, "expired")
	})
	t.Run("replayed cookie and callback", func(t *testing.T) {
		c, authURL := h.startLogin("")
		cb := h.idp.authorize(authURL, oid(1))
		rec := h.get(cb, c)
		h.signedIn(rec)
		cleared := false
		for _, sc := range rec.Result().Cookies() {
			cleared = cleared || (sc.Name == "__Host-wm_sso" && sc.MaxAge < 0)
		}
		if !cleared {
			t.Fatal("callback did not clear the flow cookie")
		}
		h.denied(h.get(cb, c), http.StatusBadRequest, "expired")
	})
	t.Run("expired cookie", func(t *testing.T) {
		c, authURL := h.startLogin("")
		cb := h.idp.authorize(authURL, oid(1))
		h.advance(11 * time.Minute)
		defer h.advance(-11 * time.Minute)
		h.denied(h.get(cb, c), http.StatusBadRequest, "expired")
	})
	t.Run("entra error parameter", func(t *testing.T) {
		c, _ := h.startLogin("")
		rec := h.get(publicBase+"/sso/callback?error=access_denied&error_description=%3Cscript%3Ex%3C%2Fscript%3E", c)
		h.denied(rec, http.StatusForbidden, "did not complete")
		if strings.Contains(rec.Body.String(), "<script>") {
			t.Fatal("error_description reflected into the page")
		}
	})
	t.Run("non-GET refused", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, publicBase+"/sso/callback", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST /sso/callback: %d", rec.Code)
		}
	})
}

func TestTokenValidationFailuresDeny(t *testing.T) {
	cases := map[string]func(h *harness){
		"bad issuer": func(h *harness) {
			h.idp.setMutate(func(c map[string]any) { c["iss"] = "https://login.example/other/v2.0" })
		},
		"bad audience":  func(h *harness) { h.idp.setMutate(func(c map[string]any) { c["aud"] = "someone-else" }) },
		"bad signature": func(h *harness) { h.idp.setSignWithOther(true) },
		"expired": func(h *harness) {
			h.idp.setMutate(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
		},
		"issued in the future": func(h *harness) {
			h.idp.setMutate(func(c map[string]any) { c["iat"] = time.Now().Add(time.Hour).Unix() })
		},
		"wrong nonce": func(h *harness) { h.idp.setMutate(func(c map[string]any) { c["nonce"] = "replayed-nonce" }) },
		"wrong tid": func(h *harness) {
			h.idp.setMutate(func(c map[string]any) { c["tid"] = "99999999-2222-3333-4444-555555555555" })
		},
		"missing oid": func(h *harness) { h.idp.setMutate(func(c map[string]any) { delete(c, "oid") }) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.addEntraUser(oid(1), "alice@corp.example", grpEng)
			setup(h)
			h.denied(h.login(oid(1), ""), http.StatusUnauthorized, "could not be verified")
			if h.wm.creates() != 0 || h.identity(oid(1)) != nil {
				t.Fatal("an unverified token provisioned an account")
			}
		})
	}
}

func TestAccessPolicy(t *testing.T) {
	t.Run("nested group via transitiveMemberOf is authorized", func(t *testing.T) {
		h := newHarness(t)
		// The user is only in a child group; Graph's transitive query returns the parent.
		h.addEntraUser(oid(1), "nested@corp.example", grpResearch)
		h.signedIn(h.login(oid(1), ""))
		if h.wm.member("research", "nested@corp.example") == nil {
			t.Fatal("nested member not added to research")
		}
	})
	t.Run("no mapped group", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "nobody@corp.example", grpUnmapped)
		h.denied(h.login(oid(1), ""), http.StatusForbidden, "not in any group")
		if h.wm.creates() != 0 {
			t.Fatal("account created without any mapped group")
		}
	})
	t.Run("disallowed e-mail domain", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "guest@partner.example", grpEng)
		h.denied(h.login(oid(1), ""), http.StatusForbidden, "domain is not allowed")
	})
	t.Run("disabled directory account", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "alice@corp.example", grpEng)
		h.graph.setEnabled(oid(1), false)
		h.denied(h.login(oid(1), ""), http.StatusForbidden, "directory account is disabled")
	})
	t.Run("graph failure denies", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "alice@corp.example", grpEng)
		h.graph.setFail(true)
		h.denied(h.login(oid(1), ""), http.StatusServiceUnavailable, "temporarily unavailable")
		if h.wm.creates() != 0 {
			t.Fatal("account created while Graph was failing")
		}
	})
	t.Run("graph 429 then success", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "alice@corp.example", grpEng)
		h.graph.setThrottle(2)
		h.signedIn(h.login(oid(1), ""))
	})
	t.Run("graph pagination over three pages", func(t *testing.T) {
		h := newHarness(t)
		// The only mapped group is on the third page.
		h.addEntraUser(oid(1), "paged@corp.example", grpUnmapped, "0a000000-0000-4000-8000-0000000000f1",
			"0a000000-0000-4000-8000-0000000000f2", "0a000000-0000-4000-8000-0000000000f3", grpOps)
		h.graph.setPageSize(2)
		h.signedIn(h.login(oid(1), ""))
		if m := h.wm.member("ops", "paged@corp.example"); m == nil || !m.Operator {
			t.Fatalf("ops membership %+v", m)
		}
	})
	t.Run("missing workspace is skipped and recorded once", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "alice@corp.example", grpGhost, grpEng)
		h.signedIn(h.login(oid(1), ""))
		h.signedIn(h.login(oid(1), ""))
		if n := strings.Count(strings.Join(h.events(oid(1)), ","), "workspace_missing:ghost"); n != 1 {
			t.Fatalf("workspace_missing recorded %d times", n)
		}
	})
}

func TestExistingAccounts(t *testing.T) {
	t.Run("adoption off denies", func(t *testing.T) {
		h := newHarness(t)
		h.wm.addUser(wmUser{Email: "bob@corp.example", LoginType: "password"})
		h.addEntraUser(oid(2), "bob@corp.example", grpEng)
		h.denied(h.login(oid(2), ""), http.StatusForbidden, "already exists")
		if u := h.wm.user("bob@corp.example"); u.LoginType != "password" || h.identity(oid(2)) != nil {
			t.Fatalf("unlinked account changed: %+v", u)
		}
	})
	t.Run("adoption on links and switches to entra", func(t *testing.T) {
		h := newHarness(t, withAdoption)
		h.wm.addUser(wmUser{Email: "bob@corp.example", LoginType: "password"})
		h.addEntraUser(oid(2), "bob@corp.example", grpEng)
		h.signedIn(h.login(oid(2), ""))
		if u := h.wm.user("bob@corp.example"); u.LoginType != "entra" {
			t.Fatalf("adopted account login type %q", u.LoginType)
		}
		if h.wm.creates() != 0 {
			t.Fatal("adoption created a second account")
		}
	})
	t.Run("superadmin target is never adopted", func(t *testing.T) {
		h := newHarness(t, withAdoption)
		h.wm.addUser(wmUser{Email: "admin@corp.example", LoginType: "password", SuperAdmin: true})
		h.addEntraUser(oid(3), "admin@corp.example", grpEngAdmin)
		h.denied(h.login(oid(3), ""), http.StatusForbidden, "instance-level privileges")
		if u := h.wm.user("admin@corp.example"); u.LoginType != "password" {
			t.Fatal("superadmin account was modified")
		}
	})
	t.Run("another object claiming a linked address is refused", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "alice@corp.example", grpEng)
		h.signedIn(h.login(oid(1), ""))
		// A different object now carries alice's address (e.g. a recycled mailbox).
		h.addEntraUser(oid(9), "alice@corp.example", grpEngAdmin)
		h.denied(h.login(oid(9), ""), http.StatusForbidden, "different directory account")
	})
	t.Run("linked account keeps its address when mail changes", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(1), "alice@corp.example", grpEng)
		h.signedIn(h.login(oid(1), ""))
		h.addEntraUser(oid(1), "alice.new@corp.example", grpEng)
		if link := h.signedIn(h.login(oid(1), "")); link.email != "alice@corp.example" {
			t.Fatalf("signed in as %q", link.email)
		}
	})
	t.Run("unmanaged membership is left alone", func(t *testing.T) {
		h := newHarness(t, withAdoption)
		h.wm.addUser(wmUser{Email: "carol@corp.example", LoginType: "entra"})
		h.wm.seedMember("eng", wmMember{Username: "carol", Email: "carol@corp.example", Operator: true, Role: "operator"})
		h.addEntraUser(oid(4), "carol@corp.example", grpEng)
		h.signedIn(h.login(oid(4), ""))
		if m := h.wm.member("eng", "carol@corp.example"); !m.Operator {
			t.Fatalf("unmanaged membership changed: %+v", m)
		}
		if !slices.Contains(h.events(oid(4)), "unmanaged_membership:eng") {
			t.Fatalf("events %v", h.events(oid(4)))
		}
	})
}

func TestConcurrentFirstLoginsCreateOneAccount(t *testing.T) {
	h := newHarness(t)
	h.addEntraUser(oid(5), "dave@corp.example", grpEng, grpOps)
	id := oidc.Identity{TenantID: h.idp.tenant, ObjectID: oid(5)}
	var wg gosync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			email, err := h.engine.Login(context.Background(), id)
			if err == nil && email != "dave@corp.example" {
				t.Errorf("email %q", email)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if h.wm.creates() != 1 {
		t.Fatalf("CreateUser called %d times", h.wm.creates())
	}
	if got := h.wm.groupMembers("ops", "oncall"); !slices.Equal(got, []string{"dave"}) {
		t.Fatalf("oncall members %v", got)
	}
}

func TestRoleChangesAndRemoval(t *testing.T) {
	h := newHarness(t)
	h.addEntraUser(oid(6), "erin@corp.example", grpEng, grpOps)
	h.signedIn(h.login(oid(6), ""))

	// Promotion to admin through a second group: highest role wins.
	h.graph.setGroups(oid(6), grpEng, grpEngAdmin, grpOps)
	h.signedIn(h.login(oid(6), ""))
	if m := h.wm.member("eng", "erin@corp.example"); !m.IsAdmin {
		t.Fatalf("not promoted: %+v", m)
	}

	// Removal from ops: membership disabled and managed group membership removed at the next
	// reconcile, without waiting for a sign-in. Demoted in eng at the same time.
	h.graph.setGroups(oid(6), grpEng)
	if res := h.reconcile(); res.Failed != 0 {
		t.Fatalf("reconcile %+v", res)
	}
	if m := h.wm.member("ops", "erin@corp.example"); m == nil || !m.Disabled {
		t.Fatalf("ops membership %+v", m)
	}
	if got := h.wm.groupMembers("ops", "oncall"); len(got) != 0 {
		t.Fatalf("oncall members %v", got)
	}
	if m := h.wm.member("eng", "erin@corp.example"); m.IsAdmin || m.Disabled {
		t.Fatalf("eng membership %+v", m)
	}

	// Back in ops: the gateway re-enables what it disabled.
	h.graph.setGroups(oid(6), grpEng, grpOps)
	h.signedIn(h.login(oid(6), ""))
	if m := h.wm.member("ops", "erin@corp.example"); m.Disabled || !m.Operator {
		t.Fatalf("ops membership not restored: %+v", m)
	}

	// Removed from every mapped group: sign-in refused, all managed memberships disabled.
	h.graph.setGroups(oid(6), grpUnmapped)
	h.denied(h.login(oid(6), ""), http.StatusForbidden, "not in any group")
	if !h.wm.member("eng", "erin@corp.example").Disabled || !h.wm.member("ops", "erin@corp.example").Disabled {
		t.Fatal("memberships still enabled after losing every group")
	}
}

func TestDeprovisionAndReenable(t *testing.T) {
	t.Run("deleted in Entra", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(7), "frank@corp.example", grpEng)
		h.signedIn(h.login(oid(7), ""))
		h.graph.removeUser(oid(7))
		h.reconcile()
		if u := h.wm.user("frank@corp.example"); !u.Disabled {
			t.Fatal("account not disabled after Graph 404")
		}
		if id := h.identity(oid(7)); !id.DisabledByGateway {
			t.Fatal("disable not attributed to the gateway")
		}
		h.denied(h.login(oid(7), ""), http.StatusForbidden, "not found in the directory")
	})
	t.Run("disabled in Entra then re-enabled", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(7), "frank@corp.example", grpEng)
		h.signedIn(h.login(oid(7), ""))
		h.graph.setEnabled(oid(7), false)
		h.reconcile()
		if !h.wm.user("frank@corp.example").Disabled {
			t.Fatal("account not disabled after accountEnabled=false")
		}
		h.graph.setEnabled(oid(7), true)
		h.signedIn(h.login(oid(7), ""))
		if h.wm.user("frank@corp.example").Disabled {
			t.Fatal("gateway did not re-enable an account it disabled")
		}
	})
	t.Run("administrator-disabled account stays disabled", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(8), "gina@corp.example", grpEng)
		h.signedIn(h.login(oid(8), ""))
		h.wm.setUserDisabled("gina@corp.example", true)
		h.denied(h.login(oid(8), ""), http.StatusForbidden, "disabled by an administrator")
		h.reconcile()
		if !h.wm.user("gina@corp.example").Disabled {
			t.Fatal("gateway re-enabled an account an administrator disabled")
		}
	})
	t.Run("graph outage during reconcile changes nothing", func(t *testing.T) {
		h := newHarness(t)
		h.addEntraUser(oid(8), "gina@corp.example", grpEng)
		h.signedIn(h.login(oid(8), ""))
		h.graph.setFail(true)
		if res := h.reconcile(); res.Failed != 1 {
			t.Fatalf("reconcile %+v", res)
		}
		if h.wm.user("gina@corp.example").Disabled || h.wm.member("eng", "gina@corp.example").Disabled {
			t.Fatal("transient Graph failure revoked access")
		}
	})
}

func TestLoginLinkOriginMismatchDenies(t *testing.T) {
	h := newHarness(t)
	h.addEntraUser(oid(1), "alice@corp.example", grpEng)
	h.wm.setLinkBase("https://evil.example")
	rec := h.login(oid(1), "")
	h.denied(rec, http.StatusBadGateway, "Something went wrong")
	if strings.Contains(rec.Header().Get("Location"), "evil") {
		t.Fatal("redirected to a foreign origin")
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	rec := h.get(publicBase+"/sso/logout", &http.Cookie{Name: "token", Value: "session-abc"})
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), h.idp.srv.URL) {
		t.Fatalf("logout: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if got := h.wm.logouts(); len(got) != 1 || got[0] != "session-abc" {
		t.Fatalf("windmill session not ended: %v", got)
	}
}

func TestReadinessAndHeaders(t *testing.T) {
	h := newHarness(t)
	if rec := h.get(publicBase + "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("readyz %d", rec.Code)
	}
	rec := h.get(publicBase + "/sso/login")
	for k, v := range map[string]string{"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if rec.Header().Get(k) != v {
			t.Fatalf("%s = %q", k, rec.Header().Get(k))
		}
	}
}

// TestSecretsNeverLogged runs successful and failing flows, then checks that no credential
// the mocks issued (client secret, superadmin secret, codes, tokens, login links) was logged.
func TestSecretsNeverLogged(t *testing.T) {
	h := newHarness(t)
	h.addEntraUser(oid(1), "alice@corp.example", grpEng, grpOps)
	h.signedIn(h.login(oid(1), "/"))
	h.idp.setSignWithOther(true)
	h.login(oid(1), "")
	h.idp.setSignWithOther(false)
	h.graph.setFail(true)
	h.login(oid(1), "")
	h.reconcile()
	h.graph.setFail(false)
	h.wm.setLinkBase("https://evil.example")
	h.login(oid(1), "")

	logs := h.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged")
	}
	for _, s := range h.sec.all() {
		if strings.Contains(logs, s) {
			t.Fatal("a credential issued by the mocks appears in the logs")
		}
	}
	for _, s := range []string{"login_link/", "id_token", "code="} {
		if strings.Contains(logs, s) {
			t.Fatalf("logs contain %q", s)
		}
	}
}
