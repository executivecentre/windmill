// Package gatewaytest exercises the gateway end to end against in-process mocks of Entra ID
// (OIDC), Microsoft Graph and the Windmill API. Nothing here is compiled into the gateway.
package gatewaytest

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	gosync "sync"
	"testing"
	"time"
)

// secrets collects every credential the mocks issue, so tests can assert none reaches a log.
type secrets struct {
	mu   gosync.Mutex
	vals []string
}

func (s *secrets) add(v string) {
	s.mu.Lock()
	s.vals = append(s.vals, v)
	s.mu.Unlock()
}

func (s *secrets) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.vals...)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ---------------------------------------------------------------- OIDC + token endpoint ----

type codeGrant struct {
	oid, nonce, challenge, redirect string
}

type idp struct {
	t            *testing.T
	srv          *httptest.Server
	tenant       string
	clientID     string
	clientSecret string
	key          *rsa.PrivateKey
	otherKey     *rsa.PrivateKey
	kid          string
	sec          *secrets

	mu         gosync.Mutex
	codes      map[string]codeGrant
	graphToken string
	// mutate changes the ID-token claims; signWithOther signs with a key not in the JWKS.
	mutate        func(map[string]any)
	signWithOther bool
	now           func() time.Time
}

func newIDP(t *testing.T, sec *secrets) *idp {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &idp{t: t, tenant: "11111111-2222-3333-4444-555555555555", clientID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		clientSecret: "client-secret-" + randHex(16), key: key, otherKey: other, kid: "test-key-1",
		sec: sec, codes: map[string]codeGrant{}, now: time.Now}
	sec.add(p.clientSecret)
	mux := http.NewServeMux()
	base := "/" + p.tenant
	mux.HandleFunc("GET "+base+"/v2.0/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET "+base+"/discovery/v2.0/keys", p.jwks)
	mux.HandleFunc("POST "+base+"/oauth2/v2.0/token", p.token)
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) authority() string { return p.srv.URL }
func (p *idp) issuer() string    { return p.srv.URL + "/" + p.tenant + "/v2.0" }
func (p *idp) tokenURL() string  { return p.srv.URL + "/" + p.tenant + "/oauth2/v2.0/token" }

func (p *idp) discovery(w http.ResponseWriter, _ *http.Request) {
	base := p.srv.URL + "/" + p.tenant
	writeJSON(w, 200, map[string]any{
		"issuer":                                p.issuer(),
		"authorization_endpoint":                base + "/oauth2/v2.0/authorize",
		"token_endpoint":                        base + "/oauth2/v2.0/token",
		"jwks_uri":                              base + "/discovery/v2.0/keys",
		"end_session_endpoint":                  base + "/oauth2/v2.0/logout",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"pairwise"},
	})
}

func (p *idp) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, 200, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.kid,
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize plays the user signing in at Entra: it reads the authorization request the
// gateway redirected to and returns the callback URL Entra would redirect back to.
func (p *idp) authorize(authURL, oid string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		p.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != p.clientID || q.Get("response_type") != "code" ||
		q.Get("code_challenge_method") != "S256" || q.Get("response_mode") != "query" {
		p.t.Fatalf("unexpected authorization request %s", u.RawQuery)
	}
	code := "code-" + randHex(16)
	p.sec.add(code)
	p.mu.Lock()
	p.codes[code] = codeGrant{oid: oid, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	p.mu.Unlock()
	cb, _ := url.Parse(q.Get("redirect_uri"))
	cq := url.Values{"code": {code}, "state": {q.Get("state")}}
	cb.RawQuery = cq.Encode()
	return cb.String()
}

func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	if r.Form.Get("client_id") != p.clientID || r.Form.Get("client_secret") != p.clientSecret {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.Form.Get("grant_type") {
	case "client_credentials":
		p.mu.Lock()
		p.graphToken = "graph-at-" + randHex(16)
		tok := p.graphToken
		p.mu.Unlock()
		p.sec.add(tok)
		writeJSON(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 3600})
	case "authorization_code":
		p.mu.Lock()
		g, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || b64(sum[:]) != g.challenge || r.Form.Get("redirect_uri") != g.redirect {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		now := p.now()
		claims := map[string]any{
			"iss": p.issuer(), "aud": p.clientID, "sub": "pairwise-" + g.oid,
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"nonce": g.nonce, "tid": p.tenant, "oid": g.oid,
			"preferred_username": "attacker-controlled@example.org",
		}
		p.mu.Lock()
		mutate, other := p.mutate, p.signWithOther
		p.mu.Unlock()
		if mutate != nil {
			mutate(claims)
		}
		idt := p.sign(claims, other)
		at := "user-at-" + randHex(16)
		p.sec.add(idt)
		p.sec.add(at)
		writeJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
	default:
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (p *idp) setMutate(f func(map[string]any)) {
	p.mu.Lock()
	p.mutate = f
	p.mu.Unlock()
}

func (p *idp) setSignWithOther(v bool) {
	p.mu.Lock()
	p.signWithOther = v
	p.mu.Unlock()
}

func (p *idp) sign(claims map[string]any, withOther bool) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": p.kid, "typ": "JWT"})
	body, _ := json.Marshal(claims)
	input := b64(hdr) + "." + b64(body)
	sum := sha256.Sum256([]byte(input))
	key := p.key
	if withOther {
		key = p.otherKey
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func (p *idp) currentGraphToken() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.graphToken
}

// ---------------------------------------------------------------------------- Graph ----

type graphUser struct {
	ID             string `json:"id"`
	AccountEnabled bool   `json:"accountEnabled"`
	UPN            string `json:"userPrincipalName"`
	Mail           string `json:"mail"`
	DisplayName    string `json:"displayName"`
}

type graphMock struct {
	t   *testing.T
	srv *httptest.Server
	idp *idp

	mu       gosync.Mutex
	users    map[string]graphUser
	groups   map[string][]string
	pageSize int
	// throttle answers this many 429s before succeeding; fail answers 500 forever.
	throttle int
	fail     bool
	calls    int
}

func newGraph(t *testing.T, p *idp) *graphMock {
	g := &graphMock{t: t, idp: p, users: map[string]graphUser{}, groups: map[string][]string{}, pageSize: 999}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1.0/users/{oid}", g.user)
	mux.HandleFunc("GET /v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group", g.memberOf)
	g.srv = httptest.NewTLSServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *graphMock) setUser(u graphUser, groups ...string) {
	g.mu.Lock()
	g.users[u.ID] = u
	g.groups[u.ID] = groups
	g.mu.Unlock()
}

func (g *graphMock) setGroups(oid string, groups ...string) {
	g.mu.Lock()
	g.groups[oid] = groups
	g.mu.Unlock()
}

func (g *graphMock) setFail(v bool) {
	g.mu.Lock()
	g.fail = v
	g.mu.Unlock()
}

func (g *graphMock) setThrottle(n int) {
	g.mu.Lock()
	g.throttle = n
	g.mu.Unlock()
}

func (g *graphMock) setPageSize(n int) {
	g.mu.Lock()
	g.pageSize = n
	g.mu.Unlock()
}

func (g *graphMock) removeUser(oid string) {
	g.mu.Lock()
	delete(g.users, oid)
	g.mu.Unlock()
}

func (g *graphMock) setEnabled(oid string, enabled bool) {
	g.mu.Lock()
	u := g.users[oid]
	u.AccountEnabled = enabled
	g.users[oid] = u
	g.mu.Unlock()
}

// gate applies auth and failure injection; it reports whether the request may proceed.
func (g *graphMock) gate(w http.ResponseWriter, r *http.Request) bool {
	if tok := g.idp.currentGraphToken(); tok == "" || r.Header.Get("Authorization") != "Bearer "+tok {
		writeJSON(w, 401, map[string]any{"error": map[string]string{"code": "InvalidAuthenticationToken"}})
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if g.fail {
		writeJSON(w, 500, map[string]any{"error": map[string]string{"code": "generalException"}})
		return false
	}
	if g.throttle > 0 {
		g.throttle--
		w.Header().Set("Retry-After", "0")
		writeJSON(w, 429, map[string]any{"error": map[string]string{"code": "TooManyRequests"}})
		return false
	}
	return true
}

func (g *graphMock) user(w http.ResponseWriter, r *http.Request) {
	if !g.gate(w, r) {
		return
	}
	g.mu.Lock()
	u, ok := g.users[r.PathValue("oid")]
	g.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "Request_ResourceNotFound"}})
		return
	}
	writeJSON(w, 200, u)
}

func (g *graphMock) memberOf(w http.ResponseWriter, r *http.Request) {
	if !g.gate(w, r) {
		return
	}
	if r.Header.Get("ConsistencyLevel") != "eventual" || r.URL.Query().Get("$count") != "true" {
		g.t.Errorf("transitiveMemberOf cast without ConsistencyLevel: eventual and $count=true")
	}
	oid := r.PathValue("oid")
	g.mu.Lock()
	all, size := g.groups[oid], g.pageSize
	_, known := g.users[oid]
	g.mu.Unlock()
	if !known {
		writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "Request_ResourceNotFound"}})
		return
	}
	skip, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	end := min(skip+size, len(all))
	vals := []map[string]string{}
	for _, id := range all[skip:end] {
		vals = append(vals, map[string]string{"id": id})
	}
	out := map[string]any{"value": vals}
	if end < len(all) {
		out["@odata.nextLink"] = fmt.Sprintf("%s%s?$select=id&$top=%d&$count=true&$skiptoken=%d", g.srv.URL, r.URL.Path, size, end)
	}
	writeJSON(w, 200, out)
}

// ------------------------------------------------------------------------- Windmill ----

type wmUser struct {
	Email      string `json:"email"`
	LoginType  string `json:"login_type"`
	SuperAdmin bool   `json:"super_admin"`
	Devops     bool   `json:"devops"`
	Disabled   bool   `json:"disabled"`
	Username   string `json:"username"`
	Name       string `json:"name,omitempty"`
}

type wmMember struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
	Operator bool   `json:"operator"`
	Disabled bool   `json:"disabled"`
	Role     string `json:"role"`
}

type wmLink struct{ email, rd string }

// windmillFake is a stateful stand-in for the Windmill endpoints the gateway calls.
type windmillFake struct {
	t      *testing.T
	srv    *httptest.Server
	secret string
	sec    *secrets

	mu          gosync.Mutex
	linkBase    string
	users       map[string]*wmUser
	members     map[string]map[string]*wmMember // workspace -> email -> member
	groups      map[string]map[string][]string  // workspace -> group -> usernames
	links       map[string]wmLink
	createCalls int
	loggedOut   []string
	failPrefix  string // requests under this path answer 500
}

var usernameUnsafe = regexp.MustCompile(`[^a-z0-9_]`)

func newWindmill(t *testing.T, sec *secrets, workspaces ...string) *windmillFake {
	f := &windmillFake{t: t, secret: "superadmin-" + randHex(16), sec: sec, linkBase: "https://windmill.test",
		users: map[string]*wmUser{}, members: map[string]map[string]*wmMember{},
		groups: map[string]map[string][]string{}, links: map[string]wmLink{}}
	sec.add(f.secret)
	for _, ws := range workspaces {
		f.members[ws] = map[string]*wmMember{}
		f.groups[ws] = map[string][]string{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/users/list_as_super_admin", f.listUsers)
	mux.HandleFunc("POST /api/users/create", f.createUser)
	mux.HandleFunc("POST /api/users/set_login_type/{email}", f.setLoginType)
	mux.HandleFunc("POST /api/users/update/{email}", f.updateUser)
	mux.HandleFunc("POST /api/users/login_links", f.loginLink)
	mux.HandleFunc("POST /api/auth/logout", f.logout)
	mux.HandleFunc("POST /api/workspaces/exists", f.workspaceExists)
	mux.HandleFunc("GET /api/w/{w}/users/list", f.listMembers)
	mux.HandleFunc("POST /api/w/{w}/workspaces/add_user", f.addMember)
	mux.HandleFunc("POST /api/w/{w}/users/update/{username}", f.updateMember)
	mux.HandleFunc("GET /api/w/{w}/groups/get/{g}", f.getGroup)
	mux.HandleFunc("POST /api/w/{w}/groups/create", f.createGroup)
	mux.HandleFunc("POST /api/w/{w}/groups/adduser/{g}", f.addToGroup)
	mux.HandleFunc("POST /api/w/{w}/groups/removeuser/{g}", f.removeFromGroup)
	f.srv = httptest.NewServer(f.auth(mux))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *windmillFake) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/logout" && r.Header.Get("Authorization") != "Bearer "+f.secret {
			http.Error(w, "Unauthorized", 401)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failPrefix != "" && strings.HasPrefix(r.URL.Path, f.failPrefix) {
			http.Error(w, "injected failure", 500)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decode(r *http.Request, v any) { _ = json.NewDecoder(r.Body).Decode(v) }

// addUser seeds an account as an administrator would have created it.
func (f *windmillFake) addUser(u wmUser) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u.Username == "" {
		u.Username = usernameUnsafe.ReplaceAllString(strings.ToLower(strings.Split(u.Email, "@")[0]), "_")
	}
	f.users[u.Email] = &u
}

func (f *windmillFake) user(email string) *wmUser {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[email]; ok {
		c := *u
		return &c
	}
	return nil
}

func (f *windmillFake) member(ws, email string) *wmMember {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.members[ws][email]; ok {
		c := *m
		return &c
	}
	return nil
}

func (f *windmillFake) groupMembers(ws, g string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.groups[ws][g]...)
}

func (f *windmillFake) setUserDisabled(email string, disabled bool) {
	f.mu.Lock()
	f.users[email].Disabled = disabled
	f.mu.Unlock()
}

func (f *windmillFake) seedMember(ws string, m wmMember) {
	f.mu.Lock()
	f.members[ws][m.Email] = &m
	f.mu.Unlock()
}

// failUnder makes every request under prefix fail with 500; "" turns it off.
func (f *windmillFake) failUnder(prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failPrefix = prefix
}

func (f *windmillFake) setLinkBase(b string) {
	f.mu.Lock()
	f.linkBase = b
	f.mu.Unlock()
}

func (f *windmillFake) link(token string) (wmLink, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.links[token]
	return l, ok
}

func (f *windmillFake) logouts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.loggedOut...)
}

func (f *windmillFake) creates() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createCalls
}

func (f *windmillFake) listUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	all := []wmUser{}
	for _, u := range f.users {
		all = append(all, *u)
	}
	start := min((page-1)*per, len(all))
	writeJSON(w, 200, all[start:min(start+per, len(all))])
}

func (f *windmillFake) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email      string `json:"email"`
		SuperAdmin bool   `json:"super_admin"`
		LoginType  string `json:"login_type"`
		Name       string `json:"name"`
	}
	decode(r, &in)
	f.createCalls++
	if in.SuperAdmin || in.LoginType != "entra" {
		f.t.Errorf("gateway created a user with super_admin=%v login_type=%q", in.SuperAdmin, in.LoginType)
	}
	if _, ok := f.users[in.Email]; ok {
		http.Error(w, "email already exists", 409)
		return
	}
	f.users[in.Email] = &wmUser{Email: in.Email, LoginType: in.LoginType, Name: in.Name,
		Username: usernameUnsafe.ReplaceAllString(strings.ToLower(strings.Split(in.Email, "@")[0]), "_")}
	w.WriteHeader(201)
}

func (f *windmillFake) setLoginType(w http.ResponseWriter, r *http.Request) {
	var in struct {
		LoginType string `json:"login_type"`
	}
	decode(r, &in)
	u, ok := f.users[r.PathValue("email")]
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	u.LoginType = in.LoginType
}

func (f *windmillFake) updateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Disabled *bool `json:"disabled"`
	}
	decode(r, &in)
	u, ok := f.users[r.PathValue("email")]
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	if in.Disabled != nil {
		u.Disabled = *in.Disabled
	}
}

func (f *windmillFake) loginLink(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email            string `json:"email"`
		RD               string `json:"rd"`
		ExpiresIn        int    `json:"expires_in_s"`
		RequireLoginType string `json:"require_login_type"`
	}
	decode(r, &in)
	u, ok := f.users[in.Email]
	if !ok || u.Disabled {
		http.Error(w, "no active account", 404)
		return
	}
	if u.SuperAdmin || u.Devops {
		http.Error(w, "login links cannot target privileged accounts", 400)
		return
	}
	if in.RequireLoginType != "" && in.RequireLoginType != u.LoginType {
		http.Error(w, "login type mismatch", 409)
		return
	}
	tok := randHex(16)
	f.sec.add(tok)
	f.links[tok] = wmLink{email: in.Email, rd: in.RD}
	writeJSON(w, 201, map[string]any{"url": f.linkBase + "/api/auth/login_link/" + tok,
		"expires_at": time.Now().Add(time.Duration(in.ExpiresIn) * time.Second)})
}

func (f *windmillFake) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("token"); err == nil {
		f.loggedOut = append(f.loggedOut, c.Value)
	}
}

func (f *windmillFake) workspaceExists(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
	}
	decode(r, &in)
	_, ok := f.members[in.ID]
	writeJSON(w, 200, ok)
}

func (f *windmillFake) listMembers(w http.ResponseWriter, r *http.Request) {
	ms, ok := f.members[r.PathValue("w")]
	if !ok {
		http.Error(w, "workspace not found", 404)
		return
	}
	out := []wmMember{}
	for _, m := range ms {
		out = append(out, *m)
	}
	writeJSON(w, 200, out)
}

func (f *windmillFake) addMember(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		IsAdmin  bool   `json:"is_admin"`
		Operator bool   `json:"operator"`
		Role     string `json:"role"`
	}
	decode(r, &in)
	ms, ok := f.members[r.PathValue("w")]
	u, uok := f.users[in.Email]
	if !ok || !uok {
		http.Error(w, "not found", 404)
		return
	}
	if _, dup := ms[in.Email]; dup {
		http.Error(w, "already a member", 409)
		return
	}
	ms[in.Email] = &wmMember{Username: u.Username, Email: in.Email, IsAdmin: in.IsAdmin, Operator: in.Operator, Role: in.Role}
	w.WriteHeader(201)
}

func (f *windmillFake) updateMember(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IsAdmin  *bool   `json:"is_admin"`
		Operator *bool   `json:"operator"`
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
	}
	decode(r, &in)
	for _, m := range f.members[r.PathValue("w")] {
		if m.Username != r.PathValue("username") {
			continue
		}
		if in.IsAdmin != nil {
			m.IsAdmin = *in.IsAdmin
		}
		if in.Operator != nil {
			m.Operator = *in.Operator
		}
		if in.Role != nil {
			m.Role = *in.Role
		}
		if in.Disabled != nil {
			m.Disabled = *in.Disabled
		}
		return
	}
	http.Error(w, "not found", 404)
}

func (f *windmillFake) getGroup(w http.ResponseWriter, r *http.Request) {
	members, ok := f.groups[r.PathValue("w")][r.PathValue("g")]
	if !ok {
		http.Error(w, "group not found", 404)
		return
	}
	writeJSON(w, 200, map[string]any{"name": r.PathValue("g"), "members": append([]string{}, members...)})
}

func (f *windmillFake) createGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	decode(r, &in)
	gs, ok := f.groups[r.PathValue("w")]
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	if _, dup := gs[in.Name]; dup {
		http.Error(w, "group exists", 400)
		return
	}
	gs[in.Name] = []string{"superadmin_secret"} // Windmill adds the creator
	w.WriteHeader(201)
}

func (f *windmillFake) addToGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
	}
	decode(r, &in)
	gs := f.groups[r.PathValue("w")]
	g, ok := gs[r.PathValue("g")]
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	gs[r.PathValue("g")] = append(g, in.Username)
}

func (f *windmillFake) removeFromGroup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
	}
	decode(r, &in)
	gs := f.groups[r.PathValue("w")]
	g, ok := gs[r.PathValue("g")]
	if !ok {
		http.Error(w, "not found", 404)
		return
	}
	out := g[:0]
	for _, u := range g {
		if u != in.Username {
			out = append(out, u)
		}
	}
	gs[r.PathValue("g")] = out
}

// -------------------------------------------------------------------------- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// logBuffer is a concurrency-safe log sink.
type logBuffer struct {
	mu  gosync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
