// Command mock-entra is a TEST-ONLY stand-in for Microsoft Entra ID (OIDC authorization code +
// PKCE, client credentials, JWKS, end session) and the two Microsoft Graph calls the gateway
// makes. It is used by docker-compose.test.yml only and is never part of a deployment.
//
// Who signs in is chosen by the test through the /_mock endpoints, not by a login form.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type user struct {
	UPN         string   `json:"upn"`
	Mail        string   `json:"mail"`
	DisplayName string   `json:"display_name"`
	Enabled     bool     `json:"enabled"`
	Groups      []string `json:"groups"`
}

type grant struct {
	oid, nonce, challenge, redirect string
	expires                         time.Time
}

type mock struct {
	base, tenant, clientID, secret string
	redirects                      []string
	key                            *rsa.PrivateKey

	mu          sync.Mutex
	users       map[string]user
	next        string
	codes       map[string]grant
	graphTokens map[string]time.Time
	counts      map[string]int
}

func main() {
	secret := strings.TrimSpace(string(must(os.ReadFile(os.Getenv("MOCK_CLIENT_SECRET_FILE")))))
	m := &mock{
		base:        strings.TrimSuffix(os.Getenv("MOCK_BASE_URL"), "/"),
		tenant:      strings.ToLower(os.Getenv("MOCK_TENANT_ID")),
		clientID:    strings.ToLower(os.Getenv("MOCK_CLIENT_ID")),
		secret:      secret,
		redirects:   strings.Split(os.Getenv("MOCK_REDIRECT_URIS"), ","),
		key:         must(rsa.GenerateKey(rand.Reader, 2048)),
		users:       map[string]user{},
		codes:       map[string]grant{},
		graphTokens: map[string]time.Time{},
		counts:      map[string]int{},
	}
	t := "/" + m.tenant
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+t+"/v2.0/.well-known/openid-configuration", m.discovery)
	mux.HandleFunc("GET "+t+"/discovery/v2.0/keys", m.jwks)
	mux.HandleFunc("GET "+t+"/oauth2/v2.0/authorize", m.authorize)
	mux.HandleFunc("POST "+t+"/oauth2/v2.0/token", m.token)
	mux.HandleFunc("GET "+t+"/oauth2/v2.0/logout", m.logout)
	mux.HandleFunc("GET /v1.0/users/{oid}", m.graphUser)
	mux.HandleFunc("GET /v1.0/users/{oid}/transitiveMemberOf/microsoft.graph.group", m.graphGroups)
	mux.HandleFunc("PUT /_mock/users/{oid}", m.putUser)
	mux.HandleFunc("DELETE /_mock/users/{oid}", m.deleteUser)
	mux.HandleFunc("POST /_mock/next/{oid}", m.setNext)
	mux.HandleFunc("GET /_mock/counts", m.getCounts)
	srv := &http.Server{Addr: ":8443", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("mock-entra (TEST ONLY) listening on :8443 as %s/%s", m.base, m.tenant)
	log.Fatal(srv.ListenAndServeTLS(os.Getenv("MOCK_TLS_CERT"), os.Getenv("MOCK_TLS_KEY")))
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}

func (m *mock) issuer() string { return m.base + "/" + m.tenant + "/v2.0" }

func (m *mock) count(name string) {
	m.mu.Lock()
	m.counts[name]++
	m.mu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func randomString() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (m *mock) discovery(w http.ResponseWriter, _ *http.Request) {
	t := m.base + "/" + m.tenant
	writeJSON(w, 200, map[string]any{
		"issuer":                                m.issuer(),
		"authorization_endpoint":                t + "/oauth2/v2.0/authorize",
		"token_endpoint":                        t + "/oauth2/v2.0/token",
		"jwks_uri":                              t + "/discovery/v2.0/keys",
		"end_session_endpoint":                  t + "/oauth2/v2.0/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"pairwise"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (m *mock) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := m.key.PublicKey
	writeJSON(w, 200, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "mock-1",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (m *mock) authorize(w http.ResponseWriter, r *http.Request) {
	m.count("authorize")
	q := r.URL.Query()
	redirect := q.Get("redirect_uri")
	if !slices.Contains(m.redirects, redirect) || !strings.EqualFold(q.Get("client_id"), m.clientID) {
		http.Error(w, "unregistered client or redirect_uri", http.StatusBadRequest)
		return
	}
	back := must(url.Parse(redirect))
	out := url.Values{"state": {q.Get("state")}}
	m.mu.Lock()
	oid := m.next
	_, known := m.users[oid]
	m.mu.Unlock()
	switch {
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		!slices.Contains(strings.Fields(q.Get("scope")), "openid") || q.Get("nonce") == "":
		out.Set("error", "invalid_request")
	case !known:
		out.Set("error", "access_denied")
	default:
		code := randomString()
		m.mu.Lock()
		m.codes[code] = grant{oid: oid, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: redirect,
			expires: time.Now().Add(5 * time.Minute)}
		m.mu.Unlock()
		out.Set("code", code)
	}
	back.RawQuery = out.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (m *mock) clientAuthenticated(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	return strings.EqualFold(id, m.clientID) && subtle.ConstantTimeCompare([]byte(secret), []byte(m.secret)) == 1
}

func (m *mock) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request")
		return
	}
	if !m.clientAuthenticated(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "client_credentials":
		m.count("client_credentials")
		if r.PostForm.Get("scope") != m.base+"/.default" {
			oauthError(w, "invalid_scope")
			return
		}
		tok := randomString()
		m.mu.Lock()
		m.graphTokens[tok] = time.Now().Add(time.Hour)
		m.mu.Unlock()
		writeJSON(w, 200, map[string]any{"token_type": "Bearer", "access_token": tok, "expires_in": 3599})
	case "authorization_code":
		m.count("authorization_code")
		m.mu.Lock()
		g, ok := m.codes[r.PostForm.Get("code")]
		delete(m.codes, r.PostForm.Get("code"))
		u := m.users[g.oid]
		m.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || time.Now().After(g.expires) || g.redirect != r.PostForm.Get("redirect_uri") ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			oauthError(w, "invalid_grant")
			return
		}
		now := time.Now()
		idToken, err := m.sign(map[string]any{
			"iss": m.issuer(), "aud": m.clientID, "sub": "pairwise-" + g.oid, "oid": g.oid, "tid": m.tenant,
			"nonce": g.nonce, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"name": u.DisplayName, "preferred_username": u.UPN, "ver": "2.0",
		})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, 200, map[string]any{"token_type": "Bearer", "access_token": randomString(), "expires_in": 3599,
			"scope": "openid profile", "id_token": idToken})
	default:
		oauthError(w, "unsupported_grant_type")
	}
}

func (m *mock) sign(claims map[string]any) (string, error) {
	enc := func(v any) string { return base64.RawURLEncoding.EncodeToString(must(json.Marshal(v))) }
	input := enc(map[string]string{"alg": "RS256", "kid": "mock-1", "typ": "JWT"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (m *mock) logout(w http.ResponseWriter, r *http.Request) {
	m.count("logout")
	if to := r.URL.Query().Get("post_logout_redirect_uri"); slices.Contains(m.redirects, to) {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	fmt.Fprintln(w, "signed out of mock-entra")
}

func (m *mock) graphAuthorized(w http.ResponseWriter, r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	m.mu.Lock()
	exp, known := m.graphTokens[tok]
	m.mu.Unlock()
	if !ok || !known || time.Now().After(exp) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "InvalidAuthenticationToken"}})
		return false
	}
	return true
}

func (m *mock) lookup(w http.ResponseWriter, oid string) (user, bool) {
	m.mu.Lock()
	u, ok := m.users[strings.ToLower(oid)]
	m.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "Request_ResourceNotFound"}})
	}
	return u, ok
}

func (m *mock) graphUser(w http.ResponseWriter, r *http.Request) {
	m.count("graph_user")
	if !m.graphAuthorized(w, r) {
		return
	}
	if u, ok := m.lookup(w, r.PathValue("oid")); ok {
		writeJSON(w, 200, map[string]any{"id": strings.ToLower(r.PathValue("oid")), "accountEnabled": u.Enabled,
			"userPrincipalName": u.UPN, "mail": u.Mail, "displayName": u.DisplayName})
	}
}

// graphGroups pages two groups at a time so the gateway's nextLink handling runs end to end.
func (m *mock) graphGroups(w http.ResponseWriter, r *http.Request) {
	m.count("graph_groups")
	if !m.graphAuthorized(w, r) {
		return
	}
	if r.Header.Get("ConsistencyLevel") != "eventual" || r.URL.Query().Get("$count") != "true" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "Request_UnsupportedQuery"}})
		return
	}
	u, ok := m.lookup(w, r.PathValue("oid"))
	if !ok {
		return
	}
	const pageSize = 2
	skip, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	end := min(skip+pageSize, len(u.Groups))
	vals := []map[string]string{}
	for _, g := range u.Groups[min(skip, end):end] {
		vals = append(vals, map[string]string{"@odata.type": "#microsoft.graph.group", "id": g})
	}
	out := map[string]any{"@odata.count": len(u.Groups), "value": vals}
	if end < len(u.Groups) {
		next := *r.URL
		q := next.Query()
		q.Set("$skiptoken", strconv.Itoa(end))
		next.RawQuery = q.Encode()
		out["@odata.nextLink"] = m.base + next.RequestURI()
	}
	writeJSON(w, 200, out)
}

func (m *mock) putUser(w http.ResponseWriter, r *http.Request) {
	var u user
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.users[strings.ToLower(r.PathValue("oid"))] = u
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (m *mock) deleteUser(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	delete(m.users, strings.ToLower(r.PathValue("oid")))
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (m *mock) setNext(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.next = strings.ToLower(r.PathValue("oid"))
	m.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (m *mock) getCounts(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	writeJSON(w, 200, m.counts)
}
