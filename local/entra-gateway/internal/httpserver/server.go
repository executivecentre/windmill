// Package httpserver serves the gateway's /sso/* endpoints: it runs the Entra sign-in, has the
// sync engine provision the account, and hands the browser to a single-use Windmill login
// link. It never sits in front of /api: Windmill authenticates every API call itself.
package httpserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"entra-gateway/internal/oidc"
	"entra-gateway/internal/sync"
)

const (
	callbackTimeout = 45 * time.Second
	readyTimeout    = 2 * time.Second
	sessionCookie   = "token" // Windmill's session cookie
)

// Authenticator runs the OIDC flow.
type Authenticator interface {
	Ready() bool
	AuthCodeURL(state, nonce, verifier string) (string, error)
	Exchange(ctx context.Context, code, verifier, nonce string) (oidc.Identity, error)
	LogoutURL(postLogout string) string
}

// Provisioner turns a verified identity into the Windmill e-mail to sign in.
type Provisioner interface {
	Login(ctx context.Context, id oidc.Identity) (string, error)
}

// Windmill is the part of the Windmill API the HTTP layer uses.
type Windmill interface {
	CreateLoginLink(ctx context.Context, email, rd string, ttlSeconds int) (string, error)
	Logout(ctx context.Context, sessionToken string) error
}

// Pinger checks a dependency is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Settings configures a Server.
type Settings struct {
	PublicBaseURL *url.URL
	CookieKey     []byte
	LoginLinkTTL  int
	Now           func() time.Time
}

// Server holds the handlers' dependencies.
type Server struct {
	s      Settings
	auth   Authenticator
	prov   Provisioner
	wm     Windmill
	db     Pinger
	log    *slog.Logger
	sealer *sealer
	replay *replayGuard
}

// New builds a Server.
func New(s Settings, auth Authenticator, prov Provisioner, wm Windmill, db Pinger, log *slog.Logger) (*Server, error) {
	if s.Now == nil {
		s.Now = time.Now
	}
	sl, err := newSealer(s.CookieKey)
	if err != nil {
		return nil, err
	}
	return &Server{s: s, auth: auth, prov: prov, wm: wm, db: db, log: log, sealer: sl, replay: newReplayGuard()}, nil
}

// Handler is the gateway's HTTP handler. Only GET (and HEAD) are routed.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sso/login", s.login)
	mux.HandleFunc("GET /sso/callback", s.callback)
	mux.HandleFunc("GET /sso/logout", s.logout)
	mux.HandleFunc("GET /sso/logged-out", s.loggedOut)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", s.ready)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Ready() {
		renderPage(w, http.StatusServiceUnavailable, pageUnavailable)
		return
	}
	state, err1 := randomToken()
	nonce, err2 := randomToken()
	if err := errors.Join(err1, err2); err != nil {
		s.log.Error("random source failed", "err", err)
		renderPage(w, http.StatusInternalServerError, pageError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	f := flow{State: state, Nonce: nonce, Verifier: verifier,
		RD: sanitizeRD(r.URL.Query().Get("rd")), Expires: s.s.Now().Add(flowTTL).Unix()}
	sealed, err := s.sealer.seal(f)
	if err != nil {
		s.log.Error("sealing flow cookie failed", "err", err)
		renderPage(w, http.StatusInternalServerError, pageError)
		return
	}
	authURL, err := s.auth.AuthCodeURL(state, nonce, verifier)
	if err != nil {
		renderPage(w, http.StatusServiceUnavailable, pageUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: sealed, Path: "/", MaxAge: int(flowTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, authURL, http.StatusFound)
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

var oauthErrorCode = regexp.MustCompile(`^[a-z_]{1,64}$`)

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	// The flow cookie is single-use whatever happens next.
	c, cookieErr := r.Cookie(flowCookie)
	clearCookie(w, flowCookie)
	now := s.s.Now()
	if cookieErr != nil {
		renderPage(w, http.StatusBadRequest, pageExpired)
		return
	}
	f, err := s.sealer.open(c.Value, now)
	if err != nil {
		renderPage(w, http.StatusBadRequest, pageExpired)
		return
	}
	q := r.URL.Query()
	if code := q.Get("error"); code != "" {
		if !oauthErrorCode.MatchString(code) {
			code = "invalid_error_code"
		}
		s.log.Warn("authorization refused by Entra", "error", code)
		renderPage(w, http.StatusForbidden, pageEntraError)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		s.log.Warn("callback state mismatch")
		renderPage(w, http.StatusBadRequest, pageExpired)
		return
	}
	if !s.replay.consume(f.State, time.Unix(f.Expires, 0), now) {
		s.log.Warn("callback replayed")
		renderPage(w, http.StatusBadRequest, pageExpired)
		return
	}
	code := q.Get("code")
	if code == "" {
		renderPage(w, http.StatusBadRequest, pageExpired)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), callbackTimeout)
	defer cancel()
	id, err := s.auth.Exchange(ctx, code, f.Verifier, f.Nonce)
	if err != nil {
		s.log.Warn("sign-in rejected", "err", err)
		renderPage(w, http.StatusUnauthorized, pageInvalid)
		return
	}
	email, err := s.prov.Login(ctx, id)
	if err != nil {
		s.renderLoginError(w, id, err)
		return
	}
	link, err := s.wm.CreateLoginLink(ctx, email, f.RD, s.s.LoginLinkTTL)
	if err != nil {
		s.log.Error("creating login link failed", "oid", id.ObjectID, "err", err)
		renderPage(w, http.StatusBadGateway, pageError)
		return
	}
	target, ok := s.sameOriginLoginLink(link)
	if !ok {
		s.log.Error("login link does not point at PUBLIC_BASE_URL; check Windmill's base URL", "oid", id.ObjectID)
		renderPage(w, http.StatusBadGateway, pageError)
		return
	}
	s.log.Info("sign-in", "oid", id.ObjectID, "email", email)
	w.Header().Set("Location", target)
	w.WriteHeader(http.StatusFound)
}

func (s *Server) renderLoginError(w http.ResponseWriter, id oidc.Identity, err error) {
	var d *sync.DenyError
	if !errors.As(err, &d) {
		s.log.Error("provisioning failed", "oid", id.ObjectID, "err", err)
		renderPage(w, http.StatusBadGateway, pageError)
		return
	}
	s.log.Info("sign-in denied", "oid", id.ObjectID, "reason", d.Reason)
	if d.Reason == sync.ReasonGraphUnavailable {
		renderPage(w, http.StatusServiceUnavailable, pageUnavailable)
		return
	}
	renderPage(w, http.StatusForbidden, deniedPage(d.Reason))
}

// sameOriginLoginLink returns the login link's path when it is a Windmill login link on
// PUBLIC_BASE_URL. Only the path is sent, so the browser stays on the public origin.
func (s *Server) sameOriginLoginLink(link string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil || u.User != nil || u.Fragment != "" ||
		u.Scheme != s.s.PublicBaseURL.Scheme || u.Host != s.s.PublicBaseURL.Host ||
		!strings.HasPrefix(u.Path, "/api/auth/login_link/") {
		return "", false
	}
	return u.RequestURI(), true
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if err := s.wm.Logout(ctx, c.Value); err != nil {
			s.log.Warn("windmill logout failed", "err", err)
		}
	}
	clearCookie(w, sessionCookie)
	after := s.s.PublicBaseURL.String() + "/sso/logged-out"
	if end := s.auth.LogoutURL(after); end != "" {
		http.Redirect(w, r, end, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/sso/logged-out", http.StatusFound)
}

func (s *Server) loggedOut(w http.ResponseWriter, _ *http.Request) {
	renderPage(w, http.StatusOK, pageLoggedOut)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
	defer cancel()
	if !s.auth.Ready() {
		http.Error(w, "oidc discovery pending", http.StatusServiceUnavailable)
		return
	}
	if err := s.db.Ping(ctx); err != nil {
		http.Error(w, "database unreachable", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ready\n"))
}
