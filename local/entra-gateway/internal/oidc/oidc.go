// Package oidc runs the authorization-code + PKCE flow against the tenant's Entra ID v2.0
// authority and verifies the returned ID token.
package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// maxIssuedAtSkew bounds how far in the future an `iat` may be; go-oidc already checks `exp`.
const maxIssuedAtSkew = 2 * time.Minute

// ErrInvalidToken covers every reason an ID token is refused. Details go to the log only.
var ErrInvalidToken = errors.New("invalid ID token")

// Identity is what the gateway keys accounts by: never `email` or `preferred_username`.
type Identity struct {
	TenantID string
	ObjectID string
}

// Settings configures a Client.
type Settings struct {
	Issuer       string
	TenantID     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
	Now          func() time.Time
}

// Client holds the discovered provider. Discovery is retried until it succeeds; until then
// Ready reports false and the login endpoints refuse to start a flow.
type Client struct {
	s Settings

	mu         sync.RWMutex
	provider   *gooidc.Provider
	verifier   *gooidc.IDTokenVerifier
	endSession string
}

// New creates a client; call Discover (or RunDiscovery) before use.
func New(s Settings) *Client {
	if s.HTTPClient == nil {
		s.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	return &Client{s: s}
}

func (c *Client) ctx(ctx context.Context) context.Context {
	return gooidc.ClientContext(ctx, c.s.HTTPClient)
}

// Discover loads the discovery document and JWKS location. go-oidc refuses a document whose
// issuer differs from the configured one.
func (c *Client) Discover(ctx context.Context) error {
	p, err := gooidc.NewProvider(c.ctx(ctx), c.s.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery: %w", err)
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := p.Claims(&extra); err != nil {
		return fmt.Errorf("oidc discovery claims: %w", err)
	}
	v := p.Verifier(&gooidc.Config{
		ClientID:             c.s.ClientID,
		SupportedSigningAlgs: []string{gooidc.RS256},
		Now:                  c.s.Now,
	})
	c.mu.Lock()
	c.provider, c.verifier, c.endSession = p, v, extra.EndSession
	c.mu.Unlock()
	return nil
}

// RunDiscovery retries Discover with backoff until it succeeds or ctx ends.
func (c *Client) RunDiscovery(ctx context.Context, onError func(error)) {
	delay := time.Second
	for {
		err := c.Discover(ctx)
		if err == nil {
			return
		}
		onError(err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < time.Minute {
			delay *= 2
		}
	}
}

// Ready reports whether discovery has completed.
func (c *Client) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.provider != nil
}

func (c *Client) oauth() (*oauth2.Config, *gooidc.IDTokenVerifier, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.provider == nil {
		return nil, nil, errors.New("oidc provider not discovered yet")
	}
	return &oauth2.Config{
		ClientID:     c.s.ClientID,
		ClientSecret: c.s.ClientSecret,
		Endpoint:     c.provider.Endpoint(),
		RedirectURL:  c.s.RedirectURL,
		Scopes:       []string{gooidc.ScopeOpenID, "profile"},
	}, c.verifier, nil
}

// AuthCodeURL is the authorization request URL for one flow.
func (c *Client) AuthCodeURL(state, nonce, verifier string) (string, error) {
	cfg, _, err := c.oauth()
	if err != nil {
		return "", err
	}
	return cfg.AuthCodeURL(state,
		gooidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("response_mode", "query"),
	), nil
}

type entraClaims struct {
	Nonce    string `json:"nonce"`
	TenantID string `json:"tid"`
	ObjectID string `json:"oid"`
}

// Exchange redeems the code with the PKCE verifier and verifies the ID token: signature
// (discovered JWKS), issuer, audience, expiry, issued-at, nonce, tenant and object ID.
func (c *Client) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	cfg, idv, err := c.oauth()
	if err != nil {
		return Identity{}, err
	}
	tok, err := cfg.Exchange(c.ctx(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("code exchange failed: %w", redactOAuthError(err))
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, fmt.Errorf("%w: token response has no id_token", ErrInvalidToken)
	}
	return c.verify(ctx, idv, raw, nonce)
}

func (c *Client) verify(ctx context.Context, idv *gooidc.IDTokenVerifier, raw, nonce string) (Identity, error) {
	idt, err := idv.Verify(c.ctx(ctx), raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %s", ErrInvalidToken, verifyReason(err))
	}
	if idt.IssuedAt.After(c.s.Now().Add(maxIssuedAtSkew)) {
		return Identity{}, fmt.Errorf("%w: issued in the future", ErrInvalidToken)
	}
	var cl entraClaims
	if err := idt.Claims(&cl); err != nil {
		return Identity{}, fmt.Errorf("%w: unreadable claims", ErrInvalidToken)
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(nonce)) != 1 {
		return Identity{}, fmt.Errorf("%w: nonce mismatch", ErrInvalidToken)
	}
	if !strings.EqualFold(cl.TenantID, c.s.TenantID) {
		return Identity{}, fmt.Errorf("%w: tenant mismatch", ErrInvalidToken)
	}
	if cl.ObjectID == "" {
		return Identity{}, fmt.Errorf("%w: no oid claim", ErrInvalidToken)
	}
	return Identity{TenantID: strings.ToLower(cl.TenantID), ObjectID: strings.ToLower(cl.ObjectID)}, nil
}

// verifyReason classifies a go-oidc error without echoing token content.
func verifyReason(err error) string {
	var expired *gooidc.TokenExpiredError
	switch msg := err.Error(); {
	case errors.As(err, &expired):
		return "expired"
	case strings.Contains(msg, "issuer"):
		return "issuer mismatch"
	case strings.Contains(msg, "audience"):
		return "audience mismatch"
	case strings.Contains(msg, "signature"):
		return "bad signature"
	default:
		return "verification failed"
	}
}

// redactOAuthError keeps the OAuth error code and drops the response body, which may echo
// request parameters.
func redactOAuthError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		code := re.ErrorCode
		if code == "" && re.Response != nil {
			code = re.Response.Status
		}
		return fmt.Errorf("token endpoint error %s", code)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("token endpoint unreachable: %v", ue.Err)
	}
	return errors.New("token endpoint error")
}

// LogoutURL is Entra's end-session URL returning to postLogout, or "" when discovery did not
// advertise one.
func (c *Client) LogoutURL(postLogout string) string {
	c.mu.RLock()
	end := c.endSession
	c.mu.RUnlock()
	if end == "" {
		return ""
	}
	u, err := url.Parse(end)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("post_logout_redirect_uri", postLogout)
	u.RawQuery = q.Encode()
	return u.String()
}
