// Package graph reads a user and their transitive group memberships from Microsoft Graph
// with app-only (client-credentials) access (the app needs only `User.Read.All`), and a user's
// own entry with their delegated token (`User.Read`).
package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	maxAttempts  = 3
	LookupBudget = 10 * time.Second
	maxPages     = 100
	maxBody      = 4 << 20
)

// ErrNotFound means Graph has no such user (deleted, or not in this tenant).
var ErrNotFound = errors.New("graph: user not found")

// User is the subset of the Graph user resource the gateway reads.
type User struct {
	ID             string `json:"id"`
	AccountEnabled bool   `json:"accountEnabled"`
	UPN            string `json:"userPrincipalName"`
	Mail           string `json:"mail"`
	DisplayName    string `json:"displayName"`
}

// Email is `mail` when set, else the UPN, lowercased.
func (u *User) Email() string {
	if m := strings.TrimSpace(u.Mail); m != "" {
		return strings.ToLower(m)
	}
	return strings.ToLower(strings.TrimSpace(u.UPN))
}

// Client calls Graph.
type Client struct {
	base  *url.URL
	http  *http.Client // carries the app's client-credentials token
	plain *http.Client // for requests that bring their own (delegated) token
	sleep func(context.Context, time.Duration) error
}

// Settings configures a Client. HTTPClient is the transport used for both the token
// endpoint and Graph (tests inject one trusting their TLS servers).
type Settings struct {
	BaseURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

// New builds a client whose requests carry a client-credentials token for Graph.
func New(s Settings) (*Client, error) {
	base, err := url.Parse(s.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("graph base URL: %w", err)
	}
	transport := s.HTTPClient
	if transport == nil {
		transport = &http.Client{Timeout: LookupBudget}
	}
	cc := clientcredentials.Config{
		ClientID:     s.ClientID,
		ClientSecret: s.ClientSecret,
		TokenURL:     s.TokenURL,
		Scopes:       []string{strings.TrimSuffix(s.BaseURL, "/") + "/.default"},
		AuthStyle:    oauth2.AuthStyleInParams,
	}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, transport)
	authed := oauth2.NewClient(ctx, cc.TokenSource(ctx))
	authed.Timeout = LookupBudget
	plain := *transport
	plain.Timeout = LookupBudget
	return &Client{base: base, http: authed, plain: &plain, sleep: sleepCtx}, nil
}

// Me reads the signed-in user's own directory entry with their delegated token (User.Read),
// which needs no admin-consented application permission. oid must match the entry.
func (c *Client) Me(ctx context.Context, accessToken, oid string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, LookupBudget)
	defer cancel()
	u := c.base.JoinPath("v1.0", "me")
	u.RawQuery = "$select=id,userPrincipalName,mail,displayName"
	var user User
	if err := c.fetch(ctx, c.plain, accessToken, u.String(), &user); err != nil {
		return nil, err
	}
	if !strings.EqualFold(user.ID, oid) {
		return nil, errors.New("graph: user id mismatch")
	}
	// Entra issues no tokens to a disabled account, so a user who just signed in is enabled.
	user.AccountEnabled = true
	return &user, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Lookup returns the user and the IDs of every group they belong to, directly or nested,
// within one overall time budget. Any error must be treated as "deny".
func (c *Client) Lookup(ctx context.Context, oid string) (*User, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, LookupBudget)
	defer cancel()
	user, err := c.user(ctx, oid)
	if err != nil {
		return nil, nil, err
	}
	groups, err := c.groups(ctx, oid)
	if err != nil {
		return nil, nil, err
	}
	return user, groups, nil
}

func (c *Client) user(ctx context.Context, oid string) (*User, error) {
	u := c.base.JoinPath("v1.0", "users", oid)
	u.RawQuery = "$select=id,accountEnabled,userPrincipalName,mail,displayName"
	var user User
	if err := c.getJSON(ctx, u.String(), &user); err != nil {
		return nil, err
	}
	if !strings.EqualFold(user.ID, oid) {
		return nil, errors.New("graph: user id mismatch")
	}
	return &user, nil
}

func (c *Client) groups(ctx context.Context, oid string) ([]string, error) {
	u := c.base.JoinPath("v1.0", "users", oid, "transitiveMemberOf", "microsoft.graph.group")
	// Graph documents the OData cast as an advanced query: it needs $count=true together with
	// the ConsistencyLevel: eventual header that getJSON sends.
	u.RawQuery = "$select=id&$top=999&$count=true"
	next := u.String()
	var ids []string
	for page := 0; next != ""; page++ {
		if page == maxPages {
			return nil, errors.New("graph: too many group pages")
		}
		var resp struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := c.getJSON(ctx, next, &resp); err != nil {
			return nil, err
		}
		for _, g := range resp.Value {
			ids = append(ids, strings.ToLower(g.ID))
		}
		next = resp.NextLink
		if next != "" && !c.sameOrigin(next) {
			// The bearer token must never be sent anywhere but Graph.
			return nil, errors.New("graph: nextLink points outside Graph")
		}
	}
	return ids, nil
}

func (c *Client) sameOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == c.base.Scheme && u.Host == c.base.Host
}

// getJSON performs a GET with retries on 429 and 5xx, honouring Retry-After within the
// caller's deadline.
func (c *Client) getJSON(ctx context.Context, rawURL string, out any) error {
	return c.fetch(ctx, c.http, "", rawURL, out)
}

// fetch is getJSON over hc, adding bearer as the Authorization token when set.
func (c *Client) fetch(ctx context.Context, hc *http.Client, bearer, rawURL string, out any) error {
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return fmt.Errorf("graph: request: %w", err)
		}
		req.Header.Set("ConsistencyLevel", "eventual")
		req.Header.Set("Accept", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("graph: %w", redact(err))
			if ctx.Err() != nil || attempt == maxAttempts {
				return lastErr
			}
			if err := c.sleep(ctx, backoff(attempt, "")); err != nil {
				return lastErr
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			if readErr != nil {
				return fmt.Errorf("graph: read body: %w", readErr)
			}
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("graph: decode: %w", err)
			}
			return nil
		case resp.StatusCode == http.StatusNotFound:
			return ErrNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("graph: HTTP %d", resp.StatusCode)
			if attempt == maxAttempts {
				return lastErr
			}
			wait := backoff(attempt, resp.Header.Get("Retry-After"))
			if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait {
				return fmt.Errorf("%w (retry budget exhausted)", lastErr)
			}
			if err := c.sleep(ctx, wait); err != nil {
				return lastErr
			}
		default:
			return fmt.Errorf("graph: HTTP %d", resp.StatusCode)
		}
	}
	return lastErr
}

func backoff(attempt int, retryAfter string) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(retryAfter); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
		return 0
	}
	return time.Duration(attempt) * 500 * time.Millisecond
}

// redact keeps transport errors free of request URLs and token-endpoint response bodies.
func redact(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return fmt.Errorf("token endpoint error %s", re.ErrorCode)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %v", ue.Op, ue.Err)
	}
	return err
}
