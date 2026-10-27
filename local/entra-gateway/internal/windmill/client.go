// Package windmill calls the Windmill server's REST API on the internal network, authenticated
// with SUPERADMIN_SECRET.
package windmill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxBody     = 4 << 20
	listPage    = 1000
	callTimeout = 15 * time.Second
	// LoginType is the only login type the gateway creates or signs in. It is never
	// pending_oauth: a pending_oauth account may set its own password.
	LoginType = "entra"
	// superadminSecretUser is the username Windmill gives the SUPERADMIN_SECRET caller; creating
	// a group adds it as a member, which the gateway removes again.
	superadminSecretUser = "superadmin_secret"
)

var (
	ErrNotFound = errors.New("windmill: not found")
	ErrConflict = errors.New("windmill: conflict")
)

// StatusError is a non-2xx response.
type StatusError struct {
	Op     string
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("windmill %s: HTTP %d", e.Op, e.Status)
	}
	return fmt.Sprintf("windmill %s: HTTP %d: %s", e.Op, e.Status, e.Body)
}

func (e *StatusError) Unwrap() error {
	switch e.Status {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	}
	return nil
}

// Client talks to one Windmill server.
type Client struct {
	base   string
	secret string
	http   *http.Client
}

// New returns a client for baseURL (an origin such as http://windmill_server:8000).
func New(baseURL, superadminSecret string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: callTimeout}
	}
	// Never follow redirects: a redirect would carry the superadmin secret elsewhere.
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: strings.TrimSuffix(baseURL, "/"), secret: superadminSecret, http: &c}
}

// do sends a request; out may be nil, *string (raw body) or a JSON target. redactBody keeps
// the response body out of errors.
func (c *Client) do(ctx context.Context, op, method, path string, in, out any, redactBody bool) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("windmill %s: encode: %w", op, err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return fmt.Errorf("windmill %s: %w", op, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("windmill %s: %w", op, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("windmill %s: read: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		se := &StatusError{Op: op, Status: resp.StatusCode}
		if !redactBody {
			se.Body = truncate(strings.TrimSpace(string(raw)), 200)
		}
		return se
	}
	switch o := out.(type) {
	case nil:
		return nil
	case *string:
		*o = string(raw)
		return nil
	default:
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("windmill %s: decode: %w", op, err)
		}
		return nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func esc(s string) string { return url.PathEscape(s) }

// GlobalUser is an instance-level account.
type GlobalUser struct {
	Email      string `json:"email"`
	LoginType  string `json:"login_type"`
	SuperAdmin bool   `json:"super_admin"`
	Devops     bool   `json:"devops"`
	Disabled   bool   `json:"disabled"`
	Username   string `json:"username"`
}

// GlobalUser returns the account with this e-mail, or nil.
func (c *Client) GlobalUser(ctx context.Context, email string) (*GlobalUser, error) {
	for page := 1; ; page++ {
		var users []GlobalUser
		path := fmt.Sprintf("/api/users/list_as_super_admin?page=%d&per_page=%d", page, listPage)
		if err := c.do(ctx, "list users", http.MethodGet, path, nil, &users, false); err != nil {
			return nil, err
		}
		for i := range users {
			if users[i].LoginType != "service_account" && strings.EqualFold(users[i].Email, email) {
				return &users[i], nil
			}
		}
		if len(users) < listPage {
			return nil, nil
		}
	}
}

// MicrosoftApp is a Microsoft Entra app registration saved in Windmill's OAuth settings.
type MicrosoftApp struct {
	Key      string `json:"-"` // the `oauths` entry it was read from
	TenantID string `json:"tenant"`
	ClientID string `json:"id"`
	Secret   string `json:"secret"`
}

// microsoftOAuthKeys are tried in order: Windmill's Microsoft login entry, then the Teams app
// (`teams` is its pre-rename key).
var microsoftOAuthKeys = []string{"microsoft", "ms_teams", "teams"}

// MicrosoftApp returns the first Microsoft app registration in Windmill's OAuth settings, or nil.
// The response holds client secrets, so it never reaches an error message.
func (c *Client) MicrosoftApp(ctx context.Context) (*MicrosoftApp, error) {
	var oauths map[string]json.RawMessage
	if err := c.do(ctx, "read oauth settings", http.MethodGet, "/api/settings/global/oauths", nil, &oauths, true); err != nil {
		var se *StatusError
		if errors.As(err, &se) {
			return nil, err
		}
		return nil, errors.New("windmill read oauth settings: unreadable response")
	}
	for _, key := range microsoftOAuthKeys {
		raw, ok := oauths[key]
		if !ok || string(raw) == "null" {
			continue
		}
		var app MicrosoftApp
		if json.Unmarshal(raw, &app) != nil {
			return nil, fmt.Errorf("windmill oauth setting %s: unreadable", key)
		}
		app.Key = key
		return &app, nil
	}
	return nil, nil
}

// CreateUser creates an `entra` account (no password, never superadmin).
func (c *Client) CreateUser(ctx context.Context, email, name string) error {
	in := map[string]any{"email": email, "super_admin": false, "login_type": LoginType}
	if name != "" {
		in["name"] = name
	}
	return c.do(ctx, "create user", http.MethodPost, "/api/users/create", in, nil, false)
}

// SetLoginType changes an account's login type.
func (c *Client) SetLoginType(ctx context.Context, email, loginType string) error {
	return c.do(ctx, "set login type", http.MethodPost, "/api/users/set_login_type/"+esc(email),
		map[string]string{"login_type": loginType}, nil, false)
}

// SetDisabled disables or re-enables an account. Disabling deletes all its tokens.
func (c *Client) SetDisabled(ctx context.Context, email string, disabled bool) error {
	return c.do(ctx, "update user", http.MethodPost, "/api/users/update/"+esc(email),
		map[string]bool{"disabled": disabled}, nil, false)
}

// CreateLoginLink mints a single-use login link for an `entra` account and returns its URL.
// The response body carries a credential, so it never reaches an error.
func (c *Client) CreateLoginLink(ctx context.Context, email, rd string, ttlSeconds int) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	in := map[string]any{"email": email, "rd": rd, "expires_in_s": ttlSeconds, "require_login_type": LoginType}
	if err := c.do(ctx, "create login link", http.MethodPost, "/api/users/login_links", in, &out, true); err != nil {
		return "", err
	}
	if out.URL == "" {
		return "", errors.New("windmill create login link: empty url")
	}
	return out.URL, nil
}

// Logout deletes the session token server-side.
func (c *Client) Logout(ctx context.Context, sessionToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/auth/logout", nil)
	if err != nil {
		return fmt.Errorf("windmill logout: %w", err)
	}
	req.AddCookie(&http.Cookie{Name: "token", Value: sessionToken})
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("windmill logout: request failed")
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &StatusError{Op: "logout", Status: resp.StatusCode}
	}
	return nil
}

// WorkspaceExists reports whether a workspace exists (archived ones included).
func (c *Client) WorkspaceExists(ctx context.Context, workspace string) (bool, error) {
	var out bool
	err := c.do(ctx, "workspace exists", http.MethodPost, "/api/workspaces/exists",
		map[string]string{"id": workspace}, &out, false)
	return out, err
}

// Role is how Windmill represents a member's workspace role.
type Role struct {
	IsAdmin  bool
	Operator bool
	Name     string // "developer" or "operator"
}

// WorkspaceUser is a workspace member.
type WorkspaceUser struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
	Operator bool   `json:"operator"`
	Disabled bool   `json:"disabled"`
	Role     string `json:"role"`
}

// RoleName is the member's grantable role: admin, developer or operator.
func (u *WorkspaceUser) RoleName() string {
	switch {
	case u.IsAdmin:
		return "admin"
	case u.Operator || u.Role == "operator":
		return "operator"
	default:
		return "developer"
	}
}

// WorkspaceUser returns the member with this e-mail, or nil.
func (c *Client) WorkspaceUser(ctx context.Context, workspace, email string) (*WorkspaceUser, error) {
	var users []WorkspaceUser
	if err := c.do(ctx, "list workspace users", http.MethodGet,
		"/api/w/"+esc(workspace)+"/users/list", nil, &users, false); err != nil {
		return nil, err
	}
	for i := range users {
		if strings.EqualFold(users[i].Email, email) {
			return &users[i], nil
		}
	}
	return nil, nil
}

func roleBody(r Role) map[string]any {
	return map[string]any{"is_admin": r.IsAdmin, "operator": r.Operator, "role": r.Name}
}

// AddWorkspaceUser adds an account to a workspace.
func (c *Client) AddWorkspaceUser(ctx context.Context, workspace, email string, r Role) error {
	in := roleBody(r)
	in["email"] = email
	return c.do(ctx, "add workspace user", http.MethodPost,
		"/api/w/"+esc(workspace)+"/workspaces/add_user", in, nil, false)
}

// UpdateWorkspaceUser sets a member's role and disabled flag.
func (c *Client) UpdateWorkspaceUser(ctx context.Context, workspace, username string, r Role, disabled bool) error {
	in := roleBody(r)
	in["disabled"] = disabled
	return c.do(ctx, "update workspace user", http.MethodPost,
		"/api/w/"+esc(workspace)+"/users/update/"+esc(username), in, nil, false)
}

// DisableWorkspaceUser disables a membership without changing its role.
func (c *Client) DisableWorkspaceUser(ctx context.Context, workspace, username string) error {
	return c.do(ctx, "disable workspace user", http.MethodPost,
		"/api/w/"+esc(workspace)+"/users/update/"+esc(username), map[string]bool{"disabled": true}, nil, false)
}

// GroupMembers returns a group's member usernames, or ErrNotFound.
func (c *Client) GroupMembers(ctx context.Context, workspace, group string) ([]string, error) {
	var out struct {
		Members []string `json:"members"`
	}
	if err := c.do(ctx, "get group", http.MethodGet,
		"/api/w/"+esc(workspace)+"/groups/get/"+esc(group), nil, &out, false); err != nil {
		return nil, err
	}
	return out.Members, nil
}

// CreateGroup creates a group and removes the caller Windmill adds as its first member.
func (c *Client) CreateGroup(ctx context.Context, workspace, group string) error {
	if err := c.do(ctx, "create group", http.MethodPost, "/api/w/"+esc(workspace)+"/groups/create",
		map[string]string{"name": group, "summary": "Managed by the Entra ID gateway"}, nil, false); err != nil {
		return err
	}
	return c.RemoveGroupMember(ctx, workspace, group, superadminSecretUser)
}

// AddGroupMember adds a workspace member to a group.
func (c *Client) AddGroupMember(ctx context.Context, workspace, group, username string) error {
	return c.do(ctx, "add group member", http.MethodPost,
		"/api/w/"+esc(workspace)+"/groups/adduser/"+esc(group), map[string]string{"username": username}, nil, false)
}

// RemoveGroupMember removes a member from a group.
func (c *Client) RemoveGroupMember(ctx context.Context, workspace, group, username string) error {
	return c.do(ctx, "remove group member", http.MethodPost,
		"/api/w/"+esc(workspace)+"/groups/removeuser/"+esc(group), map[string]string{"username": username}, nil, false)
}
