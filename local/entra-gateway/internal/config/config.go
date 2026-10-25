// Package config loads and validates the gateway configuration from the environment.
// Secrets are read from files named by `*_FILE` variables (Docker secrets); every value is
// validated at startup and the process refuses to start on anything missing or malformed.
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAuthorityURL = "https://login.microsoftonline.com"
	DefaultGraphURL     = "https://graph.microsoft.com"
	defaultListenAddr   = ":8080"
	minReconcile        = time.Minute
	maxLoginLinkTTL     = 900 // Windmill clamps login links to 1..=900 s
	cookieKeyLen        = 32
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Config is the validated gateway configuration.
type Config struct {
	PublicBaseURL     *url.URL
	TenantID          string
	ClientID          string
	ClientSecret      string
	AuthorityURL      string
	GraphURL          string
	WindmillURL       string
	SuperadminSecret  string
	DatabaseURL       string
	CookieKey         []byte
	Mappings          Mappings
	AllowedDomains    []string
	AdoptExisting     bool
	ReconcileInterval time.Duration
	LoginLinkTTL      int
	ListenAddr        string
}

// Issuer is the only issuer accepted on ID tokens.
func (c *Config) Issuer() string {
	return c.AuthorityURL + "/" + c.TenantID + "/v2.0"
}

// RedirectURL is the OIDC redirect URI registered on the Entra app.
func (c *Config) RedirectURL() string {
	return c.PublicBaseURL.String() + "/sso/callback"
}

// TokenURL is the tenant's OAuth 2.0 token endpoint, used for Graph client credentials.
func (c *Config) TokenURL() string {
	return c.AuthorityURL + "/" + c.TenantID + "/oauth2/v2.0/token"
}

// DomainAllowed reports whether the address's domain is in ALLOWED_EMAIL_DOMAINS.
func (c *Config) DomainAllowed(email string) bool {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range c.AllowedDomains {
		if domain == d {
			return true
		}
	}
	return false
}

// Env abstracts the process environment for tests.
type Env struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error)
}

// OSEnv reads the real environment and filesystem.
func OSEnv() Env {
	return Env{Getenv: os.Getenv, ReadFile: os.ReadFile}
}

type loader struct {
	env  Env
	errs []error
}

func (l *loader) fail(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *loader) plain(name, def string) string {
	v := strings.TrimSpace(l.env.Getenv(name))
	if v == "" {
		return def
	}
	return v
}

func (l *loader) required(name string) string {
	v := l.plain(name, "")
	if v == "" {
		l.fail("%s is required", name)
	}
	return v
}

// secret reads NAME_FILE (preferred) or NAME, never both.
func (l *loader) secret(name string) string {
	direct := l.env.Getenv(name)
	path := strings.TrimSpace(l.env.Getenv(name + "_FILE"))
	switch {
	case direct != "" && path != "":
		l.fail("set only one of %s and %s_FILE", name, name)
		return ""
	case path != "":
		b, err := l.env.ReadFile(path)
		if err != nil {
			l.fail("%s_FILE: cannot read secret file", name)
			return ""
		}
		v := strings.TrimSpace(string(b))
		if v == "" {
			l.fail("%s_FILE: secret file is empty", name)
		}
		return v
	case direct != "":
		return strings.TrimSpace(direct)
	default:
		l.fail("%s_FILE is required", name)
		return ""
	}
}

func (l *loader) httpsURL(name, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		l.fail("%s must be an https origin without path, query or credentials", name)
		return ""
	}
	return strings.TrimSuffix(u.String(), "/")
}

// Load reads and validates the configuration.
func Load(env Env) (*Config, error) {
	l := &loader{env: env}
	cfg := &Config{}

	public := l.required("PUBLIC_BASE_URL")
	if public != "" {
		if strings.HasSuffix(public, "/") {
			l.fail("PUBLIC_BASE_URL must not end with a slash")
		} else if origin := l.httpsURL("PUBLIC_BASE_URL", public); origin != "" {
			cfg.PublicBaseURL, _ = url.Parse(origin)
		}
	}

	cfg.TenantID = strings.ToLower(l.required("ENTRA_TENANT_ID"))
	if cfg.TenantID != "" && !uuidPattern.MatchString(cfg.TenantID) {
		l.fail("ENTRA_TENANT_ID must be the tenant's GUID")
	}
	cfg.ClientID = strings.ToLower(l.required("ENTRA_CLIENT_ID"))
	if cfg.ClientID != "" && !uuidPattern.MatchString(cfg.ClientID) {
		l.fail("ENTRA_CLIENT_ID must be the application (client) GUID")
	}
	cfg.ClientSecret = l.secret("ENTRA_CLIENT_SECRET")
	cfg.AuthorityURL = l.httpsURL("ENTRA_AUTHORITY_URL", l.plain("ENTRA_AUTHORITY_URL", DefaultAuthorityURL))
	cfg.GraphURL = l.httpsURL("GRAPH_BASE_URL", l.plain("GRAPH_BASE_URL", DefaultGraphURL))

	windmill := l.required("WINDMILL_INTERNAL_URL")
	if windmill != "" {
		u, err := url.Parse(windmill)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" ||
			(u.Path != "" && u.Path != "/") || u.User != nil {
			l.fail("WINDMILL_INTERNAL_URL must be an http(s) origin")
		} else {
			cfg.WindmillURL = strings.TrimSuffix(u.String(), "/")
		}
	}
	cfg.SuperadminSecret = l.secret("WINDMILL_SUPERADMIN_SECRET")
	cfg.DatabaseURL = l.secret("GATEWAY_DATABASE_URL")

	if key := l.secret("COOKIE_KEY"); key != "" {
		b, err := hex.DecodeString(key)
		if err != nil || len(b) != cookieKeyLen {
			l.fail("COOKIE_KEY_FILE must hold %d random bytes as hex (openssl rand -hex %d)",
				cookieKeyLen, cookieKeyLen)
		} else {
			cfg.CookieKey = b
		}
	}

	if path := l.required("GROUP_MAPPINGS_PATH"); path != "" {
		b, err := env.ReadFile(path)
		if err != nil {
			l.fail("GROUP_MAPPINGS_PATH: cannot read %s", path)
		} else if m, err := ParseMappings(b); err != nil {
			l.fail("GROUP_MAPPINGS_PATH: %v", err)
		} else {
			cfg.Mappings = m
		}
	}

	for _, d := range strings.Split(l.required("ALLOWED_EMAIL_DOMAINS"), ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, "@/ ") || !strings.Contains(d, ".") {
			l.fail("ALLOWED_EMAIL_DOMAINS: invalid domain %q", d)
			continue
		}
		cfg.AllowedDomains = append(cfg.AllowedDomains, d)
	}
	if len(cfg.AllowedDomains) == 0 && l.plain("ALLOWED_EMAIL_DOMAINS", "") != "" {
		l.fail("ALLOWED_EMAIL_DOMAINS lists no domain")
	}

	switch v := l.plain("ADOPT_EXISTING_ACCOUNTS", "false"); v {
	case "true":
		cfg.AdoptExisting = true
	case "false":
	default:
		l.fail("ADOPT_EXISTING_ACCOUNTS must be true or false")
	}

	interval, err := time.ParseDuration(l.plain("RECONCILE_INTERVAL", "15m"))
	if err != nil || interval < minReconcile {
		l.fail("RECONCILE_INTERVAL must be a duration of at least %s", minReconcile)
	}
	cfg.ReconcileInterval = interval

	ttl, err := strconv.Atoi(l.plain("LOGIN_LINK_TTL_SECONDS", "60"))
	if err != nil || ttl < 1 || ttl > maxLoginLinkTTL {
		l.fail("LOGIN_LINK_TTL_SECONDS must be an integer in 1..%d", maxLoginLinkTTL)
	}
	cfg.LoginLinkTTL = ttl

	cfg.ListenAddr = l.plain("LISTEN_ADDR", defaultListenAddr)

	if len(l.errs) > 0 {
		return nil, errors.Join(l.errs...)
	}
	return cfg, nil
}
