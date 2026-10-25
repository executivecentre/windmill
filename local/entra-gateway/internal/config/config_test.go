package config

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const validMappings = `
group_mappings:
  0A000000-0000-4000-8000-000000000001: {workspace: eng, role: developer, groups: [engineering]}
  0a000000-0000-4000-8000-000000000002: {workspace: eng, role: admin}
  0a000000-0000-4000-8000-000000000003: {workspace: ops, role: operator, groups: [oncall, engineering]}
`

func env(vars map[string]string, files map[string]string) Env {
	return Env{
		Getenv: func(k string) string { return vars[k] },
		ReadFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

func baseVars() (map[string]string, map[string]string) {
	vars := map[string]string{
		"PUBLIC_BASE_URL":                 "https://windmill.corp.example",
		"ENTRA_TENANT_ID":                 "11111111-2222-3333-4444-555555555555",
		"ENTRA_CLIENT_ID":                 "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
		"ENTRA_CLIENT_SECRET_FILE":        "/s/client",
		"WINDMILL_INTERNAL_URL":           "http://windmill_server:8000",
		"WINDMILL_SUPERADMIN_SECRET_FILE": "/s/super",
		"GATEWAY_DATABASE_URL_FILE":       "/s/db",
		"COOKIE_KEY_FILE":                 "/s/cookie",
		"GROUP_MAPPINGS_PATH":             "/etc/map.yaml",
		"ALLOWED_EMAIL_DOMAINS":           "Corp.Example, sub.corp.example",
	}
	files := map[string]string{
		"/s/client": "client-secret\n", "/s/super": "super\n", "/s/db": "postgres://x@db/entra_gateway\n",
		"/s/cookie": strings.Repeat("ab", 32) + "\n", "/etc/map.yaml": validMappings,
	}
	return vars, files
}

func TestLoadValid(t *testing.T) {
	vars, files := baseVars()
	cfg, err := Load(env(vars, files))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientSecret != "client-secret" || len(cfg.CookieKey) != 32 || cfg.ClientID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("secrets/ids not normalised: %+v", cfg)
	}
	if cfg.Issuer() != "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0" {
		t.Fatalf("issuer %s", cfg.Issuer())
	}
	if cfg.RedirectURL() != "https://windmill.corp.example/sso/callback" {
		t.Fatalf("redirect %s", cfg.RedirectURL())
	}
	if cfg.ReconcileInterval != 15*time.Minute || cfg.LoginLinkTTL != 60 || cfg.AdoptExisting {
		t.Fatalf("defaults %+v", cfg)
	}
	if !cfg.DomainAllowed("a@corp.example") || !cfg.DomainAllowed("a@SUB.corp.example") ||
		cfg.DomainAllowed("a@evilcorp.example") || cfg.DomainAllowed("a@corp.example.evil") || cfg.DomainAllowed("corp.example") {
		t.Fatal("domain matching")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]func(v, f map[string]string){
		"http public URL":      func(v, _ map[string]string) { v["PUBLIC_BASE_URL"] = "http://windmill.corp.example" },
		"public URL with path": func(v, _ map[string]string) { v["PUBLIC_BASE_URL"] = "https://windmill.corp.example/app" },
		"trailing slash":       func(v, _ map[string]string) { v["PUBLIC_BASE_URL"] = "https://windmill.corp.example/" },
		"tenant not a GUID":    func(v, _ map[string]string) { v["ENTRA_TENANT_ID"] = "common" },
		"secret and file":      func(v, _ map[string]string) { v["ENTRA_CLIENT_SECRET"] = "inline" },
		"missing secret":       func(v, _ map[string]string) { delete(v, "WINDMILL_SUPERADMIN_SECRET_FILE") },
		"unreadable secret":    func(_, f map[string]string) { delete(f, "/s/db") },
		"empty secret":         func(_, f map[string]string) { f["/s/client"] = "\n" },
		"short cookie key":     func(_, f map[string]string) { f["/s/cookie"] = "abcd" },
		"http authority":       func(v, _ map[string]string) { v["ENTRA_AUTHORITY_URL"] = "http://login.example" },
		"no domains":           func(v, _ map[string]string) { v["ALLOWED_EMAIL_DOMAINS"] = " , " },
		"bad domain":           func(v, _ map[string]string) { v["ALLOWED_EMAIL_DOMAINS"] = "@corp.example" },
		"bad adopt":            func(v, _ map[string]string) { v["ADOPT_EXISTING_ACCOUNTS"] = "yes" },
		"reconcile too often":  func(v, _ map[string]string) { v["RECONCILE_INTERVAL"] = "10s" },
		"login link ttl":       func(v, _ map[string]string) { v["LOGIN_LINK_TTL_SECONDS"] = "901" },
		"windmill URL path":    func(v, _ map[string]string) { v["WINDMILL_INTERNAL_URL"] = "http://windmill_server:8000/api" },
		"mapping file missing": func(_, f map[string]string) { delete(f, "/etc/map.yaml") },
		"mapping unknown key": func(_, f map[string]string) {
			f["/etc/map.yaml"] = "group_mappings:\n  0a000000-0000-4000-8000-000000000001: {workspace: eng, role: developer, superadmin: true}\n"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			vars, files := baseVars()
			mutate(vars, files)
			if _, err := Load(env(vars, files)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	_, err := Load(env(map[string]string{}, nil))
	if err == nil {
		t.Fatal("empty environment accepted")
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) || len(joined.Unwrap()) < 8 {
		t.Fatalf("expected every missing variable to be reported, got: %v", err)
	}
}

func TestParseMappingsRejects(t *testing.T) {
	cases := map[string]string{
		"not a uuid":         "group_mappings:\n  engineers: {workspace: eng, role: developer}\n",
		"superadmin role":    "group_mappings:\n  0a000000-0000-4000-8000-000000000001: {workspace: eng, role: superadmin}\n",
		"admins workspace":   "group_mappings:\n  0a000000-0000-4000-8000-000000000001: {workspace: admins, role: admin}\n",
		"bad workspace":      "group_mappings:\n  0a000000-0000-4000-8000-000000000001: {workspace: 'a/b', role: admin}\n",
		"reserved group all": "group_mappings:\n  0a000000-0000-4000-8000-000000000001: {workspace: eng, role: admin, groups: [all]}\n",
		"wm_deployers":       "group_mappings:\n  0a000000-0000-4000-8000-000000000001: {workspace: eng, role: admin, groups: [wm_deployers]}\n",
		"duplicate by case": "group_mappings:\n  0a000000-0000-4000-8000-00000000000a: {workspace: eng, role: admin}\n" +
			"  0A000000-0000-4000-8000-00000000000A: {workspace: ops, role: admin}\n",
		"empty": "group_mappings: {}\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMappings([]byte(doc)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestExampleMappingsParse(t *testing.T) {
	doc, err := os.ReadFile("../../group-mappings.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMappings(doc); err != nil {
		t.Fatal(err)
	}
}

func TestDesiredHighestRoleWinsAndGroupsUnion(t *testing.T) {
	m, err := ParseMappings([]byte(validMappings))
	if err != nil {
		t.Fatal(err)
	}
	got := m.Desired([]string{"0A000000-0000-4000-8000-000000000001", "0a000000-0000-4000-8000-000000000002",
		"0a000000-0000-4000-8000-000000000003", "ffffffff-0000-4000-8000-000000000000"})
	if g := got["eng"]; g.Role != RoleAdmin || strings.Join(g.Groups, ",") != "engineering" {
		t.Fatalf("eng %+v", g)
	}
	if g := got["ops"]; g.Role != RoleOperator || strings.Join(g.Groups, ",") != "engineering,oncall" {
		t.Fatalf("ops %+v", g)
	}
	if len(m.Desired(nil)) != 0 {
		t.Fatal("no groups must grant nothing")
	}
}
