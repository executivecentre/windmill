package config

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Role is a workspace role the gateway may grant. `developer` and `operator` are the roles an
// OSS Windmill defines (custom roles need an EE license); `admin` is Windmill's per-workspace
// `is_admin` flag on top of `developer`. Instance superadmin is deliberately not expressible.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleDeveloper Role = "developer"
	RoleOperator  Role = "operator"
)

// Rank orders roles so that, across several mappings to one workspace, the highest wins.
func (r Role) Rank() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleDeveloper:
		return 2
	case RoleOperator:
		return 1
	default:
		return 0
	}
}

// Valid reports whether r is one of the grantable roles.
func (r Role) Valid() bool { return r.Rank() > 0 }

var (
	workspacePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,50}$`)
	groupPattern     = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,50}$`)
	reservedGroups   = map[string]bool{"all": true, "wm_deployers": true}
)

// Mapping is what one Entra group grants in one workspace.
type Mapping struct {
	Workspace string   `yaml:"workspace"`
	Role      Role     `yaml:"role"`
	Groups    []string `yaml:"groups"`
}

// Mappings is keyed by lowercase Entra group object ID.
type Mappings map[string]Mapping

type mappingFile struct {
	GroupMappings map[string]Mapping `yaml:"group_mappings"`
}

// ParseMappings parses and validates the mapping file.
func ParseMappings(b []byte) (Mappings, error) {
	var f mappingFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if len(f.GroupMappings) == 0 {
		return nil, errors.New("group_mappings is empty")
	}
	out := make(Mappings, len(f.GroupMappings))
	var errs []error
	for id, m := range f.GroupMappings {
		key := strings.ToLower(id)
		if !uuidPattern.MatchString(key) {
			errs = append(errs, fmt.Errorf("mapping key %q is not an Entra group object ID", id))
			continue
		}
		if _, dup := out[key]; dup {
			errs = append(errs, fmt.Errorf("group %s is mapped twice", key))
			continue
		}
		if !workspacePattern.MatchString(m.Workspace) {
			errs = append(errs, fmt.Errorf("group %s: invalid workspace %q", key, m.Workspace))
		}
		if m.Workspace == "admins" {
			errs = append(errs, fmt.Errorf("group %s: the admins workspace is reserved for superadmins", key))
		}
		if !m.Role.Valid() {
			errs = append(errs, fmt.Errorf("group %s: role %q is not one of admin, developer, operator", key, m.Role))
		}
		seen := map[string]bool{}
		for _, g := range m.Groups {
			if !groupPattern.MatchString(g) || reservedGroups[g] {
				errs = append(errs, fmt.Errorf("group %s: invalid or reserved Windmill group %q", key, g))
			}
			if seen[g] {
				errs = append(errs, fmt.Errorf("group %s: Windmill group %q listed twice", key, g))
			}
			seen[g] = true
		}
		out[key] = m
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// Grant is the desired state for one workspace.
type Grant struct {
	Role   Role
	Groups []string // sorted, unique
}

// Desired computes workspace grants from the user's (transitive) Entra group IDs: highest
// role wins per workspace, Windmill groups are unioned.
func (m Mappings) Desired(entraGroupIDs []string) map[string]Grant {
	type acc struct {
		role   Role
		groups map[string]bool
	}
	byWorkspace := map[string]*acc{}
	for _, id := range entraGroupIDs {
		mapping, ok := m[strings.ToLower(id)]
		if !ok {
			continue
		}
		a := byWorkspace[mapping.Workspace]
		if a == nil {
			a = &acc{groups: map[string]bool{}}
			byWorkspace[mapping.Workspace] = a
		}
		if mapping.Role.Rank() > a.role.Rank() {
			a.role = mapping.Role
		}
		for _, g := range mapping.Groups {
			a.groups[g] = true
		}
	}
	out := make(map[string]Grant, len(byWorkspace))
	for ws, a := range byWorkspace {
		groups := make([]string, 0, len(a.groups))
		for g := range a.groups {
			groups = append(groups, g)
		}
		sort.Strings(groups)
		out[ws] = Grant{Role: a.role, Groups: groups}
	}
	return out
}
