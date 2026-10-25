package sync

import (
	"context"
	"errors"
	"slices"
	"sort"

	"entra-gateway/internal/config"
	"entra-gateway/internal/store"
	"entra-gateway/internal/windmill"
)

func windmillRole(r config.Role) windmill.Role {
	switch r {
	case config.RoleAdmin:
		return windmill.Role{IsAdmin: true, Name: "developer"}
	case config.RoleOperator:
		return windmill.Role{Operator: true, Name: "operator"}
	default:
		return windmill.Role{Name: "developer"}
	}
}

// apply makes the identity's workspace and group memberships match desired. It only ever
// changes memberships the gateway created: a membership someone else made is left alone.
func (e *Engine) apply(ctx context.Context, ident *store.Identity, desired map[string]config.Grant) error {
	managed, err := e.store.Memberships(ctx, ident.ObjectID)
	if err != nil {
		return err
	}
	managedGroups, err := e.store.GroupMemberships(ctx, ident.ObjectID)
	if err != nil {
		return err
	}

	workspaces := make([]string, 0, len(desired))
	for ws := range desired {
		workspaces = append(workspaces, ws)
	}
	sort.Strings(workspaces)
	for _, ws := range workspaces {
		if err := e.grant(ctx, ident, ws, desired[ws], managed, managedGroups[ws]); err != nil {
			return err
		}
	}

	for ws, m := range managed {
		if _, keep := desired[ws]; keep {
			continue
		}
		if err := e.revoke(ctx, ident, ws, m, managedGroups[ws]); err != nil {
			return err
		}
	}
	return nil
}

// grant brings one desired workspace up to date.
func (e *Engine) grant(ctx context.Context, ident *store.Identity, ws string, g config.Grant,
	managed map[string]store.Membership, managedGroups map[string]bool) error {
	exists, err := e.wm.WorkspaceExists(ctx, ws)
	if err != nil {
		return err
	}
	if !exists {
		e.eventOnce(ctx, ident.ObjectID, "workspace_missing", ws)
		return nil
	}
	role := windmillRole(g.Role)
	m, isManaged := managed[ws]
	member, err := e.wm.WorkspaceUser(ctx, ws, ident.Email)
	if err != nil {
		return err
	}
	switch {
	case member == nil:
		if err := e.wm.AddWorkspaceUser(ctx, ws, ident.Email, role); err != nil {
			return err
		}
		if err := e.store.PutMembership(ctx, ident.ObjectID, ws, store.Membership{Role: string(g.Role)}); err != nil {
			return err
		}
		e.event(ctx, ident.ObjectID, "membership_added", map[string]any{"workspace": ws, "role": string(g.Role)})
		if member, err = e.wm.WorkspaceUser(ctx, ws, ident.Email); err != nil {
			return err
		}
		if member == nil {
			return errors.New("windmill does not list a member it just added")
		}
	case !isManaged:
		e.eventOnce(ctx, ident.ObjectID, "unmanaged_membership", ws)
		return nil
	default:
		// A membership an administrator disabled stays disabled; the gateway re-enables only
		// what it disabled itself.
		disabled := member.Disabled && !m.DisabledByGateway
		if member.RoleName() != string(g.Role) || member.Disabled != disabled {
			if err := e.wm.UpdateWorkspaceUser(ctx, ws, member.Username, role, disabled); err != nil {
				return err
			}
			e.event(ctx, ident.ObjectID, "membership_updated", map[string]any{
				"workspace": ws, "role": string(g.Role), "disabled": disabled})
		}
		if m.Role != string(g.Role) || m.DisabledByGateway {
			if err := e.store.PutMembership(ctx, ident.ObjectID, ws, store.Membership{Role: string(g.Role)}); err != nil {
				return err
			}
		}
	}
	return e.syncGroups(ctx, ident, ws, member.Username, g.Groups, managedGroups)
}

// syncGroups adds the desired Windmill groups and removes managed ones no longer desired.
func (e *Engine) syncGroups(ctx context.Context, ident *store.Identity, ws, username string,
	want []string, managedGroups map[string]bool) error {
	for _, grp := range want {
		members, err := e.wm.GroupMembers(ctx, ws, grp)
		if errors.Is(err, windmill.ErrNotFound) {
			if err := e.wm.CreateGroup(ctx, ws, grp); err != nil {
				return err
			}
			e.event(ctx, ident.ObjectID, "group_created", map[string]any{"workspace": ws, "group": grp})
			members, err = nil, nil
		}
		if err != nil {
			return err
		}
		if slices.Contains(members, username) {
			continue
		}
		if err := e.wm.AddGroupMember(ctx, ws, grp, username); err != nil {
			return err
		}
		if err := e.store.AddGroupMembership(ctx, ident.ObjectID, ws, grp); err != nil {
			return err
		}
		e.event(ctx, ident.ObjectID, "group_member_added", map[string]any{"workspace": ws, "group": grp})
	}
	for grp := range managedGroups {
		if slices.Contains(want, grp) {
			continue
		}
		if err := e.removeGroup(ctx, ident, ws, grp, username); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) removeGroup(ctx context.Context, ident *store.Identity, ws, grp, username string) error {
	err := e.wm.RemoveGroupMember(ctx, ws, grp, username)
	if err != nil && !errors.Is(err, windmill.ErrNotFound) {
		return err
	}
	if err := e.store.DeleteGroupMembership(ctx, ident.ObjectID, ws, grp); err != nil {
		return err
	}
	e.event(ctx, ident.ObjectID, "group_member_removed", map[string]any{"workspace": ws, "group": grp})
	return nil
}

// revoke disables a managed membership the identity no longer qualifies for and removes its
// managed group memberships. Disabling rather than removing keeps the member's history and
// ownership intact for administrators.
func (e *Engine) revoke(ctx context.Context, ident *store.Identity, ws string, m store.Membership,
	managedGroups map[string]bool) error {
	member, err := e.wm.WorkspaceUser(ctx, ws, ident.Email)
	if errors.Is(err, windmill.ErrNotFound) {
		member, err = nil, nil // workspace deleted
	}
	if err != nil {
		return err
	}
	if member != nil {
		for grp := range managedGroups {
			if err := e.removeGroup(ctx, ident, ws, grp, member.Username); err != nil {
				return err
			}
		}
		if !member.Disabled {
			if err := e.wm.DisableWorkspaceUser(ctx, ws, member.Username); err != nil {
				return err
			}
		}
	}
	if m.DisabledByGateway {
		return nil
	}
	if err := e.store.PutMembership(ctx, ident.ObjectID, ws, store.Membership{Role: m.Role, DisabledByGateway: true}); err != nil {
		return err
	}
	e.event(ctx, ident.ObjectID, "membership_disabled", map[string]any{"workspace": ws})
	return nil
}
