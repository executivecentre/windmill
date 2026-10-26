// Package sync turns an Entra identity and its Graph group memberships into a Windmill account,
// workspace memberships and Windmill group memberships, at sign-in and on a schedule.
package sync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"entra-gateway/internal/config"
	"entra-gateway/internal/graph"
	"entra-gateway/internal/oidc"
	"entra-gateway/internal/store"
	"entra-gateway/internal/windmill"
)

// Deny reasons, shown to the user as a short explanation.
const (
	ReasonGraphUnavailable  = "graph_unavailable"
	ReasonUserNotFound      = "user_not_found"
	ReasonAccountDisabled   = "account_disabled"
	ReasonDomainNotAllowed  = "domain_not_allowed"
	ReasonNoAccess          = "no_access"
	ReasonEmailConflict     = "email_conflict"
	ReasonExistingAccount   = "existing_account"
	ReasonPrivilegedAccount = "privileged_account"
	ReasonDisabledByAdmin   = "disabled_by_admin"
	ReasonLoginTypeChanged  = "login_type_changed"
)

// DenyError refuses a sign-in for a reason the user may be told.
type DenyError struct{ Reason string }

func (e *DenyError) Error() string { return "sign-in denied: " + e.Reason }

func deny(reason string) error { return &DenyError{Reason: reason} }

// Settings are the engine's policy inputs.
type Settings struct {
	Mappings      config.Mappings
	DomainAllowed func(email string) bool
	AdoptExisting bool
}

// Engine applies Entra state to Windmill.
type Engine struct {
	s     Settings
	graph *graph.Client
	wm    *windmill.Client
	store *store.Store
	log   *slog.Logger
}

// New builds an engine.
func New(s Settings, g *graph.Client, wm *windmill.Client, st *store.Store, log *slog.Logger) *Engine {
	return &Engine{s: s, graph: g, wm: wm, store: st, log: log}
}

// Login provisions and synchronises the identity and returns the Windmill e-mail to sign in.
// Any error means the sign-in must be refused; a *DenyError carries a user-facing reason.
func (e *Engine) Login(ctx context.Context, id oidc.Identity) (string, error) {
	user, groups, err := e.graph.Lookup(ctx, id.ObjectID)
	if err != nil && !errors.Is(err, graph.ErrNotFound) {
		e.log.Warn("graph lookup failed", "oid", id.ObjectID, "err", err)
		return "", deny(ReasonGraphUnavailable)
	}
	return e.syncIdentity(ctx, id, user, groups, true)
}

// syncIdentity runs under the identity lock. user is nil when Graph has no such user.
func (e *Engine) syncIdentity(ctx context.Context, id oidc.Identity, user *graph.User, groups []string, signIn bool) (string, error) {
	var email string
	err := e.store.WithIdentityLock(ctx, id.TenantID, id.ObjectID, func(ctx context.Context) error {
		ident, err := e.store.GetIdentity(ctx, id.TenantID, id.ObjectID)
		if err != nil {
			return err
		}
		if reason := e.entraRefusal(user); reason != "" {
			if ident != nil {
				// The account first, so a failing revoke cannot leave it signed in. Windmill
				// keeps running a disabled account's schedules and triggers; only a disabled
				// workspace membership stops them. Both steps are idempotent across retries.
				if err := e.disableAccount(ctx, ident, reason); err != nil {
					return err
				}
				if err := e.apply(ctx, ident, nil); err != nil {
					return err
				}
			}
			return deny(reason)
		}
		desired := e.s.Mappings.Desired(groups)
		if ident == nil {
			if !signIn {
				return errors.New("identity vanished during reconcile")
			}
			if len(desired) == 0 {
				return deny(ReasonNoAccess)
			}
			if ident, err = e.link(ctx, id, user); err != nil {
				return err
			}
		} else if err := e.checkLinked(ctx, ident, user); err != nil {
			return err
		}
		if err := e.apply(ctx, ident, desired); err != nil {
			return err
		}
		if err := e.store.TouchIdentity(ctx, id.TenantID, id.ObjectID, user.UPN); err != nil {
			return err
		}
		if len(desired) == 0 {
			return deny(ReasonNoAccess)
		}
		email = ident.Email
		return nil
	})
	return email, err
}

// entraRefusal is the reason Entra state alone forbids access, or "".
func (e *Engine) entraRefusal(user *graph.User) string {
	switch {
	case user == nil:
		return ReasonUserNotFound
	case !user.AccountEnabled:
		return ReasonAccountDisabled
	case !e.s.DomainAllowed(user.Email()):
		return ReasonDomainNotAllowed
	}
	return ""
}

// link creates (or, when allowed, adopts) the Windmill account for a first sign-in.
func (e *Engine) link(ctx context.Context, id oidc.Identity, user *graph.User) (*store.Identity, error) {
	email := user.Email()
	other, err := e.store.IdentityByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if other != nil {
		// The address belongs to another Entra object: never hand that account over.
		e.event(ctx, id.ObjectID, "denied", map[string]any{"reason": ReasonEmailConflict})
		return nil, deny(ReasonEmailConflict)
	}
	existing, err := e.wm.GlobalUser(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		err := e.wm.CreateUser(ctx, email, user.DisplayName)
		switch {
		case errors.Is(err, windmill.ErrConflict):
			if existing, err = e.wm.GlobalUser(ctx, email); err != nil {
				return nil, err
			}
			if existing == nil {
				return nil, errors.New("windmill reported a conflict for an account it does not list")
			}
		case err != nil:
			return nil, err
		default:
			e.event(ctx, id.ObjectID, "account_created", nil)
		}
	}
	if existing != nil {
		if err := e.adopt(ctx, id, existing); err != nil {
			return nil, err
		}
	}
	ident := store.Identity{TenantID: id.TenantID, ObjectID: id.ObjectID, Email: email, LastUPN: user.UPN}
	if err := e.store.InsertIdentity(ctx, ident); err != nil {
		return nil, err
	}
	return &ident, nil
}

// adopt decides whether a pre-existing, unlinked Windmill account may be linked.
func (e *Engine) adopt(ctx context.Context, id oidc.Identity, gu *windmill.GlobalUser) error {
	refuse := func(reason string) error {
		e.event(ctx, id.ObjectID, "denied", map[string]any{"reason": reason})
		return deny(reason)
	}
	switch {
	case gu.SuperAdmin || gu.Devops:
		return refuse(ReasonPrivilegedAccount)
	case !e.s.AdoptExisting:
		return refuse(ReasonExistingAccount)
	case gu.Disabled:
		return refuse(ReasonDisabledByAdmin)
	}
	if gu.LoginType != windmill.LoginType {
		// Switching to `entra` also ends password sign-in for the account.
		if err := e.wm.SetLoginType(ctx, gu.Email, windmill.LoginType); err != nil {
			return err
		}
	}
	e.event(ctx, id.ObjectID, "account_adopted", map[string]any{"previous_login_type": gu.LoginType})
	return nil
}

// checkLinked verifies the linked account is still one the gateway may sign in, re-enabling
// it only if the gateway itself disabled it.
func (e *Engine) checkLinked(ctx context.Context, ident *store.Identity, user *graph.User) error {
	gu, err := e.wm.GlobalUser(ctx, ident.Email)
	if err != nil {
		return err
	}
	if gu == nil {
		if err := e.wm.CreateUser(ctx, ident.Email, user.DisplayName); err != nil {
			return err
		}
		e.event(ctx, ident.ObjectID, "account_recreated", nil)
		return nil
	}
	switch {
	case gu.SuperAdmin || gu.Devops:
		e.log.Warn("linked account was given instance privileges; refusing SSO", "oid", ident.ObjectID)
		return deny(ReasonPrivilegedAccount)
	case gu.LoginType != windmill.LoginType:
		e.log.Warn("linked account login type changed; refusing SSO", "oid", ident.ObjectID, "login_type", gu.LoginType)
		return deny(ReasonLoginTypeChanged)
	case gu.Disabled && !ident.DisabledByGateway:
		return deny(ReasonDisabledByAdmin)
	case gu.Disabled:
		if err := e.wm.SetDisabled(ctx, ident.Email, false); err != nil {
			return err
		}
		if err := e.store.SetIdentityDisabled(ctx, ident.TenantID, ident.ObjectID, false); err != nil {
			return err
		}
		ident.DisabledByGateway = false
		e.event(ctx, ident.ObjectID, "account_reenabled", nil)
	}
	return nil
}

// disableAccount turns off the Windmill account (ending every session and token) unless an
// administrator already did; only a gateway-made disable is ever undone by the gateway.
func (e *Engine) disableAccount(ctx context.Context, ident *store.Identity, reason string) error {
	gu, err := e.wm.GlobalUser(ctx, ident.Email)
	if err != nil {
		return err
	}
	if gu == nil || gu.Disabled {
		return nil
	}
	if gu.SuperAdmin || gu.Devops {
		e.log.Warn("not disabling an account with instance privileges", "oid", ident.ObjectID)
		return nil
	}
	if err := e.wm.SetDisabled(ctx, ident.Email, true); err != nil {
		return err
	}
	if err := e.store.SetIdentityDisabled(ctx, ident.TenantID, ident.ObjectID, true); err != nil {
		return err
	}
	e.event(ctx, ident.ObjectID, "account_disabled", map[string]any{"reason": reason})
	return nil
}

// event records an audit entry; a failure to record is logged, never fatal.
func (e *Engine) event(ctx context.Context, oid, action string, detail map[string]any) {
	if err := e.store.Event(ctx, oid, action, detail); err != nil {
		e.log.Error("recording sync event failed", "oid", oid, "action", action, "err", err)
		return
	}
	attrs := []any{"oid", oid, "action", action}
	for k, v := range detail {
		attrs = append(attrs, k, fmt.Sprint(v))
	}
	e.log.Info("sync", attrs...)
}

// eventOnce records an event at most once per identity, action and workspace.
func (e *Engine) eventOnce(ctx context.Context, oid, action, workspace string) {
	seen, err := e.store.HasEvent(ctx, oid, action, workspace)
	if err != nil {
		e.log.Error("reading sync events failed", "oid", oid, "err", err)
		return
	}
	if !seen {
		e.event(ctx, oid, action, map[string]any{"workspace": workspace})
	}
}
