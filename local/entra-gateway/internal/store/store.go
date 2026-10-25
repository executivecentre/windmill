// Package store holds the gateway's own state in its own Postgres database.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// migrationLockKey serialises migration runs across gateway replicas.
	migrationLockKey = 0x656e747261 // "entra"
	// minConns: every identity lock pins one connection while its writes need another, so
	// the pool must comfortably exceed reconciler concurrency plus concurrent logins.
	minConns = 20
)

// Store wraps the connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects and pings.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, errors.New("store: invalid GATEWAY_DATABASE_URL")
	}
	if cfg.MaxConns < minConns {
		cfg.MaxConns = minConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping checks the database is reachable.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Migrate applies every *.sql file of fsys not yet recorded in schema_migrations, in name
// order, in one transaction.
func (s *Store) Migrate(ctx context.Context, fsys fs.FS) error {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return fmt.Errorf("store: list migrations: %w", err)
	}
	sort.Strings(names)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("store: migration lock: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("store: schema_migrations: %w", err)
	}
	for _, name := range names {
		var done bool
		if err := tx.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)", name).Scan(&done); err != nil {
			return fmt.Errorf("store: check %s: %w", name, err)
		}
		if done {
			continue
		}
		sql, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("store: read %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("store: apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", name); err != nil {
			return fmt.Errorf("store: record %s: %w", name, err)
		}
	}
	return tx.Commit(ctx)
}

// WithIdentityLock runs fn while holding a transaction-scoped advisory lock for one Entra
// identity, so a login and the reconciler (or two first logins) never interleave for it.
// fn's own writes go through the pool and commit independently: a Windmill change that has
// happened must stay recorded even if a later step fails.
func (s *Store) WithIdentityLock(ctx context.Context, tenantID, objectID string, fn func(context.Context) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
		tenantID+"/"+objectID); err != nil {
		return fmt.Errorf("store: identity lock: %w", err)
	}
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Identity links an Entra (tenant, object) pair to one Windmill account.
type Identity struct {
	TenantID          string
	ObjectID          string
	Email             string
	LastUPN           string
	DisabledByGateway bool
}

const identityCols = "tenant_id::text, object_id::text, windmill_email, coalesce(last_upn, ''), disabled_by_gateway"

func scanIdentity(row pgx.Row) (*Identity, error) {
	var id Identity
	if err := row.Scan(&id.TenantID, &id.ObjectID, &id.Email, &id.LastUPN, &id.DisabledByGateway); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &id, nil
}

// GetIdentity returns the identity or nil.
func (s *Store) GetIdentity(ctx context.Context, tenantID, objectID string) (*Identity, error) {
	id, err := scanIdentity(s.pool.QueryRow(ctx,
		"SELECT "+identityCols+" FROM identity WHERE tenant_id = $1 AND object_id = $2", tenantID, objectID))
	if err != nil {
		return nil, fmt.Errorf("store: get identity: %w", err)
	}
	return id, nil
}

// IdentityByEmail returns the identity linked to a Windmill account, or nil.
func (s *Store) IdentityByEmail(ctx context.Context, email string) (*Identity, error) {
	id, err := scanIdentity(s.pool.QueryRow(ctx,
		"SELECT "+identityCols+" FROM identity WHERE windmill_email = $1", email))
	if err != nil {
		return nil, fmt.Errorf("store: identity by email: %w", err)
	}
	return id, nil
}

// InsertIdentity records a new link.
func (s *Store) InsertIdentity(ctx context.Context, id Identity) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO identity
		(tenant_id, object_id, windmill_email, last_upn, last_seen_at) VALUES ($1, $2, $3, $4, now())`,
		id.TenantID, id.ObjectID, id.Email, id.LastUPN)
	if err != nil {
		return fmt.Errorf("store: insert identity: %w", err)
	}
	return nil
}

// TouchIdentity records a sign-in and the UPN Graph returned.
func (s *Store) TouchIdentity(ctx context.Context, tenantID, objectID, upn string) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE identity SET last_upn = $3, last_seen_at = now() WHERE tenant_id = $1 AND object_id = $2",
		tenantID, objectID, upn)
	if err != nil {
		return fmt.Errorf("store: touch identity: %w", err)
	}
	return nil
}

// SetIdentityDisabled records whether the gateway disabled the Windmill account.
func (s *Store) SetIdentityDisabled(ctx context.Context, tenantID, objectID string, disabled bool) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE identity SET disabled_by_gateway = $3 WHERE tenant_id = $1 AND object_id = $2",
		tenantID, objectID, disabled)
	if err != nil {
		return fmt.Errorf("store: set identity disabled: %w", err)
	}
	return nil
}

// ListIdentities returns every linked identity.
func (s *Store) ListIdentities(ctx context.Context) ([]Identity, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+identityCols+" FROM identity ORDER BY created_at")
	if err != nil {
		return nil, fmt.Errorf("store: list identities: %w", err)
	}
	defer rows.Close()
	var out []Identity
	for rows.Next() {
		id, err := scanIdentity(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list identities: %w", err)
		}
		out = append(out, *id)
	}
	return out, rows.Err()
}

// Membership is a workspace membership the gateway created.
type Membership struct {
	Role              string
	DisabledByGateway bool
}

// Memberships returns the managed memberships of one identity, by workspace.
func (s *Store) Memberships(ctx context.Context, objectID string) (map[string]Membership, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT workspace, role, disabled_by_gateway FROM managed_membership WHERE object_id = $1", objectID)
	if err != nil {
		return nil, fmt.Errorf("store: memberships: %w", err)
	}
	defer rows.Close()
	out := map[string]Membership{}
	for rows.Next() {
		var ws string
		var m Membership
		if err := rows.Scan(&ws, &m.Role, &m.DisabledByGateway); err != nil {
			return nil, fmt.Errorf("store: memberships: %w", err)
		}
		out[ws] = m
	}
	return out, rows.Err()
}

// PutMembership inserts or replaces a managed membership.
func (s *Store) PutMembership(ctx context.Context, objectID, workspace string, m Membership) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO managed_membership (object_id, workspace, role, disabled_by_gateway)
		VALUES ($1, $2, $3, $4) ON CONFLICT (object_id, workspace)
		DO UPDATE SET role = EXCLUDED.role, disabled_by_gateway = EXCLUDED.disabled_by_gateway`,
		objectID, workspace, m.Role, m.DisabledByGateway)
	if err != nil {
		return fmt.Errorf("store: put membership: %w", err)
	}
	return nil
}

// GroupMemberships returns managed Windmill group memberships: workspace -> group set.
func (s *Store) GroupMemberships(ctx context.Context, objectID string) (map[string]map[string]bool, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT workspace, grp FROM managed_group_membership WHERE object_id = $1", objectID)
	if err != nil {
		return nil, fmt.Errorf("store: group memberships: %w", err)
	}
	defer rows.Close()
	out := map[string]map[string]bool{}
	for rows.Next() {
		var ws, grp string
		if err := rows.Scan(&ws, &grp); err != nil {
			return nil, fmt.Errorf("store: group memberships: %w", err)
		}
		if out[ws] == nil {
			out[ws] = map[string]bool{}
		}
		out[ws][grp] = true
	}
	return out, rows.Err()
}

// AddGroupMembership records a group membership the gateway added.
func (s *Store) AddGroupMembership(ctx context.Context, objectID, workspace, grp string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO managed_group_membership (object_id, workspace, grp)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, objectID, workspace, grp)
	if err != nil {
		return fmt.Errorf("store: add group membership: %w", err)
	}
	return nil
}

// DeleteGroupMembership forgets a group membership the gateway removed.
func (s *Store) DeleteGroupMembership(ctx context.Context, objectID, workspace, grp string) error {
	_, err := s.pool.Exec(ctx,
		"DELETE FROM managed_group_membership WHERE object_id = $1 AND workspace = $2 AND grp = $3",
		objectID, workspace, grp)
	if err != nil {
		return fmt.Errorf("store: delete group membership: %w", err)
	}
	return nil
}

// Event appends to the audit trail. detail must never contain tokens or secrets.
func (s *Store) Event(ctx context.Context, objectID, action string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	b, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("store: event detail: %w", err)
	}
	var oid any
	if objectID != "" {
		oid = objectID
	}
	if _, err := s.pool.Exec(ctx,
		"INSERT INTO sync_event (object_id, action, detail) VALUES ($1, $2, $3)", oid, action, b); err != nil {
		return fmt.Errorf("store: event: %w", err)
	}
	return nil
}

// HasEvent reports whether an event with this action and workspace was already recorded.
func (s *Store) HasEvent(ctx context.Context, objectID, action, workspace string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sync_event
		WHERE object_id = $1 AND action = $2 AND detail->>'workspace' = $3)`,
		objectID, action, workspace).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("store: has event: %w", err)
	}
	return ok, nil
}

// Events returns "action" or "action:workspace" for an identity, oldest first.
func (s *Store) Events(ctx context.Context, objectID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT action || coalesce(':' || (detail->>'workspace'), '') FROM sync_event WHERE object_id = $1 ORDER BY id",
		objectID)
	if err != nil {
		return nil, fmt.Errorf("store: events: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, fmt.Errorf("store: events: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
