//! Local patch (local/PATCHES.md): workspace auto-add and auto-invite, which the open-source code
//! leaves as a stub. `edit_auto_invite` is reached through the stub in `workspaces_oss.rs`, which
//! declares this module; `join_auto_invite_workspaces` runs for every new instance account
//! (`insert_account` in `windmill-api/src/users_oss_local.rs`).

use serde_json::{json, Map, Value};
use sqlx::{Acquire, PgConnection, Postgres, Transaction};
use windmill_api_auth::ApiAuthed;
use windmill_audit::{audit_oss::audit_log, ActionKind};
use windmill_common::{
    error::{Error, Result},
    global_settings::AUTOMATE_USERNAME_CREATION_SETTING,
    roles::{default_role_name, workspace_roles, workspace_roles_on, EffectiveRole, OPERATOR_ROLE},
    utils::require_admin,
    worker::CLOUD_HOSTED,
    DB,
};

use crate::workspaces::{EditAutoInvite, BANNED_DOMAINS};

/// The keys of `workspace_settings.auto_invite` that instance-group auto-add owns: every write
/// here keeps them.
const INSTANCE_GROUP_KEYS: [&str; 2] = ["instance_groups", "instance_groups_roles"];

/// A workspace's domain auto-invite: who joins (`domain`, `*` for anyone joining the instance),
/// whether they are added as members or invited, and with which role.
struct DomainSetting {
    domain: String,
    add: bool,
    role: String,
    operator: bool,
}

impl DomainSetting {
    fn mode(&self) -> &'static str {
        if self.add {
            "add"
        } else {
            "invite"
        }
    }
}

pub async fn edit_auto_invite(
    authed: ApiAuthed,
    db: DB,
    w_id: String,
    ea: EditAutoInvite,
) -> Result<String> {
    require_admin(authed.is_admin, &authed.username)?;
    if w_id == "admins" {
        return Err(Error::BadRequest(
            "the admins workspace is reserved for superadmins: nobody joins it automatically"
                .to_string(),
        ));
    }
    // The UI and the settings document turn auto-invite off with a body that names no role.
    let setting = if ea.operator.is_some() || ea.role.is_some() {
        Some(requested_setting(&authed, &db, &w_id, &ea).await?)
    } else {
        None
    };

    let mut tx = db.begin().await?;
    let current = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT auto_invite FROM workspace_settings WHERE workspace_id = $1 FOR UPDATE",
    )
    .bind(&w_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::NotFound(format!("workspace {w_id} not found")))?;
    let mut value: Map<String, Value> = current
        .as_ref()
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(k, _)| INSTANCE_GROUP_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(s) = &setting {
        value.extend([
            ("enabled".to_string(), json!(true)),
            ("domain".to_string(), json!(s.domain)),
            ("operator".to_string(), json!(s.operator)),
            ("role".to_string(), json!(s.role)),
            ("mode".to_string(), json!(s.mode())),
        ]);
    }
    // NULL rather than `{}`: roles.rs counts any object as naming a role.
    let value = if value.is_empty() {
        None
    } else {
        Some(Value::Object(value))
    };
    sqlx::query("UPDATE workspace_settings SET auto_invite = $1 WHERE workspace_id = $2")
        .bind(&value)
        .bind(&w_id)
        .execute(&mut *tx)
        .await?;

    let message = match &setting {
        Some(s) => {
            let (joined, skipped) = apply(&mut tx, &w_id, s, None).await?;
            let verb = if s.add { "added" } else { "invited" };
            let mut message = format!(
                "auto-{} enabled for workspace {w_id}; existing accounts {verb}: {joined}",
                s.mode()
            );
            if skipped > 0 {
                message.push_str(&format!(
                    "; skipped: {skipped} (no instance-wide username, or another member holds it)"
                ));
            }
            message
        }
        None => format!("auto-invite disabled for workspace {w_id}"),
    };
    audit_log(
        &mut *tx,
        &authed,
        "workspaces.edit_auto_invite",
        ActionKind::Update,
        &w_id,
        setting.as_ref().map(|s| s.domain.as_str()),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(message)
}

/// The setting an enabling request asks for. Resolves the role before any transaction opens:
/// `workspace_roles` may take a second pooled connection.
async fn requested_setting(
    authed: &ApiAuthed,
    db: &DB,
    w_id: &str,
    ea: &EditAutoInvite,
) -> Result<DomainSetting> {
    let domain = if ea.invite_all == Some(true) {
        if *CLOUD_HOSTED {
            return Err(Error::BadRequest(
                "invite_all is only available on self-hosted instances".to_string(),
            ));
        }
        "*".to_string()
    } else {
        let domain = email_domain(&authed.email);
        if BANNED_DOMAINS.contains(domain) {
            return Err(Error::BadRequest(format!("domain {domain} is not allowed")));
        }
        domain.to_string()
    };
    let add = ea.auto_add == Some(true);
    if add && !automates_usernames(db).await? {
        return Err(Error::BadRequest(
            "auto-add needs instance-wide usernames: turn on automated username creation in the \
             instance settings"
                .to_string(),
        ));
    }
    let roles = workspace_roles(db, w_id).await?;
    let (role, operator) = resolve_role(
        &roles,
        w_id,
        ea.operator.unwrap_or(false),
        ea.role.as_deref(),
    )?;
    Ok(DomainSetting { domain, add, role, operator })
}

/// The setting `w_id` stores, with its role resolved anew: the role may have changed since.
async fn stored_setting(
    conn: &mut PgConnection,
    w_id: &str,
    stored: &Value,
) -> Result<DomainSetting> {
    let roles = workspace_roles_on(conn, w_id).await?;
    let (role, operator) = resolve_role(
        &roles,
        w_id,
        stored
            .get("operator")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stored.get("role").and_then(Value::as_str),
    )?;
    Ok(DomainSetting {
        domain: stored
            .get("domain")
            .and_then(Value::as_str)
            .unwrap_or("*")
            .to_string(),
        add: stored.get("mode").and_then(Value::as_str) == Some("add"),
        role,
        operator,
    })
}

/// `role`, else the role the legacy `operator` flag names, else the workspace's default, with the
/// `usr.operator` flag that goes with it, as `add_user` resolves a new member's.
fn resolve_role(
    roles: &[EffectiveRole],
    w_id: &str,
    operator: bool,
    role: Option<&str>,
) -> Result<(String, bool)> {
    let name = match role {
        Some(role) => role.to_string(),
        None if operator => OPERATOR_ROLE.to_string(),
        None => default_role_name(roles.iter().map(|r| r.name.as_str())),
    };
    let found = roles.iter().find(|r| r.name == name).ok_or_else(|| {
        Error::BadRequest(format!("role `{name}` is not defined in workspace {w_id}"))
    })?;
    Ok((name, !found.capabilities.code))
}

/// Adds a new instance account to every workspace that auto-adds accounts, and invites it to every
/// one that auto-invites them. It must not fail the account's creation, which SSO sign-in shares:
/// a workspace whose setting cannot be applied (a role since removed, say) is skipped with a
/// warning, each in a savepoint of its own.
pub async fn join_auto_invite_workspaces(
    tx: &mut Transaction<'_, Postgres>,
    email: &str,
) -> Result<()> {
    let workspaces = sqlx::query_as::<_, (String, Value)>(
        "SELECT s.workspace_id, s.auto_invite FROM workspace_settings s
         JOIN workspace w ON w.id = s.workspace_id
         WHERE NOT w.deleted AND s.auto_invite->'enabled' = 'true'::jsonb
           AND COALESCE(s.auto_invite->>'domain', '*') IN ('*', $1)",
    )
    .bind(email_domain(email))
    .fetch_all(&mut **tx)
    .await?;
    for (w_id, stored) in workspaces {
        let mut savepoint = Acquire::begin(&mut *tx).await?;
        match join_one(&mut savepoint, &w_id, &stored, email).await {
            Ok(true) => savepoint.commit().await?,
            Ok(false) => {
                tracing::warn!(
                    "{email} did not join workspace {w_id} automatically: it has no \
                     instance-wide username, or another member holds it"
                );
                savepoint.commit().await?
            }
            Err(e) => {
                tracing::warn!("{email} did not join workspace {w_id} automatically: {e}");
                savepoint.rollback().await?
            }
        }
    }
    Ok(())
}

/// Applies `w_id`'s stored setting to `email`; false when it could not be added.
async fn join_one(
    conn: &mut PgConnection,
    w_id: &str,
    stored: &Value,
    email: &str,
) -> Result<bool> {
    let s = stored_setting(conn, w_id, stored).await?;
    let (_, skipped) = apply(conn, w_id, &s, Some(email)).await?;
    Ok(skipped == 0)
}

/// Applies `s` to the accounts of its domain that are not members of `w_id`, or to `email` alone
/// among them. Returns how many joined and how many could not be added.
async fn apply(
    conn: &mut PgConnection,
    w_id: &str,
    s: &DomainSetting,
    email: Option<&str>,
) -> Result<(u64, u64)> {
    const CANDIDATES: &str = "FROM password p
         WHERE ($2 = '*' OR split_part(p.email, '@', 2) = $2) AND ($3::text IS NULL OR p.email = $3)
           AND NOT EXISTS (SELECT 1 FROM usr WHERE workspace_id = $1 AND email = p.email)";
    if !s.add {
        let invited = sqlx::query(&format!(
            "INSERT INTO workspace_invite (workspace_id, email, is_admin, operator, workspace_role)
             SELECT $1, p.email, false, $4, $5 {CANDIDATES}
             ON CONFLICT (workspace_id, email) DO NOTHING"
        ))
        .bind(w_id)
        .bind(&s.domain)
        .bind(email)
        .bind(s.operator)
        .bind(&s.role)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        return Ok((invited, 0));
    }
    let accounts = sqlx::query_as::<_, (String, Option<String>)>(&format!(
        "SELECT p.email, p.username {CANDIDATES}"
    ))
    .bind(w_id)
    .bind(&s.domain)
    .bind(email)
    .fetch_all(&mut *conn)
    .await?;
    let mut added = 0;
    let mut skipped = 0;
    for (email, username) in accounts {
        let joined = match username {
            Some(username) => add_member(&mut *conn, w_id, &email, &username, s).await?,
            None => false,
        };
        if joined {
            added += 1;
        } else {
            skipped += 1;
        }
    }
    Ok((added, skipped))
}

/// Adds `email` to `w_id` as `add_user` adds a member, marked as auto-added; false when another
/// member holds `username`.
async fn add_member(
    conn: &mut PgConnection,
    w_id: &str,
    email: &str,
    username: &str,
    s: &DomainSetting,
) -> Result<bool> {
    let added = sqlx::query(
        "INSERT INTO usr (workspace_id, email, username, is_admin, operator, workspace_role, added_via)
         SELECT $1, $2, $3, false, $4, $5, jsonb_build_object('source', 'domain', 'domain', $6::text)
         WHERE NOT EXISTS (SELECT 1 FROM usr WHERE workspace_id = $1 AND email = $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(w_id)
    .bind(email)
    .bind(username)
    .bind(s.operator)
    .bind(&s.role)
    .bind(&s.domain)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;
    if added {
        sqlx::query("DELETE FROM workspace_invite WHERE workspace_id = $1 AND email = $2")
            .bind(w_id)
            .bind(email)
            .execute(&mut *conn)
            .await?;
        sqlx::query(
            "INSERT INTO usr_to_group (workspace_id, usr, group_) VALUES ($1, $2, 'all')
             ON CONFLICT DO NOTHING",
        )
        .bind(w_id)
        .bind(username)
        .execute(&mut *conn)
        .await?;
    }
    Ok(added)
}

async fn automates_usernames(db: &DB) -> Result<bool> {
    Ok(
        sqlx::query_scalar::<_, Value>("SELECT value FROM global_settings WHERE name = $1")
            .bind(AUTOMATE_USERNAME_CREATION_SETTING)
            .fetch_optional(db)
            .await?
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
    )
}

fn email_domain(email: &str) -> &str {
    email.rsplit('@').next().unwrap_or_default()
}
