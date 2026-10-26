//! Local patch (local/PATCHES.md): OSS implementations of create_user, set_password and
//! hash_password, reached through one-line delegations in the stubs of `users_oss.rs`, which
//! declares this module. Callers in `users.rs` own job-token checks, session deletion and MCP
//! grant revocation; these functions own authorization, validation and the `password` row.

use std::sync::Arc;

use argon2::{Argon2, PasswordHasher};
use http::StatusCode;
use windmill_api_auth::require_super_admin;
use windmill_audit::{audit_oss::audit_log, ActionKind};
use windmill_common::{
    error::{Error, Result},
    global_settings::AUTOMATE_USERNAME_CREATION_SETTING,
    oauth2::InstanceEvent,
    usernames::generate_instance_wide_unique_username,
    users::{has_any_account, usr_accepts_email, PENDING_OAUTH_LOGIN_TYPE, VALID_EMAIL},
};

use crate::db::{ApiAuthed, DB};
use crate::users::{EditPassword, NewUser};
use crate::webhook_util::WebhookShared;

const MIN_PASSWORD_LEN: usize = 12;

const PASSWORD_LOGIN_TYPE: &str = "password";

/// `entra` accounts are owned by the Entra ID gateway; this build has no other identity provider.
const CREATABLE_LOGIN_TYPES: [&str; 3] = [PASSWORD_LOGIN_TYPE, PENDING_OAUTH_LOGIN_TYPE, "entra"];

fn validate_login_type(login_type: &str) -> Result<()> {
    if CREATABLE_LOGIN_TYPES.contains(&login_type) {
        Ok(())
    } else {
        Err(Error::BadRequest(format!(
            "invalid login_type: expected one of {}",
            CREATABLE_LOGIN_TYPES.join(", ")
        )))
    }
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == "23505")
}

fn account_exists(email: &str) -> Error {
    Error::Generic(
        StatusCode::CONFLICT,
        format!("an account already exists for {email}"),
    )
}

pub(super) async fn create_user(
    authed: ApiAuthed,
    db: DB,
    webhook: WebhookShared,
    argon2: Arc<Argon2<'_>>,
    nu: NewUser,
) -> Result<(StatusCode, String)> {
    require_super_admin(&db, &authed).await?;

    let email = nu.email.trim().to_lowercase();
    if !VALID_EMAIL.is_match(&email) || !usr_accepts_email(&db, &email).await? {
        return Err(Error::BadRequest(format!("invalid email: {email}")));
    }

    let login_type = nu
        .login_type
        .as_deref()
        .unwrap_or(PASSWORD_LOGIN_TYPE)
        .to_string();
    validate_login_type(&login_type)?;

    let password_hash = match (login_type.as_str(), nu.password) {
        (PASSWORD_LOGIN_TYPE, Some(password)) => Some(hash_password(argon2, password)?),
        (PASSWORD_LOGIN_TYPE, None) => {
            return Err(Error::BadRequest(
                "password is required for login_type password".to_string(),
            ))
        }
        (_, Some(_)) => {
            return Err(Error::BadRequest(format!(
                "a password cannot be set for login_type {login_type}"
            )))
        }
        (_, None) => None,
    };

    let mut tx = db.begin().await?;

    if has_any_account(&mut *tx, &email).await? {
        return Err(account_exists(&email));
    }

    let automate_username_creation = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM global_settings WHERE name = $1",
    )
    .bind(AUTOMATE_USERNAME_CREATION_SETTING)
    .fetch_optional(&mut *tx)
    .await?
    .and_then(|v| v.as_bool())
    .unwrap_or(true);

    let username = if automate_username_creation {
        let pending =
            sqlx::query_scalar::<_, String>("SELECT username FROM pending_user WHERE email = $1")
                .bind(&email)
                .fetch_optional(&mut *tx)
                .await?;
        match pending {
            Some(username) => Some(username),
            None => Some(generate_instance_wide_unique_username(&mut tx, &email).await?),
        }
    } else {
        None
    };

    // `email` is the primary key: a concurrent create of the same address that passed the
    // existence check above fails here and must still read as a conflict.
    sqlx::query(
        "INSERT INTO password
            (email, password_hash, login_type, super_admin, verified, name, company, username)
         VALUES ($1, $2, $3, $4, true, $5, $6, $7)",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(&login_type)
    .bind(nu.super_admin)
    .bind(&nu.name)
    .bind(&nu.company)
    .bind(&username)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            account_exists(&email)
        } else {
            e.into()
        }
    })?;

    sqlx::query("DELETE FROM pending_user WHERE email = $1")
        .bind(&email)
        .execute(&mut *tx)
        .await?;

    audit_log(
        &mut *tx,
        &authed,
        "users.add_global",
        ActionKind::Create,
        "global",
        Some(&email),
        None,
    )
    .await?;

    tx.commit().await?;

    webhook.send_instance_event(InstanceEvent::UserAdded { email: email.clone() });

    Ok((StatusCode::CREATED, format!("email {email} created")))
}

pub(super) async fn set_password(
    db: DB,
    argon2: Arc<Argon2<'_>>,
    authed: ApiAuthed,
    user_email: &str,
    ep: EditPassword,
) -> Result<String> {
    let email = user_email.to_lowercase();
    if authed.email != email {
        require_super_admin(&db, &authed).await?;
    }

    let password_hash = hash_password(argon2, ep.password)?;

    // `pending_oauth` accounts have no credential yet; setting one turns them into password
    // accounts. Every other login type belongs to its identity provider and keeps no password.
    let updated = sqlx::query(
        "UPDATE password SET password_hash = $1, login_type = $2
         WHERE email = $3 AND login_type IN ($2, $4)",
    )
    .bind(&password_hash)
    .bind(PASSWORD_LOGIN_TYPE)
    .bind(&email)
    .bind(PENDING_OAUTH_LOGIN_TYPE)
    .execute(&db)
    .await?
    .rows_affected();

    if updated == 0 {
        let exists =
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM password WHERE email = $1)")
                .bind(&email)
                .fetch_one(&db)
                .await?;
        return Err(if exists {
            Error::BadRequest(format!(
                "{email} signs in through an identity provider and cannot have a password"
            ))
        } else {
            Error::NotFound(format!("user {email} not found"))
        });
    }

    audit_log(
        &db,
        &authed,
        "users.setpassword",
        ActionKind::Update,
        "global",
        Some(&email),
        None,
    )
    .await?;

    Ok(format!("password of {email} updated"))
}

pub(super) fn hash_password(argon2: Arc<Argon2<'_>>, password: String) -> Result<String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(Error::BadRequest(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters long"
        )));
    }
    argon2
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|e| Error::internal_err(format!("hashing password: {e}")))
}
