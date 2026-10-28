//! Local patch (local/PATCHES.md): SSO sign-in with the providers of Instance settings → SSO,
//! which the open-source `oauth2_oss.rs` leaves out. `oauth2_oss.rs` declares this module and
//! delegates its login routes and the login half of `build_oauth_clients` here. Accounts follow
//! "OAuth login" in docs/auth-surface.md, except that SSO never opens a superadmin or devops
//! account: those sign in with their password, which Caddy restricts to admin networks.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use axum::{
    extract::{Path, Query},
    response::Redirect,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;
use windmill_common::{
    error::{Error, Result},
    oauth2::REQUIRE_PREEXISTING_USER_FOR_OAUTH,
    users::{PENDING_OAUTH_LOGIN_TYPE, VALID_EMAIL},
    utils::IS_SECURE,
};
use windmill_oauth::{
    build_basic_client, exchange_code, oauth_redirect, BasicClientsMap, ClientWithScopes,
    OAuthCallback, OAuthClient, OAuthConfig, TokenResponse, OAUTH_HTTP_CLIENT,
};

use crate::db::DB;
use crate::users::{create_session_token, LoginUserInfo};
use crate::users_oss::local::insert_account;
use crate::OAUTH_CLIENTS;

lazy_static::lazy_static! {
    static ref LOGIN_REGISTRY: HashMap<String, OAuthConfig> =
        serde_json::from_str(include_str!("../../oauth_login.json"))
            .expect("oauth_login.json is valid");
}

/// The SSO providers among the instance's `oauths` entries: those with a `login_config`, or
/// with a key of `oauth_login.json`. Microsoft needs its `login_config`, which the SSO tab
/// writes with the tenant: the registry's `/common` endpoint would admit any Microsoft account.
pub(crate) fn build_login_clients(
    base_url: &str,
    oauths: Option<&HashMap<String, OAuthClient>>,
) -> BasicClientsMap {
    let mut logins = BasicClientsMap::new();
    for (name, entry) in oauths.into_iter().flatten() {
        if entry.id.is_empty() || entry.secret.is_empty() {
            continue;
        }
        let config = match (&entry.login_config, name.as_str()) {
            (Some(config), _) => config.clone(),
            (None, "microsoft") => {
                tracing::warn!("SSO provider microsoft has no tenant; it is not offered");
                continue;
            }
            (None, _) => match LOGIN_REGISTRY.get(name) {
                Some(config) => config.clone(),
                None => continue,
            },
        };
        match build_basic_client(
            name.clone(),
            config.clone(),
            entry.clone(),
            true,
            base_url,
            None,
        ) {
            Ok((_, client)) => {
                logins.insert(
                    name.clone(),
                    ClientWithScopes {
                        display_name: entry.display_name.clone(),
                        client,
                        scopes: config.scopes.unwrap_or_default(),
                        extra_params: config.extra_params,
                        extra_params_callback: config.extra_params_callback,
                        allowed_domains: entry.allowed_domains.clone(),
                        userinfo_url: config.userinfo_url,
                        connect_fields: None,
                        grant_types: entry.grant_types.clone(),
                        token_response_path: config.token_response_path,
                        token_url: config.token_url,
                        has_shared_credentials: true,
                    },
                );
            }
            Err(e) => tracing::error!("SSO provider {name} is not offered: {e}"),
        }
    }
    logins
}

pub(crate) fn routes() -> Router {
    Router::new()
        .route("/list_logins", get(list_logins))
        .route("/login/{client}", get(login))
        .route("/login_callback/{client}", post(login_callback))
}

#[derive(Serialize)]
struct LoginOption {
    #[serde(rename = "type")]
    type_: String,
    display_name: Option<String>,
}

#[derive(Serialize)]
struct Logins {
    oauth: Vec<LoginOption>,
}

async fn list_logins() -> Json<Logins> {
    let mut oauth: Vec<LoginOption> = OAUTH_CLIENTS
        .load()
        .logins
        .iter()
        .map(|(name, c)| LoginOption { type_: name.clone(), display_name: c.display_name.clone() })
        .collect();
    oauth.sort_by(|a, b| a.type_.cmp(&b.type_));
    Json(Logins { oauth })
}

#[derive(Deserialize)]
struct LoginQuery {
    /// The login page's automatic redirect, which must not stop at an account chooser.
    #[serde(default)]
    auto: bool,
}

async fn login(
    Path(client): Path<String>,
    Query(query): Query<LoginQuery>,
    cookies: Cookies,
) -> Result<Redirect> {
    let clients = OAUTH_CLIENTS.load();
    let extra_params = if query.auto {
        None
    } else {
        clients
            .logins
            .get(&client)
            .and_then(|c| c.extra_params.clone())
    };
    oauth_redirect(
        &clients.logins,
        client,
        cookies,
        None,
        extra_params,
        IS_SECURE.load(Ordering::Relaxed),
    )
}

async fn login_callback(
    Path(client): Path<String>,
    cookies: Cookies,
    Extension(db): Extension<DB>,
    Json(callback): Json<OAuthCallback>,
) -> Result<String> {
    let provider = OAUTH_CLIENTS
        .load()
        .logins
        .get(&client)
        .cloned()
        .ok_or_else(|| Error::BadRequest(format!("SSO provider {client} is not configured")))?;
    let token: TokenResponse = exchange_code(
        callback,
        &cookies,
        provider.client.clone(),
        provider.extra_params_callback.clone(),
        &OAUTH_HTTP_CLIENT,
    )
    .await?;
    let info = fetch_userinfo(&client, &provider, &token).await?;
    let email = info
        .email
        .as_deref()
        .map(|e| e.trim().to_lowercase())
        .filter(|e| VALID_EMAIL.is_match(e))
        .ok_or_else(|| {
            Error::BadRequest(format!(
                "{client} returned no email address for this account"
            ))
        })?;
    check_allowed_domains(&email, provider.allowed_domains.as_deref())?;

    let mut tx = db.begin().await?;
    let account: Option<(String, bool, bool, bool)> = sqlx::query_as(
        "SELECT login_type, super_admin, devops, disabled FROM password WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await?;
    let require_preexisting = REQUIRE_PREEXISTING_USER_FOR_OAUTH.load(Ordering::Relaxed);
    match account {
        None if require_preexisting => {
            return Err(Error::PermissionDenied(format!(
                "{email} has no account on this instance: an administrator must add it first"
            )))
        }
        None => {
            insert_account(
                &mut tx,
                &email,
                None,
                &client,
                false,
                info.name.as_deref(),
                info.company.as_deref(),
            )
            .await?
        }
        Some((_, super_admin, devops, _)) if super_admin || devops => {
            return Err(Error::PermissionDenied(format!(
                "{email} is an instance administrator account, which cannot sign in with SSO"
            )))
        }
        Some((_, _, _, true)) => {
            return Err(Error::PermissionDenied(format!(
                "the account {email} is disabled"
            )))
        }
        Some((login_type, ..)) if login_type == client => {}
        Some((login_type, ..))
            if login_type == PENDING_OAUTH_LOGIN_TYPE && info.email_verified != Some(false) =>
        {
            sqlx::query(
                "UPDATE password SET login_type = $1, password_hash = NULL WHERE email = $2",
            )
            .bind(&client)
            .bind(&email)
            .execute(&mut *tx)
            .await?;
        }
        Some(_) if require_preexisting => {}
        Some(_) => {
            return Err(Error::BadRequest(format!(
                "an account exists for {email} with a different login type"
            )))
        }
    }

    create_session_token(&email, false, None, false, &mut tx, cookies).await?;
    tx.commit().await?;
    Ok(format!("signed in with {client}"))
}

async fn fetch_userinfo(
    client: &str,
    provider: &ClientWithScopes,
    token: &TokenResponse,
) -> Result<LoginUserInfo> {
    let url = provider
        .userinfo_url
        .as_deref()
        .ok_or_else(|| Error::BadConfig(format!("SSO provider {client} has no userinfo URL")))?;
    let response = OAUTH_HTTP_CLIENT
        .get(url)
        .bearer_auth(token.access_token.as_ref() as &str)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| Error::BadGateway(format!("reading the {client} user profile: {e}")))?;
    response
        .json::<LoginUserInfo>()
        .await
        .map_err(|e| Error::BadGateway(format!("reading the {client} user profile: {e}")))
}

fn check_allowed_domains(email: &str, allowed: Option<&[String]>) -> Result<()> {
    let Some(allowed) = allowed.filter(|a| !a.is_empty()) else {
        return Ok(());
    };
    let domain = email.rsplit('@').next().unwrap_or_default();
    if allowed
        .iter()
        .any(|d| d.trim().eq_ignore_ascii_case(domain))
    {
        Ok(())
    } else {
        Err(Error::PermissionDenied(format!(
            "{email} is not in a domain allowed to sign in"
        )))
    }
}
