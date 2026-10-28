//! Local patch (local/PATCHES.md): SSO sign-in (`oauth2_oss_local.rs`) against a mock
//! provider. One test: the SSO clients are a process-wide static.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Form, Json, Router,
};
use serde_json::json;
use sqlx::{Pool, Postgres};
use windmill_api::oauth2_oss::{build_oauth_clients, OAuthClient};
use windmill_test_utils::*;

/// A provider whose token is the authorization code, and whose userinfo returns that code
/// as the email: the code picks who signs in.
async fn start_provider() -> anyhow::Result<String> {
    let app = Router::new()
        .route(
            "/token",
            post(|Form(form): Form<HashMap<String, String>>| async move {
                Json(json!({"access_token": form["code"], "token_type": "bearer"}))
            }),
        )
        .route(
            "/userinfo",
            get(|headers: HeaderMap| async move {
                let auth = headers["authorization"].to_str().unwrap_or_default();
                match auth.strip_prefix("Bearer ") {
                    Some(email) => Ok(Json(json!({"email": email, "name": "SSO User"}))),
                    None => Err(StatusCode::UNAUTHORIZED),
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    tokio::spawn(async move { axum::serve(listener, app).await });
    Ok(base)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Starts a sign-in and returns the provider redirect and the CSRF cookie it set.
async fn start_login(port: u16) -> anyhow::Result<(reqwest::Url, String)> {
    let resp = client()
        .get(format!("http://localhost:{port}/api/oauth/login/testsso"))
        .send()
        .await?;
    assert!(resp.status().is_redirection(), "{}", resp.status());
    let location = reqwest::Url::parse(resp.headers()["location"].to_str()?)?;
    let csrf = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find_map(|c| c.strip_prefix("csrf=")?.split(';').next())
        .expect("csrf cookie")
        .to_string();
    Ok((location, csrf))
}

async fn finish_login(
    port: u16,
    csrf: &str,
    state: &str,
    email: &str,
) -> anyhow::Result<reqwest::Response> {
    Ok(client()
        .post(format!(
            "http://localhost:{port}/api/oauth/login_callback/testsso"
        ))
        .header("cookie", format!("csrf={csrf}"))
        .json(&json!({"code": email, "state": state}))
        .send()
        .await?)
}

async fn sign_in(port: u16, email: &str) -> anyhow::Result<reqwest::Response> {
    let (location, csrf) = start_login(port).await?;
    let state = location
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state");
    finish_login(port, &csrf, &state, email).await
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn sso_sign_in(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();
    let provider = start_provider().await?;
    let oauths: HashMap<String, OAuthClient> = serde_json::from_value(json!({
        "testsso": {
            "id": "client-id", "secret": "client-secret", "display_name": "Test SSO",
            "login_config": {
                "auth_url": format!("{provider}/authorize"),
                "token_url": format!("{provider}/token"),
                "userinfo_url": format!("{provider}/userinfo"),
                "scopes": ["openid", "email"]
            }
        },
        "microsoft": {"id": "client-id", "secret": "client-secret"},
        "ms_teams": {"id": "client-id", "secret": "client-secret", "tenant": "t"}
    }))?;
    let base_url = format!("http://localhost:{port}");
    let clients = build_oauth_clients(&base_url, Some(oauths), &db).await?;
    windmill_api::OAUTH_CLIENTS.store(Arc::new(clients));

    // Only the provider with a login config is offered: Microsoft needs its tenant.
    let logins: serde_json::Value = client()
        .get(format!("{base_url}/api/oauth/list_logins"))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(
        logins["oauth"],
        json!([{"type": "testsso", "display_name": "Test SSO"}])
    );

    let (location, _) = start_login(port).await?;
    assert!(
        location
            .as_str()
            .starts_with(&format!("{provider}/authorize?")),
        "{location}"
    );
    let redirect_uri = location
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .unwrap()
        .1;
    assert_eq!(
        redirect_uri,
        format!("{base_url}/user/login_callback/testsso")
    );

    // A first sign-in creates a plain account and a session; the next one reuses both.
    let resp = sign_in(port, "New.User@Example.com").await?;
    assert_eq!(resp.status(), 200, "{}", resp.text().await?);
    let session = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|c| c.to_str().ok())
        .find_map(|c| {
            c.strip_prefix("token=")?
                .split(';')
                .next()
                .map(str::to_string)
        })
        .expect("session cookie");
    let whoami = client()
        .get(format!("{base_url}/api/users/whoami"))
        .bearer_auth(&session)
        .send()
        .await?;
    assert_eq!(whoami.status(), 200);
    let (login_type, super_admin, name): (String, bool, Option<String>) = sqlx::query_as(
        "SELECT login_type, super_admin, name FROM password WHERE email = 'new.user@example.com'",
    )
    .fetch_one(&db)
    .await?;
    assert_eq!((login_type.as_str(), super_admin), ("testsso", false));
    assert_eq!(name.as_deref(), Some("SSO User"));
    assert_eq!(sign_in(port, "new.user@example.com").await?.status(), 200);

    // An account an administrator added ahead of time is claimed by its first sign-in.
    sqlx::query("INSERT INTO password (email, login_type, super_admin, verified) VALUES ('pending@example.com', 'pending_oauth', false, true)")
        .execute(&db)
        .await?;
    assert_eq!(sign_in(port, "pending@example.com").await?.status(), 200);
    let claimed: String =
        sqlx::query_scalar("SELECT login_type FROM password WHERE email = 'pending@example.com'")
            .fetch_one(&db)
            .await?;
    assert_eq!(claimed, "testsso");

    // Refused: a superadmin, a password account, and a callback whose state is not the cookie's.
    assert_eq!(sign_in(port, "test@windmill.dev").await?.status(), 403);
    assert_eq!(sign_in(port, "test2@windmill.dev").await?.status(), 400);
    let (_, csrf) = start_login(port).await?;
    let resp = finish_login(port, &csrf, "forged-state", "someone@example.com").await?;
    assert_eq!(resp.status(), 400);
    let created: i64 =
        sqlx::query_scalar("SELECT count(*) FROM password WHERE email = 'someone@example.com'")
            .fetch_one(&db)
            .await?;
    assert_eq!(created, 0);

    Ok(())
}
