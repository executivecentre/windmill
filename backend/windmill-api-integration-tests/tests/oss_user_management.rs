//! Local patch (local/PATCHES.md): the OSS `create_user` / `set_password` / `hash_password`.

use serde_json::json;
use sqlx::{Pool, Postgres};

use windmill_test_utils::*;

const PASSWORD: &str = "correct-horse-battery";

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn create(
    port: u16,
    token: &str,
    body: serde_json::Value,
) -> anyhow::Result<reqwest::Response> {
    Ok(client()
        .post(format!("http://localhost:{port}/api/users/create"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?)
}

async fn login(port: u16, email: &str, password: &str) -> anyhow::Result<reqwest::Response> {
    Ok(client()
        .post(format!("http://localhost:{port}/api/auth/login"))
        .json(&json!({"email": email, "password": password}))
        .send()
        .await?)
}

/// Whether the server announced `token`'s deletion to every API server's auth cache.
async fn invalidated(db: &Pool<Postgres>, token: &str) -> anyhow::Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM notify_event
         WHERE channel = 'notify_token_invalidation' AND $1 LIKE payload || '%')",
    )
    .bind(token)
    .fetch_one(db)
    .await?)
}

async fn count_accounts(db: &Pool<Postgres>) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT count(*) FROM password")
        .fetch_one(db)
        .await?)
}

async fn whoami_status(port: u16, token: &str) -> anyhow::Result<u16> {
    Ok(client()
        .get(format!("http://localhost:{port}/api/users/whoami"))
        .bearer_auth(token)
        .send()
        .await?
        .status()
        .as_u16())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn password_user_is_created_and_can_log_in(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();

    let resp = create(
        port,
        "SECRET_TOKEN",
        json!({"email": "Alice@Example.com", "password": PASSWORD, "super_admin": false,
               "name": "Alice"}),
    )
    .await?;
    assert_eq!(resp.status(), 201, "{}", resp.text().await?);

    let (hash, login_type, username, super_admin): (String, String, Option<String>, bool) =
        sqlx::query_as(
            "SELECT password_hash, login_type, username, super_admin FROM password
             WHERE email = 'alice@example.com'",
        )
        .fetch_one(&db)
        .await?;
    assert!(hash.starts_with("$argon2id$"), "{hash}");
    assert_eq!(login_type, "password");
    assert_eq!(username.as_deref(), Some("alice"));
    assert!(!super_admin);

    let resp = login(port, "alice@example.com", PASSWORD).await?;
    assert_eq!(resp.status(), 200, "{}", resp.text().await?);
    let token = resp.text().await?;
    assert_eq!(whoami_status(port, &token).await?, 200);

    let resp = login(port, "alice@example.com", "wrong-password-123").await?;
    assert_eq!(resp.status(), 400);

    for body in [
        json!({"email": "empty@example.com", "password": "", "super_admin": false}),
        json!({"email": "nopassword@example.com", "super_admin": false}),
        json!({"email": "not-an-email", "password": PASSWORD, "super_admin": false}),
    ] {
        let resp = create(port, "SECRET_TOKEN", body.clone()).await?;
        assert_eq!(resp.status(), 400, "{body}");
    }

    Ok(())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn provider_user_has_no_password(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();

    let resp = create(
        port,
        "SECRET_TOKEN",
        json!({"email": "bob@example.com", "password": PASSWORD, "super_admin": false,
               "login_type": "pending_oauth"}),
    )
    .await?;
    assert_eq!(
        resp.status(),
        400,
        "a provider account must not carry a password"
    );

    let resp = create(
        port,
        "SECRET_TOKEN",
        json!({"email": "bob@example.com", "super_admin": false, "login_type": "pending_oauth"}),
    )
    .await?;
    assert_eq!(resp.status(), 201, "{}", resp.text().await?);
    let hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM password WHERE email = 'bob@example.com'")
            .fetch_one(&db)
            .await?;
    assert_eq!(hash, None);

    let resp = login(port, "bob@example.com", PASSWORD).await?;
    assert_eq!(resp.status(), 400);

    // Not even a superadmin can give an SSO account a password.
    sqlx::query("UPDATE password SET login_type = 'microsoft' WHERE email = 'bob@example.com'")
        .execute(&db)
        .await?;
    let resp = client()
        .post(format!(
            "http://localhost:{port}/api/users/set_password_of/bob@example.com"
        ))
        .bearer_auth("SECRET_TOKEN")
        .json(&json!({"password": PASSWORD}))
        .send()
        .await?;
    assert_eq!(resp.status(), 400);
    let login_type: String =
        sqlx::query_scalar("SELECT login_type FROM password WHERE email = 'bob@example.com'")
            .fetch_one(&db)
            .await?;
    assert_eq!(login_type, "microsoft");

    // Only password and pending_oauth accounts can be created; SSO creates the others.
    for login_type in ["github", "saml", "microsoft", "entra", ""] {
        let resp = create(
            port,
            "SECRET_TOKEN",
            json!({"email": "carol@example.com", "super_admin": false,
                   "login_type": login_type}),
        )
        .await?;
        assert_eq!(resp.status(), 400, "{login_type}");
    }

    Ok(())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn duplicate_and_unauthorized_creates_are_refused(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();
    let body =
        json!({"email": "dave@example.com", "super_admin": false, "login_type": "pending_oauth"});
    let accounts_before = count_accounts(&db).await?;

    let resp = create(port, "SECRET_TOKEN_2", body.clone()).await?;
    assert_eq!(resp.status(), 401);
    let resp = client()
        .post(format!("http://localhost:{port}/api/users/create"))
        .json(&body)
        .send()
        .await?;
    assert_eq!(resp.status(), 401);

    let resp = create(port, "SECRET_TOKEN", body.clone()).await?;
    assert_eq!(resp.status(), 201);
    let resp = create(
        port,
        "SECRET_TOKEN",
        json!({"email": "DAVE@example.com", "password": PASSWORD, "super_admin": false}),
    )
    .await?;
    assert_eq!(resp.status(), 409);
    let resp = create(
        port,
        "SECRET_TOKEN",
        json!({"email": "test2@windmill.dev", "password": PASSWORD, "super_admin": false}),
    )
    .await?;
    assert_eq!(resp.status(), 409);

    assert_eq!(count_accounts(&db).await?, accounts_before + 1);

    Ok(())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn concurrent_duplicate_creates_leave_one_row(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();

    let requests = (0..10).map(|_| {
        create(
            port,
            "SECRET_TOKEN",
            json!({"email": "erin@example.com", "super_admin": false,
                   "login_type": "pending_oauth"}),
        )
    });
    let statuses: Vec<u16> = futures::future::try_join_all(requests)
        .await?
        .iter()
        .map(|r| r.status().as_u16())
        .collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == 201).count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|s| **s == 409).count(),
        9,
        "{statuses:?}"
    );

    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM password WHERE email = 'erin@example.com'")
            .fetch_one(&db)
            .await?;
    assert_eq!(rows, 1);

    Ok(())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn password_change_invalidates_other_sessions(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();

    let resp = create(
        port,
        "SECRET_TOKEN",
        json!({"email": "frank@example.com", "password": PASSWORD, "super_admin": false}),
    )
    .await?;
    assert_eq!(resp.status(), 201);

    // `other` is never used before the change, so it is not in this server's AUTH_CACHE: the
    // test server does not run the notify_event listener that evicts cached sessions, which is
    // asserted through the emitted events instead.
    let current = login(port, "frank@example.com", PASSWORD)
        .await?
        .text()
        .await?;
    let other = login(port, "frank@example.com", PASSWORD)
        .await?
        .text()
        .await?;
    assert_eq!(whoami_status(port, &current).await?, 200);

    let set_own = |password: &'static str| {
        client()
            .post(format!("http://localhost:{port}/api/users/setpassword"))
            .bearer_auth(&current)
            .json(&json!({"password": password}))
            .send()
    };
    assert_eq!(set_own("").await?.status(), 400);
    let new_password = "another-long-password";
    let resp = set_own(new_password).await?;
    assert_eq!(resp.status(), 200, "{}", resp.text().await?);

    assert_eq!(whoami_status(port, &current).await?, 200);
    assert_eq!(whoami_status(port, &other).await?, 401);
    assert!(invalidated(&db, &other).await?);
    assert!(!invalidated(&db, &current).await?);
    assert_eq!(
        login(port, "frank@example.com", PASSWORD).await?.status(),
        400
    );
    assert_eq!(
        login(port, "frank@example.com", new_password)
            .await?
            .status(),
        200
    );

    // A superadmin reset ends every session of the account.
    let resp = client()
        .post(format!(
            "http://localhost:{port}/api/users/set_password_of/frank@example.com"
        ))
        .bearer_auth("SECRET_TOKEN")
        .json(&json!({"password": "superadmin-chosen-password"}))
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "{}", resp.text().await?);
    assert!(invalidated(&db, &current).await?);
    let sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM token WHERE email = 'frank@example.com' AND label = 'session'",
    )
    .fetch_one(&db)
    .await?;
    assert_eq!(sessions, 0);

    // A non-superadmin cannot set someone else's password.
    let resp = client()
        .post(format!(
            "http://localhost:{port}/api/users/set_password_of/test3@windmill.dev"
        ))
        .bearer_auth("SECRET_TOKEN_2")
        .json(&json!({"password": PASSWORD}))
        .send()
        .await?;
    assert_eq!(resp.status(), 401);

    Ok(())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn pending_oauth_account_becomes_password_account(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();

    let resp = create(
        port,
        "SECRET_TOKEN",
        json!({"email": "grace@example.com", "super_admin": false,
               "login_type": "pending_oauth"}),
    )
    .await?;
    assert_eq!(resp.status(), 201);
    let resp = client()
        .post(format!(
            "http://localhost:{port}/api/users/set_password_of/grace@example.com"
        ))
        .bearer_auth("SECRET_TOKEN")
        .json(&json!({"password": PASSWORD}))
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "{}", resp.text().await?);
    let login_type: String =
        sqlx::query_scalar("SELECT login_type FROM password WHERE email = 'grace@example.com'")
            .fetch_one(&db)
            .await?;
    assert_eq!(login_type, "password");
    assert_eq!(
        login(port, "grace@example.com", PASSWORD).await?.status(),
        200
    );

    Ok(())
}

/// The CE build capped instances at 50 users and 10 SSO users.
#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn accounts_above_former_ce_caps(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();
    let accounts_before = count_accounts(&db).await?;

    for i in 0..60 {
        let resp = create(
            port,
            "SECRET_TOKEN",
            json!({"email": format!("user{i}@example.com"), "password": PASSWORD,
                   "super_admin": false}),
        )
        .await?;
        assert_eq!(resp.status(), 201, "user{i}: {}", resp.text().await?);
    }
    for i in 0..12 {
        let resp = create(
            port,
            "SECRET_TOKEN",
            json!({"email": format!("sso{i}@example.com"), "super_admin": false,
                   "login_type": "pending_oauth"}),
        )
        .await?;
        assert_eq!(resp.status(), 201, "sso{i}: {}", resp.text().await?);
    }

    let provider_accounts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM password WHERE login_type = 'pending_oauth'")
            .fetch_one(&db)
            .await?;
    assert_eq!(provider_accounts, 12);
    assert_eq!(count_accounts(&db).await?, accounts_before + 72);
    assert_eq!(
        login(port, "user59@example.com", PASSWORD).await?.status(),
        200
    );

    Ok(())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn set_password_revokes_mcp_oauth_grants(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;

    sqlx::raw_sql(
        "INSERT INTO mcp_oauth_server_client (client_id, client_name, redirect_uris)
         VALUES ('mcp-client', 'MCP client', ARRAY['http://localhost/cb']);
         INSERT INTO token (token_hash, token_prefix, email, label, expiration)
         VALUES (encode(sha256('MCP_ACCESS_TOKEN'::bytea), 'hex'), 'MCP_ACCESS', 'test2@windmill.dev',
                 'mcp-oauth-mcp-client', now() + interval '7 days'),
                (encode(sha256('OTHER_MCP_TOKEN'::bytea), 'hex'), 'OTHER_MCP_', 'test3@windmill.dev',
                 'mcp-oauth-mcp-client', now() + interval '7 days');
         INSERT INTO mcp_oauth_refresh_token
             (refresh_token, access_token_hash, client_id, user_email, workspace_id, scopes, token_family, expires_at)
         VALUES ('test2-refresh', encode(sha256('MCP_ACCESS_TOKEN'::bytea), 'hex'), 'mcp-client',
                 'test2@windmill.dev', 'test-workspace', ARRAY['mcp:all'], gen_random_uuid(), now() + interval '30 days'),
                ('test3-refresh', encode(sha256('OTHER_MCP_TOKEN'::bytea), 'hex'), 'mcp-client',
                 'test3@windmill.dev', 'test-workspace', ARRAY['mcp:all'], gen_random_uuid(), now() + interval '30 days');
         INSERT INTO mcp_oauth_server_code (code, client_id, user_email, workspace_id, scopes, redirect_uri)
         VALUES ('test2-code', 'mcp-client', 'test2@windmill.dev', 'test-workspace', ARRAY['mcp:all'],
                 'http://localhost/cb');",
    )
    .execute(&db)
    .await?;

    let resp = client()
        .post(format!(
            "http://localhost:{}/api/users/set_password_of/test2@windmill.dev",
            server.addr.port()
        ))
        .bearer_auth("SECRET_TOKEN")
        .json(&json!({"password": "new-test-password-123"}))
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "{}", resp.text().await?);

    let labels: Vec<(String, String)> = sqlx::query_as(
        "SELECT email, label FROM token WHERE email IN ('test2@windmill.dev', 'test3@windmill.dev')
         ORDER BY email, label",
    )
    .fetch_all(&db)
    .await?;
    assert_eq!(
        labels,
        vec![
            ("test2@windmill.dev".to_string(), "test token 2".to_string()),
            (
                "test3@windmill.dev".to_string(),
                "mcp-oauth-mcp-client".to_string()
            ),
            ("test3@windmill.dev".to_string(), "test token 3".to_string()),
        ]
    );
    let refresh: Vec<String> = sqlx::query_scalar(
        "SELECT refresh_token FROM mcp_oauth_refresh_token ORDER BY refresh_token",
    )
    .fetch_all(&db)
    .await?;
    assert_eq!(refresh, vec!["test3-refresh".to_string()]);
    let codes: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_oauth_server_code")
        .fetch_one(&db)
        .await?;
    assert_eq!(codes, 0);

    Ok(())
}
