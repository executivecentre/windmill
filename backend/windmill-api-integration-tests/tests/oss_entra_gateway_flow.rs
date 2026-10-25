//! Local patch (local/PATCHES.md): the Windmill API calls the Entra gateway makes, in order,
//! authenticated with SUPERADMIN_SECRET as the gateway is. One test per binary: the secret is
//! read from the process environment when the API server starts.

use serde_json::json;
use sqlx::{Pool, Postgres};

use windmill_test_utils::*;

const EMAIL: &str = "entra.user@example.com";

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn session_cookie(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("token="))
        .map(|c| c.split(';').next().unwrap_or_default().to_string())
        .filter(|t| !t.is_empty())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn gateway_provisions_hands_off_and_disables(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let secret = format!("gw-{}", uuid::Uuid::new_v4().simple());
    std::env::set_var("SUPERADMIN_SECRET", &secret);
    let server = ApiServer::start(db.clone()).await?;
    let base = format!("http://localhost:{}/api", server.addr.port());
    let post = |path: &str, body: serde_json::Value| {
        client()
            .post(format!("{base}{path}"))
            .bearer_auth(&secret)
            .json(&body)
            .send()
    };

    let resp = client()
        .post(format!("{base}/users/create"))
        .bearer_auth("not-the-secret")
        .json(&json!({"email": EMAIL, "super_admin": false, "login_type": "entra"}))
        .send()
        .await?;
    assert_eq!(resp.status(), 401);

    // Provision: account, workspace membership, group membership.
    let resp = post(
        "/users/create",
        json!({"email": EMAIL, "super_admin": false, "login_type": "entra", "name": "Entra User"}),
    )
    .await?;
    assert_eq!(resp.status(), 201, "{}", resp.text().await?);
    let resp = post(
        "/w/test-workspace/workspaces/add_user",
        json!({"email": EMAIL, "is_admin": false, "operator": false}),
    )
    .await?;
    assert!(resp.status().is_success(), "{}", resp.text().await?);
    let username: String = sqlx::query_scalar(
        "SELECT username FROM usr WHERE workspace_id = 'test-workspace' AND email = $1",
    )
    .bind(EMAIL)
    .fetch_one(&db)
    .await?;

    let resp = post(
        "/w/test-workspace/groups/create",
        json!({"name": "entra_engineering", "summary": "Synced from Entra ID"}),
    )
    .await?;
    assert!(resp.status().is_success(), "{}", resp.text().await?);
    // `create_group` makes its caller a member; the gateway removes that row.
    let members = |db: Pool<Postgres>| async move {
        sqlx::query_scalar::<_, String>(
            "SELECT usr FROM usr_to_group
             WHERE workspace_id = 'test-workspace' AND group_ = 'entra_engineering' ORDER BY usr",
        )
        .fetch_all(&db)
        .await
    };
    assert_eq!(members(db.clone()).await?, vec!["superadmin_secret"]);
    let resp = post(
        "/w/test-workspace/groups/removeuser/entra_engineering",
        json!({"username": "superadmin_secret"}),
    )
    .await?;
    assert!(resp.status().is_success(), "{}", resp.text().await?);
    let resp = post(
        "/w/test-workspace/groups/adduser/entra_engineering",
        json!({"username": username}),
    )
    .await?;
    assert!(resp.status().is_success(), "{}", resp.text().await?);
    assert_eq!(members(db.clone()).await?, vec![username.clone()]);

    // Hand-off: a login link bound to the `entra` login type.
    let resp = post(
        "/users/login_links",
        json!({"email": EMAIL, "require_login_type": "pending_oauth"}),
    )
    .await?;
    assert_eq!(resp.status(), 409);
    let resp = post(
        "/users/login_links",
        json!({"email": EMAIL, "require_login_type": "entra", "rd": "/", "expires_in_s": 60}),
    )
    .await?;
    assert_eq!(resp.status(), 201, "{}", resp.text().await?);
    let link = resp.json::<serde_json::Value>().await?;
    let path = link["url"]
        .as_str()
        .unwrap()
        .split_once("/api")
        .unwrap()
        .1
        .to_string();

    let resp = client().get(format!("{base}{path}")).send().await?;
    assert_eq!(resp.status(), 302);
    assert_eq!(resp.headers()["location"], "/");
    let session = session_cookie(&resp).expect("login link sets a session cookie");
    let resp = client()
        .get(format!("{base}/users/whoami"))
        .bearer_auth(&session)
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<serde_json::Value>().await?["email"], EMAIL);
    let resp = client()
        .get(format!("{base}/w/test-workspace/users/whoami"))
        .bearer_auth(&session)
        .send()
        .await?;
    assert_eq!(resp.status(), 200);
    let me = resp.json::<serde_json::Value>().await?;
    assert_eq!(me["username"], username.as_str());
    assert_eq!(me["is_admin"], false);
    assert!(me["groups"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g == "entra_engineering"));

    // The link is single use.
    let resp = client().get(format!("{base}{path}")).send().await?;
    assert_eq!(resp.status(), 302);
    assert!(session_cookie(&resp).is_none());

    // Deprovision: disabling the account removes every token and blocks new links.
    let resp = post(&format!("/users/update/{EMAIL}"), json!({"disabled": true})).await?;
    assert!(resp.status().is_success(), "{}", resp.text().await?);
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM token WHERE email = $1")
        .bind(EMAIL)
        .fetch_one(&db)
        .await?;
    assert_eq!(tokens, 0);
    let resp = post(
        "/users/login_links",
        json!({"email": EMAIL, "require_login_type": "entra"}),
    )
    .await?;
    assert_eq!(resp.status(), 404);

    Ok(())
}
