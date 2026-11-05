//! Local patch (local/PATCHES.md): workspace auto-add and auto-invite in the OSS build.

use serde_json::{json, Value};
use sqlx::{Pool, Postgres};

use windmill_test_utils::*;

const W_ID: &str = "test-workspace";

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

async fn edit_auto_invite(port: u16, body: Value) -> anyhow::Result<()> {
    let resp = client()
        .post(format!(
            "http://localhost:{port}/api/w/{W_ID}/workspaces/edit_auto_invite"
        ))
        .bearer_auth("SECRET_TOKEN")
        .json(&body)
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "{body}: {}", resp.text().await?);
    Ok(())
}

async fn create_account(port: u16, email: &str) -> anyhow::Result<()> {
    let resp = client()
        .post(format!("http://localhost:{port}/api/users/create"))
        .bearer_auth("SECRET_TOKEN")
        .json(&json!({"email": email, "password": "correct-horse-battery",
                      "super_admin": false, "name": "Auto Invite"}))
        .send()
        .await?;
    assert_eq!(resp.status(), 201, "{email}: {}", resp.text().await?);
    Ok(())
}

async fn auto_invite(db: &Pool<Postgres>) -> anyhow::Result<Option<Value>> {
    Ok(
        sqlx::query_scalar("SELECT auto_invite FROM workspace_settings WHERE workspace_id = $1")
            .bind(W_ID)
            .fetch_one(db)
            .await?,
    )
}

async fn set_auto_invite(db: &Pool<Postgres>, value: &Value) -> anyhow::Result<()> {
    sqlx::query("UPDATE workspace_settings SET auto_invite = $1 WHERE workspace_id = $2")
        .bind(value)
        .bind(W_ID)
        .execute(db)
        .await?;
    Ok(())
}

/// `email`'s role, `operator` flag and `added_via` in the workspace, if a member.
async fn membership(
    db: &Pool<Postgres>,
    email: &str,
) -> anyhow::Result<Option<(Option<String>, bool, Option<Value>)>> {
    Ok(sqlx::query_as(
        "SELECT workspace_role, operator, added_via FROM usr
         WHERE workspace_id = $1 AND email = $2",
    )
    .bind(W_ID)
    .bind(email)
    .fetch_optional(db)
    .await?)
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn auto_add_takes_in_existing_and_new_accounts(db: Pool<Postgres>) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();
    let instance_groups =
        json!({"instance_groups": ["eng"], "instance_groups_roles": {"eng": "developer"}});
    set_auto_invite(&db, &instance_groups).await?;
    create_account(port, "early@example.com").await?;

    // What the workspace settings page sends for "Auto-add anyone joining the instance".
    edit_auto_invite(
        port,
        json!({"is_admin": false, "operator": false, "role": "developer",
               "invite_all": true, "auto_add": true}),
    )
    .await?;
    assert_eq!(
        auto_invite(&db).await?,
        Some(
            json!({"instance_groups": ["eng"], "instance_groups_roles": {"eng": "developer"},
                    "enabled": true, "domain": "*", "operator": false, "role": "developer",
                    "mode": "add"})
        )
    );
    let added = Some((
        Some("developer".to_string()),
        false,
        Some(json!({"source": "domain", "domain": "*"})),
    ));
    assert_eq!(membership(&db, "early@example.com").await?, added);
    create_account(port, "late@example.com").await?;
    assert_eq!(membership(&db, "late@example.com").await?, added);
    let in_all: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM usr_to_group
         WHERE workspace_id = $1 AND usr = 'late' AND group_ = 'all')",
    )
    .bind(W_ID)
    .fetch_one(&db)
    .await?;
    assert!(in_all);

    // Switching it off sends no role, and leaves the instance-group keys alone.
    edit_auto_invite(port, json!({})).await?;
    assert_eq!(auto_invite(&db).await?, Some(instance_groups));
    create_account(port, "after@example.com").await?;
    assert_eq!(membership(&db, "after@example.com").await?, None);
    Ok(())
}

#[sqlx::test(migrations = "../migrations", fixtures("base"))]
async fn auto_invite_invites_new_accounts_and_never_blocks_one(
    db: Pool<Postgres>,
) -> anyhow::Result<()> {
    initialize_tracing().await;
    let server = ApiServer::start(db.clone()).await?;
    let port = server.addr.port();

    // What workspace creation sends with "operator" checked and auto-add off.
    edit_auto_invite(
        port,
        json!({"operator": true, "invite_all": true, "auto_add": false}),
    )
    .await?;
    create_account(port, "new@example.com").await?;
    let invite: Option<(bool, Option<String>)> = sqlx::query_as(
        "SELECT operator, workspace_role FROM workspace_invite
         WHERE workspace_id = $1 AND email = 'new@example.com'",
    )
    .bind(W_ID)
    .fetch_optional(&db)
    .await?;
    assert_eq!(invite, Some((true, Some("operator".to_string()))));
    assert_eq!(membership(&db, "new@example.com").await?, None);

    // NULL, not `{}`, once no instance-group keys are left to keep.
    edit_auto_invite(port, json!({})).await?;
    assert_eq!(auto_invite(&db).await?, None);

    // A setting naming a role the workspace no longer defines must not fail the sign-up.
    set_auto_invite(
        &db,
        &json!({"enabled": true, "domain": "*", "role": "removed-role", "mode": "add"}),
    )
    .await?;
    create_account(port, "blocked@example.com").await?;
    assert_eq!(membership(&db, "blocked@example.com").await?, None);
    Ok(())
}
