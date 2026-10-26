#[cfg(feature = "private")]
#[allow(unused)]
pub use crate::users_ee::*;

#[cfg(not(feature = "private"))]
use std::sync::Arc;

#[cfg(not(feature = "private"))]
use crate::db::ApiAuthed;

#[cfg(not(feature = "private"))]
use crate::users::{EditPassword, NewUser};

#[cfg(not(feature = "private"))]
use crate::{db::DB, webhook_util::WebhookShared};

#[cfg(not(feature = "private"))]
use argon2::Argon2;

#[cfg(not(feature = "private"))]
use axum::{extract::Extension, Json};

#[cfg(not(feature = "private"))]
use http::StatusCode;

#[cfg(not(feature = "private"))]
use serde::Deserialize;

#[cfg(not(feature = "private"))]
use windmill_common::error::{Error, Result};

// Local patch (local/PATCHES.md): the three stubs below delegate to users_oss_local.rs.
#[cfg(not(feature = "private"))]
#[path = "users_oss_local.rs"]
mod local;

#[cfg(not(feature = "private"))]
pub async fn create_user(
    _authed: ApiAuthed,
    _db: DB,
    _webhook: WebhookShared,
    _argon2: Arc<Argon2<'_>>,
    mut _nu: NewUser,
) -> Result<(StatusCode, String)> {
    local::create_user(_authed, _db, _webhook, _argon2, _nu).await
}

#[cfg(not(feature = "private"))]
pub async fn set_password(
    _db: DB,
    _argon2: Arc<Argon2<'_>>,
    _authed: ApiAuthed,
    _user_email: &str,
    _ep: EditPassword,
) -> Result<String> {
    local::set_password(_db, _argon2, _authed, _user_email, _ep).await
}

#[cfg(not(feature = "private"))]
pub fn hash_password(_argon2: Arc<Argon2<'_>>, _password: String) -> Result<String> {
    local::hash_password(_argon2, _password)
}

#[cfg(not(feature = "private"))]
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct OnboardingData {
    pub touch_point: String,
    pub use_case: String,
}

#[cfg(not(feature = "private"))]
pub async fn submit_onboarding_data(
    _authed: ApiAuthed,
    Extension(_db): Extension<DB>,
    Json(_data): Json<OnboardingData>,
) -> Result<String> {
    Err(Error::internal_err(
        "Not implemented in Windmill's Open Source repository".to_string(),
    ))
}
