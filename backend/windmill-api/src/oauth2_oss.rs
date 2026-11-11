#[cfg(feature = "private")]
#[allow(unused)]
pub use crate::oauth2_ee::*;

/*
 * Author: Ruben Fiszel
 * Copyright: Windmill Labs, Inc 2022
 * This file and its contents are licensed under the AGPLv3 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-AGPL for a copy of the license.
 */

#[cfg(not(feature = "private"))]
use std::{collections::HashMap, fmt::Debug};

#[cfg(not(feature = "private"))]
use axum::{routing::get, Json, Router};
#[cfg(not(feature = "private"))]
use hmac::Mac;

#[cfg(all(feature = "oauth2", not(feature = "private")))]
use itertools::Itertools;
#[cfg(not(feature = "private"))]
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "oauth2", not(feature = "private")))]
use windmill_common::more_serde::maybe_number_opt;
#[cfg(all(feature = "oauth2", not(feature = "private")))]
use windmill_oauth::{helpers, AccessToken, RefreshToken, Scope};

#[cfg(all(feature = "oauth2", not(feature = "private")))]
use crate::OAUTH_CLIENTS;
#[cfg(not(feature = "private"))]
use windmill_common::error;
#[cfg(not(feature = "private"))]
use windmill_common::oauth2::*;

#[cfg(not(feature = "private"))]
use crate::db::DB;
#[cfg(not(feature = "private"))]
use std::str;

// Local patch (local/PATCHES.md): SSO sign-in lives in oauth2_oss_local.rs.
#[cfg(all(feature = "oauth2", not(feature = "private")))]
#[path = "oauth2_oss_local.rs"]
mod local;

#[cfg(not(feature = "private"))]
pub fn global_service() -> Router {
    Router::new()
        .merge(local::routes())
        .route("/list_connects", get(list_connects))
}

#[cfg(not(feature = "private"))]
pub fn workspaced_service() -> Router {
    Router::new()
}

#[cfg(not(feature = "private"))]
pub async fn workspace_connect_slack() -> Result<http::status::StatusCode, error::Error> {
    Err(error::Error::BadRequest(
        "Slack only available on enterprise".to_string(),
    ))
}

#[cfg(not(feature = "private"))]
pub async fn connect_slack_instance() -> Result<http::status::StatusCode, error::Error> {
    Err(error::Error::BadRequest(
        "Slack only available on enterprise".to_string(),
    ))
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
pub use windmill_oauth::{AllClients, BasicClientsMap, ClientWithScopes};

#[cfg(not(feature = "private"))]
pub use windmill_oauth::{OAuthClient, OAuthConfig};

#[cfg(all(feature = "oauth2", not(feature = "private")))]
pub async fn build_oauth_clients(
    _base_url: &str,
    _oauths_from_config: Option<HashMap<String, OAuthClient>>,
    _db: &DB,
) -> anyhow::Result<AllClients> {
    // Implementation is not open source
    return Ok(AllClients {
        logins: local::build_login_clients(_base_url, _oauths_from_config.as_ref()),
        connects: HashMap::default(),
        slack: None,
        slack_signing_secret: None,
    });
}

#[cfg(all(feature = "oauth2", not(feature = "private")))]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenResponse {
    access_token: AccessToken,
    #[serde(deserialize_with = "maybe_number_opt")]
    #[serde(default)]
    expires_in: Option<u64>,
    refresh_token: Option<RefreshToken>,
    #[serde(deserialize_with = "helpers::deserialize_space_delimited_vec")]
    #[serde(serialize_with = "helpers::serialize_space_delimited_vec")]
    #[serde(default)]
    scope: Option<Vec<Scope>>,
}

#[cfg(not(feature = "private"))]
#[allow(dead_code)] // Local patch (local/PATCHES.md): replaced by oauth2_oss_local.rs.
#[derive(Serialize)]
struct Logins {
    oauth: Vec<String>,
    saml: Option<String>,
    auto_login: Option<String>,
}
#[cfg(not(feature = "private"))]
#[allow(dead_code)] // Local patch (local/PATCHES.md): replaced by oauth2_oss_local.rs.
async fn list_logins() -> error::JsonResult<Logins> {
    // Implementation is not open source
    return Ok(Json(Logins { oauth: vec![], saml: None, auto_login: None }));
}

#[allow(unused)]
#[cfg(all(feature = "oauth2", not(feature = "private")))]
async fn list_connects() -> error::JsonResult<Vec<String>> {
    Ok(Json(
        (&OAUTH_CLIENTS.load().connects)
            .keys()
            .map(|x| x.to_owned())
            .collect_vec(),
    ))
}

#[allow(unused)]
#[cfg(not(all(feature = "oauth2", not(feature = "private"))))]
async fn list_connects() -> windmill_common::error::JsonResult<Vec<String>> {
    // Implementation is not open source
    return Ok(axum::Json(vec![]));
}

#[cfg(not(feature = "private"))]
pub async fn _refresh_token(
    _path: &str,
    _w_id: &str,
    _id: i32,
    _db: &DB,
    _force: bool,
) -> error::Result<String> {
    // Implementation is not open source
    Err(error::Error::BadRequest(
        "Not implemented in Windmill's Open Source repository".to_string(),
    ))
}

#[cfg(not(feature = "private"))]
// Local patch (local/PATCHES.md): no user quota.
pub async fn check_nb_of_user(_db: &DB) -> error::Result<()> {
    Ok(())
}

#[derive(Clone, Debug)]
#[cfg(not(feature = "private"))]
pub struct SlackVerifier {
    mac: HmacSha256,
}
#[cfg(not(feature = "private"))]
impl SlackVerifier {
    pub fn new<S: AsRef<[u8]>>(secret: S) -> anyhow::Result<SlackVerifier> {
        HmacSha256::new_from_slice(secret.as_ref())
            .map(|mac| SlackVerifier { mac })
            .map_err(|_| anyhow::anyhow!("invalid secret"))
    }

    pub fn verify(&self, ts: &str, body: &str, exp_sig: &str) -> anyhow::Result<()> {
        let basestring = format!("v0:{}:{}", ts, body);
        let mut mac = self.mac.clone();
        mac.update(basestring.as_bytes());
        let sig = format!("v0={}", hex::encode(mac.finalize().into_bytes()));
        if sig != exp_sig {
            Err(anyhow::anyhow!("signature mismatch"))?;
        }
        Ok(())
    }
}
