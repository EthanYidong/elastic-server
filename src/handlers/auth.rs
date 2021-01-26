use std::sync::Arc;

use crate::errors::*;
use crate::google_auth::GoogleAuthKeyStore;
use crate::tokens::{TokenHelper, TokenClaims};
use crate::types::auth::*;
use crate::ArcRwLock;

pub async fn login(
    db_client: mongodb::Client,
    keystore: ArcRwLock<GoogleAuthKeyStore>,
    token_helper: Arc<TokenHelper>,
    login_request: LoginRequest,
) -> Result<impl warp::Reply, warp::Rejection> {
    if keystore.read().await.is_expired() {
        keystore.write().await.update_keys().await.map_err(InternalError::log)?;
    }
    let keystore = keystore.read().await;

    let claims = keystore.verify_token(&login_request.token).map_err(BadRequest::from)?;

    let coll = db_client.database("elastic").collection("users");

    let query = bson::doc!{
        "google_id": &claims.sub,
    };
    let update = bson::doc!{
        "$set": {
            "google_id": &claims.sub,
            "google_profile": bson::to_bson(&claims.profile).map_err(InternalError::log)?,
        }
    };
    let options = mongodb::options::UpdateOptions::builder()
        .upsert(true)
        .build();

    coll.update_one(query, update, options).await.map_err(InternalError::log)?;

    Ok(warp::reply::json(&LoginResponse {
        token: token_helper.encode(TokenClaims::new(claims.sub)).map_err(InternalError::log)?,
    }))
}
