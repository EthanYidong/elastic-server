use warp::Filter;

use std::sync::Arc;

use crate::ArcRwLock;
use crate::google_auth::GoogleAuthKeyStore;
use crate::tokens::TokenHelper;
use crate::types::auth::*;
use crate::handlers::auth as handlers;

use super::extractor;

pub fn login(
    db_client: mongodb::Client,
    keystore: ArcRwLock<GoogleAuthKeyStore>,
    token_helper: Arc<TokenHelper>,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path!("login")
        .and(warp::post())
        .and(extractor(db_client))
        .and(extractor(keystore))
        .and(extractor(token_helper))
        .and(warp::body::json::<LoginRequest>())
        .and_then(handlers::login)
}
