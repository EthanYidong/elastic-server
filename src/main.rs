mod google_auth;
mod routes;
mod handlers;
mod types;
mod errors;
mod tokens;

use warp::Filter;
use warp::http::header;

use tokio::sync::RwLock;

use std::sync::Arc;

pub type ArcRwLock<T> = Arc<RwLock<T>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::vars();
    pretty_env_logger::init();

    let mongodb_url = dotenv::var("MONGODB_URL")?;
    let db_client = mongodb::Client::with_uri_str(&mongodb_url).await?;

    // Setup google auth keystore
    let mut keystore = google_auth::GoogleAuthKeyStore::new()?;
    keystore.update_keys().await?;
    let keystore = Arc::new(RwLock::new(keystore));

    let token_helper = Arc::new(tokens::TokenHelper::new()?);

    let cors = warp::cors()
        .allow_headers(vec![header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_origins(vec!["https://elastic.blender.eu.org", "http://localhost:8080"])
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .build();

    let filter = routes::auth::login(db_client.clone(), keystore.clone(), token_helper.clone())
        .recover(errors::handle_rejection)
        .with(cors);

    warp::serve(filter)
        .run(([127, 0, 0, 1], 3030))
        .await;
    
    Ok(())
}
