use serde::{Serialize, Deserialize};

use thiserror::Error;

use jsonwebtoken as jwt;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const GOOGLE_JWKS_URL: &'static str = "https://www.googleapis.com/oauth2/v3/certs";
const VALID_ISSUERS: &[&'static str] = &["accounts.google.com", "https://accounts.google.com"];

pub struct GoogleAuthKeyStore {
    reqwest_client: reqwest::Client,
    validation: jwt::Validation,
    keys: HashMap<String, jwt::DecodingKey<'static>>,
    key_expiry: Instant,
}

impl GoogleAuthKeyStore {
    pub fn new() -> Result<GoogleAuthKeyStore, GoogleAuthError> {
        let mut aud = HashSet::new();
        aud.insert(dotenv::var("GOOGLE_CLIENT_ID").map_err(GoogleAuthError::from)?);

        let algorithms = vec![jwt::Algorithm::RS256];

        let reqwest_client = reqwest::Client::new();
        let validation = jwt::Validation {
            aud: Some(aud),
            algorithms,
            ..Default::default()
        };
        let keys = HashMap::new();
        let key_expiry = Instant::now();

        Ok(GoogleAuthKeyStore {
            reqwest_client,
            validation,
            keys,
            key_expiry,
        })
    }

    pub async fn update_keys(&mut self) -> Result<(), GoogleAuthError> {
        let resp = self.reqwest_client.get(GOOGLE_JWKS_URL)
            .send()
            .await?;
        
        let headers = resp.headers();
        let cache_control = headers.get(reqwest::header::CACHE_CONTROL)
            .ok_or(GoogleAuthError::InvalidCacheControl)?
            .to_str()
            .map_err(|_| GoogleAuthError::InvalidCacheControl)?;
        let max_age = parse_cache_control(&cache_control)?;
        self.key_expiry = Instant::now() + Duration::from_secs(max_age);

        let keys_wrapper = resp
            .json::<KeysWrapper>()
            .await?;
        
        for key in keys_wrapper.keys.into_iter() {
            self.keys.insert(key.kid, jwt::DecodingKey::from_rsa_components(&key.n, &key.e).into_static());
        }

        Ok(())
    }

    pub fn is_expired(&self) -> bool {
        self.key_expiry < Instant::now()
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, InvalidTokenError> {
        let header = jwt::decode_header(token)?;

        let kid = header.kid.ok_or(InvalidTokenError::MissingKeyID)?;
        let decoding_key = self.keys.get(&kid).ok_or(InvalidTokenError::UnknownKeyID(kid))?;

        let claims = jwt::decode::<Claims>(token, decoding_key, &self.validation)?.claims;

        if !VALID_ISSUERS.contains(&claims.iss.as_str()) {
            Err(InvalidTokenError::WrongIssuer(claims.iss))
        } else {
            Ok(claims)
        }
    }
}

fn parse_cache_control(cache_control: &str) -> Result<u64, GoogleAuthError> {
    let tokens: Vec<&str> = cache_control.split(",").collect();
    for token in tokens {
        let mut key_value_pair = token.split("=").map(|s| s.trim());
        let key = key_value_pair.next().ok_or(GoogleAuthError::InvalidCacheControl)?;
        let val = key_value_pair.next();

        if key == "max-age" {
            return Ok(
                val.ok_or(GoogleAuthError::InvalidCacheControl)?
                    .parse()
                    .map_err(|_| GoogleAuthError::InvalidCacheControl)?
            )
        }
    }
    Err(GoogleAuthError::InvalidCacheControl)
}

#[derive(Deserialize, Debug)]
pub struct Claims {
    pub iss: String,
    pub azp: String,
    pub aud: String,
    pub sub: String,
    pub at_hash: String,
    pub iat: u32,
    pub exp: u32,
    pub jti: String,
    #[serde(flatten)]
    pub profile: Profile,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Profile {
    pub hd: Option<String>,
    pub email: String,
    pub email_verified: bool,
    pub picture: String,
    pub given_name: String,
    pub family_name: String,
    pub locale: String,
}

#[derive(Deserialize)]
pub struct KeysWrapper {
    keys: Vec<Key>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct Key {
    kid: String,
    e: String,
    n: String,
    // Unused, but are always provided in google JWKS
    r#use: String,
    kty: String,
    alg: String,
}

#[derive(Error, Debug)]
pub enum GoogleAuthError {
    #[error("Error from reqwest: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Error from dotenv: {0}")]
    EnvError(#[from] dotenv::Error),
    #[error("Invalid cache-control header")]
    InvalidCacheControl,
}

#[derive(Error, Debug)]
pub enum InvalidTokenError {
    #[error("Error from jwt: {0}")]
    JWTError(#[from] jwt::errors::Error),
    #[error("Token header missing 'kid' field")]
    MissingKeyID,
    #[error("Key ID {0} isn't known")]
    UnknownKeyID(String),
    #[error("Key ID {0} isn't known")]
    WrongIssuer(String),
}
