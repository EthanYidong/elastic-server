use serde::{Serialize, Deserialize};

use thiserror::Error;

use jsonwebtoken as jwt;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

// 30 days
pub const JWT_DURATION: Duration = Duration::from_secs(60 * 60 * 24 * 30);

pub struct TokenHelper {
    _jwt_secret: String,
    encoding_key: jwt::EncodingKey,
    decoding_key: jwt::DecodingKey<'static>,
}

impl TokenHelper {
    pub fn new() -> Result<TokenHelper, TokenHelperError> {
        let jwt_secret = dotenv::var("JWT_SECRET")?;
        let encoding_key = jwt::EncodingKey::from_base64_secret(&jwt_secret)?;
        let decoding_key = jwt::DecodingKey::from_base64_secret(&jwt_secret)?;

        Ok(TokenHelper {
            _jwt_secret: jwt_secret,
            encoding_key,
            decoding_key,
        })
    }

    pub fn encode(&self, claims: TokenClaims) -> Result<String, jwt::errors::Error> {
        jwt::encode(
            &jwt::Header::default(),
            &claims,
            &self.encoding_key,
        )
    }

    pub fn decode(&self, token: &str) -> Result<TokenClaims, jwt::errors::Error> {
        jwt::decode(
            token,
            &self.decoding_key,
            &jwt::Validation::default(),
        ).map(|token_data| token_data.claims)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenClaims {
    pub exp: u64,
    pub user_id: String,
}

impl TokenClaims {
    pub fn new(user_id: String) -> TokenClaims {
        TokenClaims {
            exp: (SystemTime::now() + JWT_DURATION).duration_since(UNIX_EPOCH).unwrap().as_secs(),
            user_id,
        }
    }
}

#[derive(Error, Debug)]
pub enum TokenHelperError {
    #[error("Error from dotenv: {0}")]
    EnvError(#[from] dotenv::Error),
    #[error("Error from jwt: {0}")]
    JWTError(#[from] jwt::errors::Error),
}
