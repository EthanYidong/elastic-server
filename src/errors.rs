use warp::reject;
use warp::http::StatusCode;

use thiserror::Error;

#[derive(Debug)]
pub struct InternalError;

impl InternalError {
    pub fn log(error: impl std::fmt::Debug) -> InternalError {
        log::error!("{:?}", error);
        InternalError
    }
}

impl reject::Reject for InternalError {}

#[derive(Error, Debug)]
pub enum BadRequest {
    #[error("Invalid token")]
    InvalidTokenError(#[from] crate::google_auth::InvalidTokenError),
}

impl reject::Reject for BadRequest {}

pub async fn handle_rejection(err: reject::Rejection) -> Result<impl warp::Reply, std::convert::Infallible> {
    Ok(if err.is_not_found() {
        warp::reply::with_status(String::from("not found"), StatusCode::NOT_FOUND)
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        warp::reply::with_status(String::from("method not allowed"), StatusCode::METHOD_NOT_ALLOWED)
    } else if let Some(e) = err.find::<BadRequest>() {
        warp::reply::with_status(format!("{}", e), StatusCode::BAD_REQUEST)
    } else if let Some(_) = err.find::<InternalError>() {
        warp::reply::with_status(String::from("internal server error"), StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        log::error!("{:?}", err);
        warp::reply::with_status(String::from("unhandled internal server error"), StatusCode::INTERNAL_SERVER_ERROR)
    })
}
