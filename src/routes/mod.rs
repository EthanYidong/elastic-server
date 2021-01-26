pub mod auth;

use warp::Filter;

pub fn extractor<T: Clone + Send>(extract: T) -> impl Filter<Extract = (T,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || extract.clone())
}
