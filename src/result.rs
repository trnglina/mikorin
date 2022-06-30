use axum::{http::StatusCode, Json};
use headers::HeaderName;

pub type CreateResult<T> = Result<(StatusCode, [(HeaderName, String); 1], Json<T>), StatusCode>;
pub type ListResult<T> = Result<Json<Vec<T>>, StatusCode>;
pub type ShowResult<T> = Result<Json<T>, StatusCode>;
pub type UpdateResult = Result<StatusCode, StatusCode>;
pub type DeleteResult = Result<StatusCode, StatusCode>;
