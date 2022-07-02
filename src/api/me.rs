use axum::{http::StatusCode, routing::get, Extension, Router};
use axum_extra::extract::CookieJar;
use sqlx::{Pool, Postgres};

use crate::{
    config,
    model::User,
    utility::{action, ApiResult},
};

pub fn controllers() -> Router {
    Router::new().route("/", get(show_me))
}

async fn show_me(
    Extension(pool): Extension<Pool<Postgres>>,
    jar: CookieJar,
) -> ApiResult<action::Show<User>> {
    if let Some(session_id) = jar
        .get(config::COOKIE_SESSION_KEY)
        .map(|x| x.value().to_string())
    {
        Ok(action::Show(
            sqlx::query_as!(
                User,
                r#"
                SELECT Users.id, Users.name
                FROM Sessions JOIN Users ON Sessions.user_id = Users.id
                WHERE Sessions.id = $1
                "#,
                session_id,
            )
            .fetch_one(&pool)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => StatusCode::FORBIDDEN,
                _ => internal_error!(err),
            })?,
        ))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
