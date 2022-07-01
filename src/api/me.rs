use axum::{http::StatusCode, routing::get, Extension, Router};
use axum_extra::extract::CookieJar;
use sqlx::{Pool, Postgres};

use crate::{
    config,
    model::{Group, User},
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
        let partial_user = sqlx::query!(
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
        })?;

        let groups = sqlx::query_as!(
            Group,
            r#"
            SELECT
                Groups.id,
                Groups.name,
                ARRAY_REMOVE(Groups.permissions, NULL) as "permissions!: Vec<String>"
            FROM UserGroups JOIN Groups ON UserGroups.group_id = Groups.id
            WHERE UserGroups.user_id = $1
            "#,
            partial_user.id
        )
        .fetch_all(&pool)
        .await
        .map_err(|err| internal_error!(err))?;

        Ok(action::Show(User {
            id: partial_user.id,
            name: partial_user.name,
            groups,
        }))
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
