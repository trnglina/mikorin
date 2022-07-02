use axum::{http::StatusCode, response::Redirect, routing::post, Extension, Router};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use chrono::{Duration, Utc};
use rand::Rng;
use sqlx::{Pool, Postgres};

use crate::{config, extract::Priveledged};

pub fn controllers() -> Router {
    Router::new()
        .route("/sign-in", post(sign_in))
        .route("/sign-out", post(sign_out))
}

async fn sign_in(
    Extension(pool): Extension<Pool<Postgres>>,
    priveledged: Priveledged,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), StatusCode> {
    // Generate session.
    let session_id = hex::encode(rand::thread_rng().gen::<[u8; 24]>());
    let expires = Utc::now() + Duration::days(24);

    // Push session to database.
    sqlx::query!(
        r#"
        INSERT INTO Sessions (id, user_id, expires)
                    VALUES ($1, $2, $3)
        "#,
        session_id,
        priveledged.user_id,
        expires
    )
    .execute(&pool)
    .await
    .map_err(|err| internal_error!(err))?;

    // Construct cookie.
    let mut cookie = Cookie::new(config::COOKIE_SESSION_ID, session_id);
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_max_age(time::Duration::days(24));
    cookie.set_path(config::API_ROUTE);

    Ok((
        jar.add(cookie),
        Redirect::to(&format!(
            "{}/users/{}",
            config::API_ROUTE,
            priveledged.user_id
        )),
    ))
}

async fn sign_out(
    Extension(pool): Extension<Pool<Postgres>>,
    jar: CookieJar,
) -> (CookieJar, StatusCode) {
    if let Some(session_id) = jar
        .get(config::COOKIE_SESSION_ID)
        .map(|x| x.value().to_string())
    {
        // Remove session from database.
        let _ = sqlx::query!(
            "
            DELETE FROM Sessions
            WHERE id = $1
            ",
            session_id
        )
        .execute(&pool)
        .await
        .map_err(|err| internal_error!(err));
    }

    (
        jar.remove(Cookie::named(config::COOKIE_SESSION_ID)),
        StatusCode::NO_CONTENT,
    )
}
