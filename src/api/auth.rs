use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use chrono::{Duration, Utc};
use rand::Rng;
use serde::Deserialize;
use sqlx::{Pool, Postgres};

use crate::config;

struct AuthUser {
    pub id: i64,
    pub digest: String,
}

pub fn controllers() -> Router {
    Router::new()
        .route("/sign-in", post(sign_in))
        .route("/sign-out", post(sign_out))
}

#[derive(Debug, Deserialize)]
struct SignInBody {
    username: String,
    password: String,
}

async fn sign_in(
    Extension(pool): Extension<Pool<Postgres>>,
    Json(body): Json<SignInBody>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), StatusCode> {
    // Retrieve auth information.
    let auth_user = sqlx::query_as!(
        AuthUser,
        r#"
        SELECT id, digest as "digest!: String"
        FROM Users
        WHERE username = $1 AND digest IS NOT NULL
        "#,
        body.username
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::RowNotFound => StatusCode::FORBIDDEN,
        _ => internal_error!(err),
    })?;

    // Verify password.
    Argon2::default()
        .verify_password(
            body.password.as_bytes(),
            &PasswordHash::new(&auth_user.digest).map_err(|err| internal_error!(err))?,
        )
        .map_err(|_| StatusCode::FORBIDDEN)?;

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
        auth_user.id,
        expires
    )
    .execute(&pool)
    .await
    .map_err(|err| internal_error!(err))?;

    // Construct cookie.
    let mut cookie = Cookie::new(config::COOKIE_SESSION_KEY, session_id);
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_max_age(time::Duration::days(24));
    cookie.set_path(config::API_ROUTE);

    Ok((jar.add(cookie), StatusCode::NO_CONTENT))
}

async fn sign_out(
    Extension(pool): Extension<Pool<Postgres>>,
    jar: CookieJar,
) -> (CookieJar, StatusCode) {
    if let Some(session_id) = jar
        .get(config::COOKIE_SESSION_KEY)
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
        jar.remove(Cookie::named(config::COOKIE_SESSION_KEY)),
        StatusCode::NO_CONTENT,
    )
}
