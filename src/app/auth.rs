use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    http::{header, StatusCode},
    routing::post,
    Extension, Json, Router, TypedHeader,
};
use chrono::{Duration, Utc};
use headers::{authorization::Bearer, Authorization, HeaderName};
use rand::Rng;
use serde::Deserialize;
use sqlx::{Pool, Postgres};

use crate::model::Token;

#[derive(Debug, Deserialize)]
struct GrantDto {
    username: String,
    password: String,
}

#[derive(Debug)]
enum GrantError {
    DeletedUser,
    InvalidCredentials,
    NotFound,
    Database(sqlx::Error),
    Hashing(argon2::password_hash::Error),
}

async fn grant(pool: &Pool<Postgres>, dto: GrantDto) -> Result<Token, GrantError> {
    // Retrieve auth information.
    let auth = sqlx::query!(
        "
        SELECT id, password
        FROM Users
        WHERE username = $1
        ",
        dto.username
    )
    .fetch_one(pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::RowNotFound => GrantError::NotFound,
        _ => GrantError::Database(err),
    })?;

    if let Some(password) = auth.password {
        // Verify password.
        Argon2::default()
            .verify_password(
                dto.password.as_bytes(),
                &PasswordHash::new(&password).map_err(GrantError::Hashing)?,
            )
            .map_err(|_| GrantError::InvalidCredentials)?;

        // Generate token.
        let token = hex::encode(rand::thread_rng().gen::<[u8; 24]>());
        let expires = Utc::now() + Duration::days(24);

        // Push token to database.
        sqlx::query!(
            "
            INSERT INTO
                Tokens (token, user_id, expires)
                VALUES ($1, $2, $3)
            ",
            token,
            auth.id,
            expires
        )
        .execute(pool)
        .await
        .map_err(GrantError::Database)?;

        Ok(Token {
            token,
            user_id: auth.id,
            expires,
        })
    } else {
        Err(GrantError::DeletedUser)
    }
}

#[derive(Debug)]
enum RevokeError {
    Database(sqlx::Error),
}

async fn revoke(pool: &Pool<Postgres>, token: &str) -> Result<(), RevokeError> {
    sqlx::query!(
        "
        DELETE FROM Tokens
        WHERE token = $1
        ",
        token
    )
    .execute(pool)
    .await
    .map_err(RevokeError::Database)?;

    Ok(())
}

#[derive(Debug)]
enum RevokeAllError {
    Database(sqlx::Error),
}

async fn revoke_all(pool: &Pool<Postgres>, token: &str) -> Result<(), RevokeAllError> {
    sqlx::query!(
        "
        WITH user_id AS (
            SELECT user_id
            FROM Tokens
            WHERE token = $1
        )
        DELETE FROM Tokens
        WHERE user_id = user_id
        ",
        token
    )
    .execute(pool)
    .await
    .map_err(RevokeAllError::Database)?;

    Ok(())
}

type GrantResult = Result<([(HeaderName, String); 1], Json<Token>), StatusCode>;
type RevokeResult = Result<(), StatusCode>;

pub fn controllers() -> Router {
    Router::new()
        .route(
            "/grant",
            post(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            Json(dto): Json<GrantDto>|
                            -> GrantResult {
                    let token = grant(&pool, dto).await.map_err(|err| match err {
                        GrantError::InvalidCredentials
                        | GrantError::DeletedUser
                        | GrantError::NotFound => StatusCode::FORBIDDEN,
                        GrantError::Database(_) | GrantError::Hashing(_) => {
                            tracing::error!("{:?}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    })?;

                    Ok(([(header::EXPIRES, token.expires.to_rfc2822())], Json(token)))
                },
            ),
        )
        .route(
            "/revoke",
            post(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            TypedHeader(Authorization(bearer)): TypedHeader<
                    Authorization<Bearer>,
                >|
                            -> RevokeResult {
                    revoke(&pool, bearer.token())
                        .await
                        .map_err(|err| match err {
                            RevokeError::Database(_) => {
                                tracing::error!("{:?}", err);
                                StatusCode::INTERNAL_SERVER_ERROR
                            }
                        })?;

                    Ok(())
                },
            ),
        )
        .route(
            "/revoke-all",
            post(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            TypedHeader(Authorization(bearer)): TypedHeader<
                    Authorization<Bearer>,
                >|
                            -> RevokeResult {
                    revoke_all(&pool, bearer.token())
                        .await
                        .map_err(|err| match err {
                            RevokeAllError::Database(_) => {
                                tracing::error!("{:?}", err);
                                StatusCode::INTERNAL_SERVER_ERROR
                            }
                        })?;

                    Ok(())
                },
            ),
        )
}
