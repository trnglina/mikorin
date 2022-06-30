use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    http::{header, StatusCode},
    routing::post,
    Extension, Json, Router, TypedHeader,
};
use chrono::{DateTime, Duration, Utc};
use headers::{authorization::Bearer, Authorization, HeaderName};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

#[derive(Debug, Serialize)]
struct Token {
    token: String,
    user_id: i64,
    expires: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct SignInDto {
    username: String,
    password: String,
}

#[derive(Debug)]
enum SignInError {
    DeletedUser,
    InvalidCredentials,
    NotFound,
    Database(sqlx::Error),
    Hashing(argon2::password_hash::Error),
}

async fn sign_in(pool: &Pool<Postgres>, dto: SignInDto) -> Result<Token, SignInError> {
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
        sqlx::Error::RowNotFound => SignInError::NotFound,
        _ => SignInError::Database(err),
    })?;

    if let Some(password) = auth.password {
        // Verify password.
        Argon2::default()
            .verify_password(
                dto.password.as_bytes(),
                &PasswordHash::new(&password).map_err(SignInError::Hashing)?,
            )
            .map_err(|_| SignInError::InvalidCredentials)?;

        // Generate token.
        let token = hex::encode(rand::thread_rng().gen::<[u8; 24]>());
        let expires = Utc::now() + Duration::days(24);

        // Push token to database.
        sqlx::query!(
            "
            INSERT INTO
                UserTokens (token, user_id, expires)
                VALUES ($1, $2, $3)
            ",
            token,
            auth.id,
            expires
        )
        .execute(pool)
        .await
        .map_err(SignInError::Database)?;

        Ok(Token {
            token,
            user_id: auth.id,
            expires,
        })
    } else {
        Err(SignInError::DeletedUser)
    }
}

#[derive(Debug)]
enum SignOutError {
    Database(sqlx::Error),
}

async fn sign_out(pool: &Pool<Postgres>, token: &str) -> Result<(), SignOutError> {
    sqlx::query!(
        "
        DELETE FROM UserTokens
        WHERE token = $1
        ",
        token
    )
    .execute(pool)
    .await
    .map_err(SignOutError::Database)?;

    Ok(())
}

type SignInResult = Result<([(HeaderName, String); 1], Json<Token>), StatusCode>;
type SignOutResult = Result<(), StatusCode>;

pub fn controllers() -> Router {
    Router::new()
        .route(
            "/sign-in",
            post(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            Json(dto): Json<SignInDto>|
                            -> SignInResult {
                    let token = sign_in(&pool, dto).await.map_err(|err| match err {
                        SignInError::InvalidCredentials
                        | SignInError::DeletedUser
                        | SignInError::NotFound => StatusCode::FORBIDDEN,
                        SignInError::Database(_) | SignInError::Hashing(_) => {
                            tracing::error!("{:?}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    })?;

                    Ok(([(header::EXPIRES, token.expires.to_rfc2822())], Json(token)))
                },
            ),
        )
        .route(
            "/sign-out",
            post(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            TypedHeader(Authorization(bearer)): TypedHeader<
                    Authorization<Bearer>,
                >|
                            -> SignOutResult {
                    sign_out(&pool, &bearer.token())
                        .await
                        .map_err(|err| match err {
                            SignOutError::Database(_) => {
                                tracing::error!("{:?}", err);
                                StatusCode::INTERNAL_SERVER_ERROR
                            }
                        })?;

                    Ok(())
                },
            ),
        )
}
