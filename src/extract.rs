use std::{collections::HashSet, convert::Infallible};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::StatusCode,
    TypedHeader,
};
use axum_extra::extract::CookieJar;
use headers::{authorization::Basic, Authorization};
use sqlx::{Pool, Postgres};

use crate::config;

async fn extract_session_id<B>(req: &mut RequestParts<B>) -> Option<String>
where
    B: Send,
{
    CookieJar::from_request(req)
        .await
        .unwrap()
        .get(config::COOKIE_SESSION_ID)
        .map(|x| x.value().to_string())
}

async fn extract_state<B>(req: &mut RequestParts<B>) -> Result<&Pool<Postgres>, ()>
where
    B: Send,
{
    req.extensions().get::<Pool<Postgres>>().map_or(Err(()), Ok)
}

#[derive(Debug)]
pub struct Authenticated {
    pub user_id: i64,
    pub session_id: String,
}

#[async_trait]
impl<B> FromRequest<B> for Authenticated
where
    B: Send,
{
    type Rejection = StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let session_id = extract_session_id(req).await.ok_or(StatusCode::FORBIDDEN)?;
        let pool = extract_state(req).await.map_err(|_| {
            tracing::error!("no database connection retrievable");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        Ok(Self {
            user_id: sqlx::query_scalar!(
                r#"
                SELECT user_id
                FROM Sessions
                WHERE id = $1 AND expires > NOW()
                "#,
                session_id
            )
            .fetch_one(pool)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => StatusCode::FORBIDDEN,
                _ => {
                    tracing::error!("{}", err);
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            })?,
            session_id,
        })
    }
}

#[derive(Debug)]
pub struct Authorized {
    pub user_id: i64,
    pub session_id: String,
    pub permissions: HashSet<String>,
}

#[async_trait]
impl<B> FromRequest<B> for Authorized
where
    B: Send,
{
    type Rejection = StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let session_id = extract_session_id(req).await.ok_or(StatusCode::FORBIDDEN)?;
        let pool = extract_state(req).await.map_err(|_| {
            tracing::error!("no database connection retrievable");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let record = sqlx::query!(
            r#"
            SELECT Sessions.user_id, UserGroups.permissions as "permissions: Vec<String>"
            FROM Sessions JOIN Users ON Sessions.user_id = Users.id
                          JOIN UserGroups ON Users.group_id = UserGroups.id
            WHERE Sessions.id = $1 AND Sessions.expires > NOW()
            "#,
            session_id
        )
        .fetch_one(pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => StatusCode::FORBIDDEN,
            _ => {
                tracing::error!("{}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

        Ok(Self {
            user_id: record.user_id,
            session_id,
            permissions: HashSet::from_iter(record.permissions),
        })
    }
}

#[derive(Debug)]
pub struct Priveledged {
    pub user_id: i64,
}

#[async_trait]
impl<B> FromRequest<B> for Priveledged
where
    B: Send,
{
    type Rejection = StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(credentials)) =
            TypedHeader::<Authorization<Basic>>::from_request(req)
                .await
                .map_err(|_| StatusCode::FORBIDDEN)?;
        let pool = extract_state(req).await.map_err(|_| {
            tracing::error!("no database connection retrievable");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Retrieve auth information.
        let auth_user = sqlx::query!(
            r#"
            SELECT id, digest as "digest!: String"
            FROM Users
            WHERE username = $1 AND digest IS NOT NULL
            "#,
            credentials.username()
        )
        .fetch_one(pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => StatusCode::FORBIDDEN,
            _ => internal_error!(err),
        })?;

        // Verify password.
        Argon2::default()
            .verify_password(
                credentials.password().as_bytes(),
                &PasswordHash::new(&auth_user.digest).map_err(|err| internal_error!(err))?,
            )
            .map_err(|_| StatusCode::FORBIDDEN)?;

        Ok(Self {
            user_id: auth_user.id,
        })
    }
}

#[derive(Debug)]
pub struct Maybe<T>(pub Option<T>);

#[async_trait]
impl<B, T> FromRequest<B> for Maybe<T>
where
    B: Send,
    T: FromRequest<B>,
{
    type Rejection = Infallible;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        Ok(Self(T::from_request(req).await.ok()))
    }
}
