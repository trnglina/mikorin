use std::collections::HashSet;

use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::StatusCode,
};
use axum_extra::extract::CookieJar;
use sqlx::{Pool, Postgres};

use crate::config;

async fn extract_session_id<B>(req: &mut RequestParts<B>) -> Option<String>
where
    B: Send,
{
    CookieJar::from_request(req)
        .await
        .unwrap()
        .get(config::COOKIE_SESSION_KEY)
        .map(|x| x.value().to_string())
}

async fn extract_state<B>(req: &mut RequestParts<B>) -> Result<&Pool<Postgres>, ()>
where
    B: Send,
{
    req.extensions().get::<Pool<Postgres>>().map_or(Err(()), Ok)
}

#[derive(Debug)]
pub struct Authenticated(pub i64);

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

        Ok(Self(
            sqlx::query_scalar!(
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
        ))
    }
}

#[derive(Debug)]
pub struct Authorized(pub i64, pub HashSet<String>);

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
            SELECT Sessions.user_id, ARRAY_AGG(perms) as "permissions: Vec<String>"
            FROM Sessions JOIN UserGroups ON Sessions.user_id = UserGroups.user_id
                          JOIN Groups ON UserGroups.group_id = Groups.id,
                 UNNEST(Groups.permissions) as perms
            WHERE Sessions.id = $1 AND Sessions.expires > NOW()
            GROUP BY Sessions.user_id
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

        Ok(Self(
            record.user_id,
            HashSet::from_iter(record.permissions.unwrap_or_default()),
        ))
    }
}
