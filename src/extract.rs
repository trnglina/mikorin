use std::collections::HashSet;

use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::StatusCode,
    response::{IntoResponse, Response},
    TypedHeader,
};
use headers::{authorization::Bearer, Authorization};
use sqlx::{Pool, Postgres};

async fn extract_bearer<B>(req: &mut RequestParts<B>) -> Result<Bearer, ()>
where
    B: Send,
{
    let TypedHeader(Authorization(bearer)) =
        TypedHeader::<Authorization<Bearer>>::from_request(req)
            .await
            .map_err(|_| ())?;

    Ok(bearer)
}

async fn extract_state<B>(req: &mut RequestParts<B>) -> Result<&Pool<Postgres>, ()>
where
    B: Send,
{
    req.extensions().get::<Pool<Postgres>>().map_or(Err(()), Ok)
}

async fn get_user_id(pool: &Pool<Postgres>, token: &str) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query!(
        "
        SELECT user_id
        FROM Tokens
        WHERE token = $1 AND expires > now()
        ",
        token
    )
    .fetch_one(pool)
    .await?
    .user_id)
}

async fn get_user_permissions(
    pool: &Pool<Postgres>,
    user_id: i64,
) -> Result<HashSet<String>, sqlx::Error> {
    Ok(HashSet::from_iter(
        sqlx::query!(
            "
            SELECT permission_name
            FROM UserGroups INNER JOIN GroupPermissions ON UserGroups.group_id = GroupPermissions.group_id
            WHERE UserGroups.user_id = $1
            ",
            user_id
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|row| row.permission_name),
    ))
}

#[derive(Debug)]
pub struct Authenticated(pub i64);

#[async_trait]
impl<B> FromRequest<B> for Authenticated
where
    B: Send,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let bearer = extract_bearer(req).await.map_err(|_| {
            (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer")]).into_response()
        })?;

        let pool = extract_state(req).await.map_err(|_| {
            tracing::error!("no database connection retrievable");
            (StatusCode::INTERNAL_SERVER_ERROR).into_response()
        })?;

        let user_id = get_user_id(pool, bearer.token())
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => StatusCode::FORBIDDEN.into_response(),
                _ => {
                    tracing::error!("{}", err);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            })?;

        Ok(Self(user_id))
    }
}

#[derive(Debug)]
pub struct Authorized(pub i64, pub HashSet<String>);

#[async_trait]
impl<B> FromRequest<B> for Authorized
where
    B: Send,
{
    type Rejection = Response;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let bearer = extract_bearer(req).await.map_err(|_| {
            (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer")]).into_response()
        })?;

        let pool = extract_state(req).await.map_err(|_| {
            tracing::error!("no database connection retrievable");
            (StatusCode::INTERNAL_SERVER_ERROR).into_response()
        })?;

        let user_id = get_user_id(pool, bearer.token())
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => StatusCode::FORBIDDEN.into_response(),
                _ => {
                    tracing::error!("{}", err);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            })?;

        let permissions = get_user_permissions(pool, user_id).await.map_err(|err| {
            tracing::error!("{}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

        Ok(Self(user_id, permissions))
    }
}
