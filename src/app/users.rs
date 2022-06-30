use argon2::{
    password_hash::{rand_core, SaltString},
    Argon2, PasswordHasher,
};
use axum::{
    extract::{OriginalUri, Path},
    http::{header, StatusCode},
    routing::get,
    Extension, Json, Router,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, QueryBuilder};

use crate::{
    extract::Authenticated,
    result::{CreateResult, DeleteResult, ListResult, ShowResult, UpdateResult},
    serde::deserialize_some,
};

lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new("^[a-zA-Z0-9_\\-]{4,64}$").unwrap();
}

#[derive(Debug, Serialize)]
struct User {
    id: i64,
    name: Option<String>,
}

#[derive(Debug)]
enum ListUsersError {
    Database(sqlx::Error),
}

async fn list_users(pool: &Pool<Postgres>) -> Result<Vec<User>, ListUsersError> {
    sqlx::query_as!(User, "SELECT id, name FROM Users")
        .fetch_all(pool)
        .await
        .map_err(ListUsersError::Database)
}

#[derive(Debug, Deserialize)]
struct CreateUserDto {
    username: String,
    password: String,
    name: Option<String>,
}

#[derive(Debug)]
enum CreateUserError {
    Conflict,
    CredentialValidation,
    Database(sqlx::Error),
    Hashing(argon2::password_hash::Error),
}

async fn create_user(pool: &Pool<Postgres>, dto: CreateUserDto) -> Result<User, CreateUserError> {
    if !USERNAME_REGEX.is_match(&dto.username) || !(8..=512).contains(&dto.password.len()) {
        return Err(CreateUserError::CredentialValidation);
    }

    let salt = SaltString::generate(&mut rand_core::OsRng);
    let hash = Argon2::default()
        .hash_password(dto.password.as_bytes(), &salt)
        .map_err(CreateUserError::Hashing)?;

    Ok(sqlx::query_as!(
        User,
        "INSERT INTO Users (username, password, name) VALUES ($1, $2, $3) RETURNING id, name",
        dto.username,
        hash.to_string(),
        dto.name
    )
    .fetch_one(pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(db) if "23505" == db.code().unwrap() => CreateUserError::Conflict,
        _ => CreateUserError::Database(err),
    })?)
}

#[derive(Debug)]
enum ShowUserError {
    NotFound,
    Database(sqlx::Error),
}

async fn show_user(pool: &Pool<Postgres>, id: i64) -> Result<User, ShowUserError> {
    sqlx::query_as!(User, "SELECT id, name FROM Users WHERE id = $1", id)
        .fetch_one(pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => ShowUserError::NotFound,
            _ => ShowUserError::Database(err),
        })
}

#[derive(Debug, Deserialize)]
struct UpdateUserDto {
    username: Option<String>,
    password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    name: Option<Option<String>>,
}

#[derive(Debug)]
enum UpdateUserError {
    Conflict,
    CredentialValidation,
    Database(sqlx::Error),
    Hashing(argon2::password_hash::Error),
}

async fn update_user(
    pool: &Pool<Postgres>,
    id: i64,
    dto: UpdateUserDto,
) -> Result<(), UpdateUserError> {
    // Only do something if at least one field is set.
    if dto.username.is_some() || dto.password.is_some() || dto.name.is_some() {
        // Validate username if set.
        let username = match &dto.username {
            Some(uname) if USERNAME_REGEX.is_match(uname) => Some(uname),
            Some(_) => return Err(UpdateUserError::CredentialValidation),
            None => None,
        };

        // Validate password and hash if set.
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let hash = match &dto.password {
            Some(pword) if (8..=512).contains(&pword.len()) => Some(
                Argon2::default()
                    .hash_password(pword.as_bytes(), &salt)
                    .map_err(UpdateUserError::Hashing)?,
            ),
            Some(_) => return Err(UpdateUserError::CredentialValidation),
            None => None,
        };

        // Construct query.
        let mut query = QueryBuilder::<Postgres>::new("UPDATE Users SET ");
        if let Some(uname) = username {
            query.push("username = ");
            query.push_bind(uname);
        }
        if let Some(hash) = hash {
            query.push("password = ");
            query.push_bind(hash.to_string());
        }
        if let Some(name) = dto.name {
            query.push("name = ");
            query.push_bind(name);
        }
        query.push("WHERE id = ");
        query.push_bind(id);

        // Execute query.
        query.build().execute(pool).await.map_err(|err| match err {
            sqlx::Error::Database(db) if "23505" == db.code().unwrap() => UpdateUserError::Conflict,
            _ => UpdateUserError::Database(err),
        })?;

        // If username or password were successfully changed, also revoke all tokens.
        if dto.username.is_some() || dto.password.is_some() {
            sqlx::query!("DELETE FROM UserTokens WHERE user_id = $1", id)
                .execute(pool)
                .await
                .map_err(UpdateUserError::Database)?;
        }
    }

    Ok(())
}

#[derive(Debug)]
enum DeleteUserError {
    Database(sqlx::Error),
}

async fn delete_user(pool: &Pool<Postgres>, id: i64) -> Result<(), DeleteUserError> {
    sqlx::query!(
        "UPDATE Users SET username = NULL, password = NULL, name = NULL WHERE id = $1",
        id
    )
    .execute(pool)
    .await
    .map_err(DeleteUserError::Database)?;

    // Revoke all tokens.
    sqlx::query!("DELETE FROM UserTokens WHERE user_id = $1", id)
        .execute(pool)
        .await
        .map_err(DeleteUserError::Database)?;

    Ok(())
}

pub fn controllers() -> Router {
    Router::new()
        .route(
            "/",
            get(
                async move |Extension(pool): Extension<Pool<Postgres>>| -> ListResult<User> {
                    let users = list_users(&pool).await.map_err(|err| {
                        tracing::error!("{:?}", err);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

                    Ok(Json(users))
                },
            )
            .post(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            OriginalUri(uri): OriginalUri,
                            Json(dto): Json<CreateUserDto>|
                            -> CreateResult<User> {
                    let user = create_user(&pool, dto).await.map_err(|err| match err {
                        CreateUserError::Conflict => StatusCode::CONFLICT,
                        CreateUserError::CredentialValidation => StatusCode::BAD_REQUEST,
                        CreateUserError::Database(_) | CreateUserError::Hashing(_) => {
                            tracing::error!("{:?}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    })?;

                    Ok((
                        StatusCode::CREATED,
                        [(header::LOCATION, format!("{}/{}", uri, user.id))],
                        Json(user),
                    ))
                },
            ),
        )
        .route(
            "/:id",
            get(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            Path(id): Path<i64>|
                            -> ShowResult<User> {
                    let user = show_user(&pool, id).await.map_err(|err| match err {
                        ShowUserError::NotFound => StatusCode::NOT_FOUND,
                        ShowUserError::Database(_) => {
                            tracing::error!("{:?}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    })?;

                    Ok(Json(user))
                },
            )
            .patch(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            Path(id): Path<i64>,
                            Json(dto): Json<UpdateUserDto>,
                            Authenticated(user_id, _): Authenticated|
                            -> UpdateResult {
                    if user_id != id {
                        return Err(StatusCode::FORBIDDEN);
                    }

                    update_user(&pool, id, dto).await.map_err(|err| match err {
                        UpdateUserError::Conflict => StatusCode::CONFLICT,
                        UpdateUserError::CredentialValidation => StatusCode::BAD_REQUEST,
                        UpdateUserError::Database(_) | UpdateUserError::Hashing(_) => {
                            tracing::error!("{:?}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    })?;

                    Ok(StatusCode::NO_CONTENT)
                },
            )
            .delete(
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            Path(id): Path<i64>,
                            Authenticated(user_id, _): Authenticated|
                            -> DeleteResult {
                    if user_id != id {
                        return Err(StatusCode::FORBIDDEN);
                    }

                    delete_user(&pool, id).await.map_err(|err| match err {
                        DeleteUserError::Database(_) => {
                            tracing::error!("{:?}", err);
                            StatusCode::INTERNAL_SERVER_ERROR
                        }
                    })?;

                    Ok(StatusCode::NO_CONTENT)
                },
            ),
        )
}
