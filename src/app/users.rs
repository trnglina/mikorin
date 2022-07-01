use std::cmp::min;

use argon2::{
    password_hash::{rand_core, SaltString},
    Argon2, PasswordHasher,
};
use axum::{
    extract::{OriginalUri, Path, Query},
    http::{header, StatusCode},
    routing::get,
    Extension, Json, Router,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use sqlx::{Pool, Postgres, QueryBuilder};

use crate::{
    config,
    extract::Authenticated,
    model::{Group, User},
    result::{CreateResult, DeleteResult, ListResult, ShowResult, UpdateResult},
    serde::deserialize_some,
};

lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new("^[a-zA-Z0-9_\\-]{4,64}$").unwrap();
    static ref PASSWORD_REGEX: Regex = Regex::new("^.{8,512}$").unwrap();
}

async fn get_groups(pool: &Pool<Postgres>, group_ids: Vec<i64>) -> Result<Vec<Group>, sqlx::Error> {
    sqlx::query_as!(
        Group,
        r#"
        SELECT
            Groups.id,
            Groups.name,
            ARRAY_AGG(GroupPermissions.permission_name) as "permissions!: Vec<String>"
        FROM Groups JOIN GroupPermissions ON Groups.id = GroupPermissions.group_id
        WHERE Groups.id = ANY($1)
        GROUP BY Groups.id
        "#,
        &group_ids[..]
    )
    .fetch_all(pool)
    .await
}

#[derive(Debug, Deserialize)]
struct ListUsersQuery {
    offset: Option<i64>,
    limit: Option<i64>,
}

#[derive(Debug)]
enum ListUsersError {
    Database(sqlx::Error),
}

async fn list_users(
    pool: &Pool<Postgres>,
    offset: i64,
    limit: i64,
) -> Result<Vec<User>, ListUsersError> {
    let limit = min(limit, config::PAGINATION_MAX_LIMIT);

    let records = sqlx::query!(
        r#"
        SELECT
            Users.id,
            Users.name,
            ARRAY_REMOVE(ARRAY_AGG(UserGroups.group_id), NULL) as "groups: Vec<i64>"
        FROM Users LEFT OUTER JOIN UserGroups ON Users.id = UserGroups.user_id
        GROUP BY Users.id
        ORDER BY Users.id
        OFFSET $1
        LIMIT $2
        "#,
        offset,
        limit
    )
    .fetch_all(pool)
    .await
    .map_err(ListUsersError::Database)?;

    let mut users: Vec<User> = Vec::new();
    for record in records {
        let groups = if let Some(group_ids) = record.groups {
            get_groups(pool, group_ids)
                .await
                .map_err(ListUsersError::Database)?
        } else {
            Vec::new()
        };

        users.push(User {
            id: record.id,
            name: record.name,
            groups,
        })
    }

    Ok(users)
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
    if !USERNAME_REGEX.is_match(&dto.username) || !PASSWORD_REGEX.is_match(&dto.password) {
        return Err(CreateUserError::CredentialValidation);
    }

    let salt = SaltString::generate(&mut rand_core::OsRng);
    let hash = Argon2::default()
        .hash_password(dto.password.as_bytes(), &salt)
        .map_err(CreateUserError::Hashing)?;

    let record = sqlx::query!(
        "
        INSERT INTO
            Users (username, password, name)
            VALUES ($1, $2, $3)
        RETURNING id, name
        ",
        dto.username,
        hash.to_string(),
        dto.name
    )
    .fetch_one(pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(db) if "23505" == db.code().unwrap() => CreateUserError::Conflict,
        _ => CreateUserError::Database(err),
    })?;

    Ok(User {
        id: record.id,
        name: record.name,
        groups: Vec::new(),
    })
}

#[derive(Debug)]
enum ShowUserError {
    NotFound,
    Database(sqlx::Error),
}

async fn show_user(pool: &Pool<Postgres>, id: i64) -> Result<User, ShowUserError> {
    let record = sqlx::query!(
        r#"
        SELECT
            id,
            name,
            ARRAY_REMOVE(ARRAY_AGG(UserGroups.group_id), NULL) as "groups: Vec<i64>"
        FROM Users LEFT OUTER JOIN UserGroups ON Users.id = UserGroups.user_id
        WHERE id = $1
        GROUP BY Users.id
        "#,
        id
    )
    .fetch_one(pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::RowNotFound => ShowUserError::NotFound,
        _ => ShowUserError::Database(err),
    })?;

    let groups = if let Some(group_ids) = record.groups {
        get_groups(pool, group_ids)
            .await
            .map_err(ShowUserError::Database)?
    } else {
        Vec::new()
    };

    Ok(User {
        id: record.id,
        name: record.name,
        groups,
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
            Some(pword) if PASSWORD_REGEX.is_match(pword) => Some(
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
            sqlx::query!(
                "
                DELETE FROM Tokens
                WHERE user_id = $1
                ",
                id
            )
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
        "
        UPDATE Users SET
            username = NULL,
            password = NULL,
            name = NULL
        WHERE id = $1
        ",
        id
    )
    .execute(pool)
    .await
    .map_err(DeleteUserError::Database)?;

    // Revoke all tokens.
    sqlx::query!(
        "
        DELETE FROM Tokens
        WHERE user_id = $1
        ",
        id
    )
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
                async move |Extension(pool): Extension<Pool<Postgres>>,
                            Query(query): Query<ListUsersQuery>|
                            -> ListResult<User> {
                    let users = list_users(
                        &pool,
                        query.offset.unwrap_or(0),
                        query.limit.unwrap_or(config::PAGINATION_MAX_LIMIT),
                    )
                    .await
                    .map_err(|err| {
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
                            Authenticated(user_id): Authenticated|
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
                            Authenticated(user_id): Authenticated|
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
