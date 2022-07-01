use argon2::{
    password_hash::{rand_core, SaltString},
    Argon2, PasswordHasher,
};
use axum::{
    extract::{OriginalUri, Path, Query},
    http::StatusCode,
    routing::get,
    Extension, Json, Router,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use sqlx::{Pool, Postgres, QueryBuilder};

use crate::{
    auth::Authenticated,
    config,
    model::{Group, User},
    utility::{action, deserialize_some, ApiResult},
};

struct PartialUser {
    pub id: i64,
    pub name: Option<String>,
}

lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new("^[a-zA-Z0-9_\\-]{4,64}$").unwrap();
    static ref PASSWORD_REGEX: Regex = Regex::new("^.{8,512}$").unwrap();
}

pub fn controllers() -> Router {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/:id", get(show_user).patch(patch_user).delete(delete_user))
}

#[derive(Debug, Deserialize)]
struct ListUsersQuery {
    offset: Option<i64>,
    limit: Option<i64>,
    threshold: Option<f32>,
    name: Option<String>,
}

async fn list_users(
    Extension(pool): Extension<Pool<Postgres>>,
    Query(query): Query<ListUsersQuery>,
) -> ApiResult<action::List<User>> {
    let offset = 0.max(query.offset.unwrap_or(0));
    let limit = 0.max(
        config::PAGINATION_MAX_LIMIT.min(query.limit.unwrap_or(config::PAGINATION_DEFAULT_LIMIT)),
    );

    let partial_users = if let Some(name) = query.name {
        let threshold = 0.0_f32.max(
            query
                .threshold
                .unwrap_or(config::SIMILARITY_DEFAULT_THRESHOLD),
        );

        sqlx::query_as!(
            PartialUser,
            r#"
            SELECT id, name
            FROM Users
            WHERE SIMILARITY (name, $1) > $2
            ORDER BY id
            OFFSET $3
            LIMIT $4
            "#,
            name,
            threshold,
            offset,
            limit
        )
        .fetch_all(&pool)
        .await
        .map_err(|err| internal_error!(err))?
    } else {
        sqlx::query_as!(
            PartialUser,
            r#"
            SELECT id, name
            FROM Users
            ORDER BY id
            OFFSET $1
            LIMIT $2
            "#,
            offset,
            limit
        )
        .fetch_all(&pool)
        .await
        .map_err(|err| internal_error!(err))?
    };

    let mut users: Vec<User> = Vec::new();
    for partial_user in partial_users {
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

        users.push(User {
            id: partial_user.id,
            name: partial_user.name,
            groups,
        })
    }

    Ok(action::List(users))
}

#[derive(Debug, Deserialize)]
struct CreateUserBody {
    username: String,
    password: String,
    name: Option<String>,
}

async fn create_user(
    Extension(pool): Extension<Pool<Postgres>>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<CreateUserBody>,
) -> ApiResult<action::Create<User>> {
    if !USERNAME_REGEX.is_match(&body.username) || !PASSWORD_REGEX.is_match(&body.password) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let salt = SaltString::generate(&mut rand_core::OsRng);
    let hash = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|err| internal_error!(err))?;

    let partial_user = sqlx::query_as!(
        PartialUser,
        r#"
        INSERT INTO Users (username, digest, name)
                    VALUES ($1, $2, $3)
        RETURNING id, name
        "#,
        body.username,
        hash.to_string(),
        body.name
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(db) if "23505" == db.code().unwrap() => StatusCode::CONFLICT,
        _ => internal_error!(err),
    })?;

    Ok(action::Create(
        User {
            id: partial_user.id,
            name: partial_user.name,
            groups: Vec::new(),
        },
        uri,
        partial_user.id.to_string(),
    ))
}

async fn show_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(id): Path<i64>,
) -> ApiResult<action::Show<User>> {
    let partial_user = sqlx::query_as!(
        PartialUser,
        r#"
        SELECT id, name
        FROM Users
        WHERE id = $1
        "#,
        id,
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
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
}

#[derive(Debug, Deserialize)]
struct PatchUserBody {
    username: Option<String>,
    password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    name: Option<Option<String>>,
}

async fn patch_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(id): Path<i64>,
    Json(body): Json<PatchUserBody>,
    Authenticated(user_id): Authenticated,
) -> ApiResult<action::Patch> {
    if user_id != id {
        return Err(StatusCode::FORBIDDEN);
    }

    if body.username.is_none() && body.password.is_none() && body.name.is_none() {
        return Ok(action::Patch);
    }

    // Validate username if set.
    let username = match &body.username {
        Some(uname) if USERNAME_REGEX.is_match(uname) => Some(uname),
        Some(_) => return Err(StatusCode::BAD_REQUEST),
        None => None,
    };

    // Validate password and hash if set.
    let salt = SaltString::generate(&mut rand_core::OsRng);
    let hash = match &body.password {
        Some(pword) if PASSWORD_REGEX.is_match(pword) => Some(
            Argon2::default()
                .hash_password(pword.as_bytes(), &salt)
                .map_err(|err| internal_error!(err))?,
        ),
        Some(_) => return Err(StatusCode::BAD_REQUEST),
        None => None,
    };

    // Construct query.
    let mut query = QueryBuilder::<Postgres>::new("UPDATE Users SET ");
    if let Some(uname) = username {
        query.push("username = ");
        query.push_bind(uname);
    }
    if let Some(hash) = hash {
        query.push("digest = ");
        query.push_bind(hash.to_string());
    }
    if let Some(name) = body.name {
        query.push("name = ");
        query.push_bind(name);
    }
    query.push("WHERE id = ");
    query.push_bind(id);

    // Execute query.
    query
        .build()
        .execute(&pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::Database(db) if "23505" == db.code().unwrap() => StatusCode::CONFLICT,
            _ => internal_error!(err),
        })?;

    // If username or password changed, also invalidate all sessions.
    if body.username.is_some() || body.password.is_some() {
        sqlx::query!(
            r#"
                DELETE FROM Sessions
                WHERE user_id = $1
                "#,
            id
        )
        .execute(&pool)
        .await
        .map_err(|err| internal_error!(err))?;
    }

    Ok(action::Patch)
}

async fn delete_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(id): Path<i64>,
    Authenticated(user_id): Authenticated,
) -> ApiResult<action::Delete> {
    if user_id != id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Null-out all user information.
    sqlx::query!(
        r#"
        UPDATE Users
        SET username = NULL,
            digest   = NULL,
            name     = NULL
        WHERE id = $1
        "#,
        id
    )
    .execute(&pool)
    .await
    .map_err(|err| internal_error!(err))?;

    // Invalidate all sessions.
    sqlx::query!(
        r#"
        DELETE FROM Sessions
        WHERE user_id = $1
        "#,
        id
    )
    .execute(&pool)
    .await
    .map_err(|err| internal_error!(err))?;

    Ok(action::Delete)
}
