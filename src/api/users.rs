use argon2::{
    password_hash::{rand_core, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use axum::{
    extract::{OriginalUri, Path, Query},
    http::StatusCode,
    routing::{get, put},
    Extension, Json, Router,
};
use lazy_static::lazy_static;
use regex::Regex;
use serde::Deserialize;
use sqlx::{Pool, Postgres, QueryBuilder, Row};

use crate::{
    auth::{Authenticated, Authorized},
    config,
    model::{Group, User},
    utility::{action, deserialize_some, ApiResult},
};

lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new("^[a-zA-Z0-9_\\-]{4,64}$").unwrap();
    static ref PASSWORD_REGEX: Regex = Regex::new("^.{8,512}$").unwrap();
}

pub fn controllers() -> Router {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route(
            "/:user_id",
            get(show_user).patch(patch_user).delete(delete_user),
        )
        .route("/:user_id/groups", get(list_user_groups))
        .route(
            "/:user_id/groups/:group_id",
            put(put_user_groups).delete(delete_user_groups),
        )
}

async fn clear_sessions(pool: &Pool<Postgres>, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        DELETE FROM Sessions
        WHERE user_id = $1
        "#,
        id
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ListUsersQuery {
    offset: Option<i64>,
    limit: Option<i64>,
    name: Option<String>,
    fuzzy: Option<String>,
}

async fn list_users(
    Extension(pool): Extension<Pool<Postgres>>,
    Query(query): Query<ListUsersQuery>,
) -> ApiResult<action::List<User>> {
    let offset = 0.max(query.offset.unwrap_or(0));
    let limit = 0.max(
        config::PAGINATION_MAX_LIMIT.min(query.limit.unwrap_or(config::PAGINATION_DEFAULT_LIMIT)),
    );

    // Construct query.
    let mut q = QueryBuilder::<Postgres>::new("SELECT id, name FROM Users ");
    if let Some(name) = query.name {
        if query.fuzzy.is_some() {
            q.push("WHERE SIMILARITY (name, ");
            q.push_bind(name);
            q.push(format!(") > {}", config::FUZZY_SIMILARITY_THRESHOLD));
        } else {
            q.push("WHERE name LIKE '%' || ");
            q.push_bind(name);
            q.push(" || '%'");
        }
    }
    q.push(format!("ORDER BY id OFFSET {} LIMIT {}", offset, limit));

    Ok(action::List(
        q.build()
            .map(|row| User {
                id: row.try_get("id").unwrap(),
                name: row.try_get("name").unwrap(),
            })
            .fetch_all(&pool)
            .await
            .map_err(|err| internal_error!(err))?,
    ))
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

    let user = sqlx::query_as!(
        User,
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

    let path = user.id.to_string();
    Ok(action::Create(user, uri, path))
}

async fn show_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(user_id): Path<i64>,
) -> ApiResult<action::Show<User>> {
    Ok(action::Show(
        sqlx::query_as!(
            User,
            r#"
            SELECT id, name
            FROM Users
            WHERE id = $1
            "#,
            user_id,
        )
        .fetch_one(&pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
            _ => internal_error!(err),
        })?,
    ))
}

#[derive(Debug, Deserialize)]
struct PatchUserBody {
    _current_password: Option<String>,

    username: Option<String>,
    password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    name: Option<Option<String>>,
}

async fn patch_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(user_id): Path<i64>,
    Json(body): Json<PatchUserBody>,
    Authenticated(auth_id): Authenticated,
) -> ApiResult<action::Patch> {
    if auth_id != user_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // If no fields are updated, return immediately.
    if body.username.is_none() && body.password.is_none() && body.name.is_none() {
        return Ok(action::Patch);
    }

    // Changes to username and password must also include _current_password
    if body.username.is_some() || body.password.is_some() {
        if let Some(current_password) = body._current_password {
            // Check current password.
            let digest = sqlx::query_scalar!(
                r#"
                SELECT digest as "digest!: String"
                FROM Users
                WHERE id = $1 AND digest IS NOT NULL
                "#,
                user_id
            )
            .fetch_one(&pool)
            .await
            .map_err(|err| match err {
                sqlx::Error::RowNotFound => StatusCode::FORBIDDEN,
                _ => internal_error!(err),
            })?;

            Argon2::default()
                .verify_password(
                    current_password.as_bytes(),
                    &PasswordHash::new(&digest).map_err(|err| internal_error!(err))?,
                )
                .map_err(|_| StatusCode::FORBIDDEN)?;
        } else {
            return Err(StatusCode::FORBIDDEN);
        }
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
    let mut q = QueryBuilder::<Postgres>::new("UPDATE Users SET ");
    if let Some(uname) = username {
        q.push("username = ");
        q.push_bind(uname);
    }
    if let Some(hash) = hash {
        q.push("digest = ");
        q.push_bind(hash.to_string());
    }
    if let Some(name) = body.name {
        q.push("name = ");
        q.push_bind(name);
    }
    q.push("WHERE id = ");
    q.push_bind(user_id);

    // Execute query.
    q.build().execute(&pool).await.map_err(|err| match err {
        sqlx::Error::Database(db) if "23505" == db.code().unwrap() => StatusCode::CONFLICT,
        _ => internal_error!(err),
    })?;

    // If username or password changed, also invalidate all sessions.
    if body.username.is_some() || body.password.is_some() {
        clear_sessions(&pool, user_id)
            .await
            .map_err(|err| internal_error!(err))?;
    }

    Ok(action::Patch)
}

async fn delete_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(user_id): Path<i64>,
    Authenticated(auth_id): Authenticated,
) -> ApiResult<action::Delete> {
    if auth_id != user_id {
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
        user_id
    )
    .execute(&pool)
    .await
    .map_err(|err| internal_error!(err))?;

    // Invalidate all sessions.
    clear_sessions(&pool, user_id)
        .await
        .map_err(|err| internal_error!(err))?;

    Ok(action::Delete)
}

async fn list_user_groups(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(user_id): Path<i64>,
) -> ApiResult<action::List<Group>> {
    Ok(action::List(
        sqlx::query_as!(
            Group,
            r#"
            SELECT Groups.id, Groups.name, Groups.permissions as "permissions!: Vec<String>"
            FROM UserGroups JOIN Groups ON UserGroups.group_id = Groups.id
            WHERE UserGroups.user_id = $1
            "#,
            user_id
        )
        .fetch_all(&pool)
        .await
        .map_err(|err| internal_error!(err))?,
    ))
}

async fn put_user_groups(
    Extension(pool): Extension<Pool<Postgres>>,
    Path((user_id, group_id)): Path<(i64, i64)>,
    Authorized(_, permissions): Authorized,
) -> ApiResult<action::Put> {
    if !permissions.contains("users.groups.edit") {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query!(
        r#"
        INSERT INTO UserGroups (user_id, group_id)
                    VALUES ($1, $2)
        "#,
        user_id,
        group_id,
    )
    .execute(&pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(db) if "23505" == db.code().unwrap() => StatusCode::OK,
        sqlx::Error::Database(db) if "23503" == db.code().unwrap() => StatusCode::BAD_REQUEST,
        _ => internal_error!(err),
    })?;

    Ok(action::Put)
}

async fn delete_user_groups(
    Extension(pool): Extension<Pool<Postgres>>,
    Path((user_id, group_id)): Path<(i64, i64)>,
    Authorized(_, permissions): Authorized,
) -> ApiResult<action::Delete> {
    if !permissions.contains("users.groups.edit") {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query!(
        r#"
        DELETE FROM UserGroups
        WHERE user_id = $1 AND group_id = $2
        "#,
        user_id,
        group_id,
    )
    .execute(&pool)
    .await
    .map_err(|err| match err {
        sqlx::Error::Database(db) if "23505" == db.code().unwrap() => StatusCode::OK,
        sqlx::Error::Database(db) if "23503" == db.code().unwrap() => StatusCode::BAD_REQUEST,
        _ => internal_error!(err),
    })?;

    Ok(action::Delete)
}
