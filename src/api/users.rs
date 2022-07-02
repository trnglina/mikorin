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
use sqlx::{Pool, Postgres, QueryBuilder, Row};

use crate::{
    config,
    entities::{Permission, User},
    extract::{Authenticated, Authorized, Maybe, Priveledged},
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
    fuzzy: Option<String>,
    name: Option<String>,
    group_id: Option<i64>,
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
    let mut q = QueryBuilder::<Postgres>::new("SELECT id, name, group_id FROM Users ");
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
    if let Some(group_id) = query.group_id {
        q.push("WHERE group_id = ");
        q.push_bind(group_id);
    }
    q.push(format!("ORDER BY id OFFSET {} LIMIT {}", offset, limit));

    Ok(action::List(
        q.build()
            .map(|row| User {
                id: row.try_get("id").unwrap(),
                name: row.try_get("name").unwrap(),
                group_id: row.try_get("group_id").unwrap(),
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
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
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
        RETURNING id, name, group_id
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
            SELECT id, name, group_id
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
    username: Option<String>,
    password: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some")]
    name: Option<Option<String>>,
    group_id: Option<i64>,
}

async fn patch_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(user_id): Path<i64>,
    Json(body): Json<PatchUserBody>,
    Maybe(priveledged): Maybe<Priveledged>,
    authorized: Authorized,
) -> ApiResult<action::Patch> {
    if body.username.is_none()
        && body.password.is_none()
        && body.name.is_none()
        && body.group_id.is_none()
    {
        return Ok(action::Patch);
    }

    let username = match body.username {
        Some(ref username) => {
            if !user_id == authorized.user_id
                || !priveledged
                    .as_ref()
                    .map(|p| user_id == p.user_id)
                    .unwrap_or(false)
            {
                return Err(StatusCode::FORBIDDEN);
            }

            if !USERNAME_REGEX.is_match(username) {
                return Err(StatusCode::UNPROCESSABLE_ENTITY);
            }

            Some(username)
        }
        None => None,
    };

    let digest = match body.password {
        Some(ref password) => {
            if !user_id == authorized.user_id
                || !priveledged
                    .as_ref()
                    .map(|p| user_id == p.user_id)
                    .unwrap_or(false)
            {
                return Err(StatusCode::FORBIDDEN);
            }

            if !PASSWORD_REGEX.is_match(password) {
                return Err(StatusCode::UNPROCESSABLE_ENTITY);
            }

            let salt = SaltString::generate(&mut rand_core::OsRng);
            Some(
                Argon2::default()
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(|err| internal_error!(err))?
                    .to_string(),
            )
        }
        None => None,
    };

    let name = require_user!(authorized, user_id, body.name);
    let group_id = require_permission!(authorized, Permission::Users_GroupId_Edit, body.group_id);

    // Construct query.
    let mut q = QueryBuilder::<Postgres>::new("UPDATE Users SET ");
    if let Some(ref uname) = username {
        q.push("username = ");
        q.push_bind(uname);
    }
    if let Some(ref digest) = digest {
        q.push("digest = ");
        q.push_bind(digest);
    }
    if let Some(ref name) = name {
        q.push("name = ");
        q.push_bind(name);
    }
    if let Some(ref group_id) = group_id {
        q.push("group_id = ");
        q.push_bind(group_id);
    }
    q.push("WHERE id = ");
    q.push_bind(user_id);

    // Execute query.
    q.build().execute(&pool).await.map_err(|err| match err {
        sqlx::Error::Database(db) if "23505" == db.code().unwrap() => StatusCode::CONFLICT,
        _ => internal_error!(err),
    })?;

    // If username or password changed, also invalidate all sessions.
    if username.is_some() || digest.is_some() {
        clear_sessions(&pool, user_id)
            .await
            .map_err(|err| internal_error!(err))?;
    }

    Ok(action::Patch)
}

async fn delete_user(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(user_id): Path<i64>,
    priveledged: Priveledged,
    authenticated: Authenticated,
) -> ApiResult<action::Delete> {
    if user_id != priveledged.user_id || user_id != authenticated.user_id {
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
