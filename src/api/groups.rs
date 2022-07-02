use axum::{
    extract::{OriginalUri, Path, Query},
    http::StatusCode,
    routing::get,
    Extension, Json, Router,
};
use serde::Deserialize;
use sqlx::{Pool, Postgres, QueryBuilder, Row};

use crate::{
    config,
    entities::{Group, Permission, PermissionVec},
    extract::Authorized,
    utility::{action, ApiResult},
};

pub fn controllers() -> Router {
    Router::new()
        .route("/", get(list_groups).post(create_group))
        .route(
            "/:group_id",
            get(show_group).patch(patch_group).delete(delete_group),
        )
}

#[derive(Debug, Deserialize)]
struct ListGroupsQuery {
    offset: Option<i64>,
    limit: Option<i64>,
    fuzzy: Option<String>,
    name: Option<String>,
    has_permission: Option<Permission>,
}

async fn list_groups(
    Extension(pool): Extension<Pool<Postgres>>,
    Query(query): Query<ListGroupsQuery>,
) -> ApiResult<action::List<Group>> {
    let offset = 0.max(query.offset.unwrap_or(0));
    let limit = 0.max(
        config::PAGINATION_MAX_LIMIT.min(query.limit.unwrap_or(config::PAGINATION_DEFAULT_LIMIT)),
    );

    // Construct query.
    let mut q = QueryBuilder::<Postgres>::new(
        r#"
        SELECT id, name, permissions
        FROM Groups_
        "#,
    );
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
    if let Some(has_permission) = query.has_permission {
        q.push("WHERE ");
        q.push_bind(has_permission);
        q.push(" = ANY(permissions)");
    }
    q.push(format!("ORDER BY id OFFSET {} LIMIT {}", offset, limit));

    Ok(action::List(
        q.build()
            .map(|row| Group {
                id: row.try_get("id").unwrap(),
                name: row.try_get("name").unwrap(),
                permissions: row.try_get("permissions").unwrap(),
            })
            .fetch_all(&pool)
            .await
            .map_err(|err| internal_error!(err))?,
    ))
}

#[derive(Debug, Deserialize)]
struct CreateGroupBody {
    name: String,
    permissions: Vec<Permission>,
}

async fn create_group(
    Extension(pool): Extension<Pool<Postgres>>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<CreateGroupBody>,
    authorized: Authorized,
) -> ApiResult<action::Create<Group>> {
    require_permission!(authorized, Permission::Groups_Create);

    let group = sqlx::query_as!(
        Group,
        r#"
        INSERT INTO Groups_ (name, permissions)
                    VALUES ($1, $2)
        RETURNING id, name, permissions as "permissions: PermissionVec"
        "#,
        body.name,
        &body.permissions[..] as _
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| internal_error!(err))?;

    let path = group.id.to_string();
    Ok(action::Create(group, uri, path))
}

async fn show_group(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(group_id): Path<i64>,
) -> ApiResult<action::Show<Group>> {
    Ok(action::Show(
        sqlx::query_as!(
            Group,
            r#"
            SELECT id, name, permissions as "permissions: PermissionVec"
            FROM Groups_
            WHERE id = $1
            "#,
            group_id
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
struct PatchGroupBody {
    name: Option<String>,
    permissions: Option<Vec<Permission>>,
}

async fn patch_group(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(group_id): Path<i64>,
    Json(body): Json<PatchGroupBody>,
    authorized: Authorized,
) -> ApiResult<action::Patch> {
    require_permission!(authorized, Permission::Groups_Edit);

    if body.name.is_none() && body.permissions.is_none() {
        return Ok(action::Patch);
    }

    // Construct query.
    let mut q = QueryBuilder::<Postgres>::new("UPDATE Groups_ SET ");
    if let Some(ref name) = body.name {
        q.push("name = ");
        q.push_bind(name);
    }
    if let Some(ref permissions) = body.permissions {
        q.push("permissions = ");
        q.push_bind(&permissions[..]);
    }
    q.push("WHERE id = ");
    q.push_bind(group_id);

    // Execute query.
    q.build()
        .execute(&pool)
        .await
        .map_err(|err| internal_error!(err))?;

    Ok(action::Patch)
}

async fn delete_group(
    Extension(pool): Extension<Pool<Postgres>>,
    Path(group_id): Path<i64>,
    authorized: Authorized,
) -> ApiResult<action::Delete> {
    require_permission!(authorized, Permission::Groups_Delete);

    sqlx::query!(
        r#"
        DELETE FROM Groups_
        WHERE id = $1
        "#,
        group_id
    )
    .execute(&pool)
    .await
    .map_err(|err| internal_error!(err))?;

    Ok(action::Delete)
}
