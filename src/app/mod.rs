use axum::Extension;
use axum::Router;
use sqlx::Pool;
use sqlx::Postgres;

mod auth;
mod users;

pub async fn app(pool: Pool<Postgres>) -> Router {
    Router::new()
        .nest("/auth", auth::controllers())
        .nest("/users", users::controllers())
        .layer(Extension(pool))
}
