use axum::Router;

mod auth;
mod me;
mod users;

pub fn routes() -> Router {
    Router::new()
        .nest("/users", users::controllers())
        .nest("/auth", auth::controllers())
        .nest("/me", me::controllers())
}
