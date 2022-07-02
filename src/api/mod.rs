use axum::Router;

mod auth;
mod me;

mod groups;
mod users;

pub fn routes() -> Router {
    Router::new()
        // Special routes
        .nest("/auth", auth::controllers())
        .nest("/me", me::controllers())
        // REST-ish routes
        .nest("/groups", groups::controllers())
        .nest("/users", users::controllers())
}
