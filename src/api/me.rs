use axum::{response::Redirect, routing::get, Router};

use crate::{auth::Authenticated, config};

pub fn controllers() -> Router {
    Router::new().route("/", get(show_me))
}

async fn show_me(Authenticated(user_id): Authenticated) -> Redirect {
    Redirect::to(&format!("{}/users/{}", config::API_ROUTE, user_id))
}
