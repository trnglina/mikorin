use axum::{response::Redirect, routing::get, Router};

use crate::{config, extract::Authenticated};

pub fn controllers() -> Router {
    Router::new().route("/", get(show_me))
}

async fn show_me(authenticated: Authenticated) -> Redirect {
    Redirect::to(&format!(
        "{}/users/{}",
        config::API_ROUTE,
        authenticated.user_id
    ))
}
