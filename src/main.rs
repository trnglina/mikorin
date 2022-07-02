use axum::{Extension, Router};
use axum_extra::routing::SpaRouter;
use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[macro_use]
mod utility;

mod api;
mod config;
mod entities;
mod extract;

#[tokio::main]
async fn main() {
    // Set up environment.
    dotenv().ok();

    // Initialize tracing.
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // Connect to database.
    let pool = PgPoolOptions::new()
        .max_connections(64)
        .connect_lazy(&std::env::var("DATABASE_URL").unwrap())
        .unwrap();

    // Configure server.
    let config = RustlsConfig::from_pem_file(
        &std::env::var("CERT_PATH").unwrap(),
        &std::env::var("KEY_PATH").unwrap(),
    )
    .await
    .unwrap();
    tracing::debug!("using rustls");

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    tracing::debug!("listening on {}", addr);

    // Construct app.
    let spa = SpaRouter::new("/assets", "dist");
    let app = Router::new()
        .merge(spa)
        .nest(config::API_ROUTE, api::routes())
        .layer(Extension(pool));

    // Start app.
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
