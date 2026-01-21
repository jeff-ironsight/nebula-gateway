mod app;
mod gateway;
mod protocol;
mod rest;
mod settings;
mod state;
mod types;

use crate::{settings::Settings, state::AppState};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let settings = Settings::load().expect("failed to load configuration");

    let db = PgPool::connect(&settings.server.database_url).await?;
    let state = Arc::new(AppState::new(db, settings.auth.token_secret.into_bytes()));

    let app = app::build_router(state);

    let addr = settings.server.bind_addr;
    info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
