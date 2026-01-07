mod app;
mod gateway;
mod protocol;
mod settings;
mod state;
mod types;

use crate::{settings::Settings, state::AppState};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let settings = Settings::load().expect("failed to load configuration");
    let state = Arc::new(AppState::new());

    let app = app::build_router(state);

    let addr = settings.server.bind_addr;
    info!("listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
