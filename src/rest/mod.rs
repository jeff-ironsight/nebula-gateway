use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

pub mod auth;
mod health;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().merge(health::router())
}
