use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

mod auth;
mod health;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().merge(auth::router().merge(health::router()))
}
