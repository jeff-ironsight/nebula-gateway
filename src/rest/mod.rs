use axum::Router;
use std::sync::Arc;

use crate::state::AppState;

pub mod auth;
mod channels;
mod health;
mod invites;
mod messages;
mod servers;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(health::router())
        .merge(servers::router())
        .merge(channels::router())
        .merge(messages::router())
        .merge(invites::router())
}
