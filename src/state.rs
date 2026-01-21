use crate::types::{ChannelId, ConnectionId, OutboundTx, Token, UserId};
use dashmap::{DashMap, DashSet};
use sqlx::PgPool;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub user_id: UserId,
    // later: last_heartbeat, seq, presence, etc.
}

pub struct AppState {
    pub db: PgPool,
    pub connections: DashMap<ConnectionId, OutboundTx>,
    pub auth_tokens: DashMap<Token, UserId>,
    pub sessions: DashMap<ConnectionId, Session>,
    pub channel_members: DashMap<ChannelId, DashSet<ConnectionId>>,
    pub connection_channels: DashMap<ConnectionId, DashSet<ChannelId>>,

    #[cfg(test)]
    pub dispatch_counter: AtomicUsize,
}

impl AppState {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            connections: DashMap::new(),
            auth_tokens: DashMap::new(),
            sessions: DashMap::new(),
            channel_members: DashMap::new(),
            connection_channels: DashMap::new(),

            #[cfg(test)]
            dispatch_counter: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
pub const TEST_DATABASE_URL: &str = "postgres://root:rootpass@localhost:5432/nebuladb";

#[cfg(test)]
pub fn test_db() -> PgPool {
    PgPool::connect_lazy(TEST_DATABASE_URL).expect("failed to init Postgres pool")
}
