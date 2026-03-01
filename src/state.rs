use crate::auth0::Auth0Verifier;
use crate::types::{ChannelId, ConnectionId, OutboundTx, UserId};
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
    pub sessions: DashMap<ConnectionId, Session>,
    /// Channel ID -> Set of connections subscribed to that channel
    pub channel_subscribers: DashMap<ChannelId, DashSet<ConnectionId>>,
    /// Connection ID -> Set of channels that connection is subscribed to
    pub connection_channels: DashMap<ConnectionId, DashSet<ChannelId>>,
    pub auth0: Option<Auth0Verifier>,

    #[cfg(test)]
    pub dispatch_counter: AtomicUsize,
}

impl AppState {
    pub fn new(db: PgPool, auth0: Option<Auth0Verifier>) -> Self {
        Self {
            db,
            connections: DashMap::new(),
            sessions: DashMap::new(),
            channel_subscribers: DashMap::new(),
            connection_channels: DashMap::new(),
            auth0,

            #[cfg(test)]
            dispatch_counter: AtomicUsize::new(0),
        }
    }
}
