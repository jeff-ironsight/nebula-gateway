use crate::types::{ChannelId, ConnectionId, OutboundTx, UserId};
use dashmap::{DashMap, DashSet};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub user_id: UserId,
    // later: last_heartbeat, seq, presence, etc.
}

pub struct AppState {
    pub connections: DashMap<ConnectionId, OutboundTx>,
    pub sessions: DashMap<ConnectionId, Session>,
    pub channel_members: DashMap<ChannelId, DashSet<ConnectionId>>,
    pub connection_channels: DashMap<ConnectionId, DashSet<ChannelId>>,

    #[cfg(test)]
    pub dispatch_counter: AtomicUsize,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            sessions: DashMap::new(),
            channel_members: DashMap::new(),
            connection_channels: DashMap::new(),

            #[cfg(test)]
            dispatch_counter: AtomicUsize::new(0),
        }
    }
}
