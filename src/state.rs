use crate::types::{ChannelId, ConnectionId, OutboundTx};
use dashmap::{DashMap, DashSet};

pub struct AppState {
    pub connections: DashMap<ConnectionId, OutboundTx>,
    pub channel_members: DashMap<ChannelId, DashSet<ConnectionId>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            channel_members: DashMap::new(),
        }
    }
}
