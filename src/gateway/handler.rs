use crate::{
    protocol::GatewayPayload,
    state::AppState,
    types::{ChannelId, ConnectionId},
};
use axum::extract::ws::Message;
use serde_json::json;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;
use tracing::{debug, info, warn};

pub fn subscribe_connection(
    state: &Arc<AppState>,
    channel_id: ChannelId,
    connection_id: ConnectionId,
) {
    let members = state.channel_members.entry(channel_id.clone()).or_default();
    let already_member = !members.insert(connection_id);
    drop(members);

    if already_member {
        debug!(?connection_id, channel = %channel_id, "connection already subscribed");
    } else {
        info!(?connection_id, channel = %channel_id, "subscribed to channel");
    }

    state
        .connection_channels
        .entry(connection_id)
        .or_default()
        .insert(channel_id);
}

pub fn broadcast_message_to_channel(state: &Arc<AppState>, channel_id: &ChannelId, content: &str) {
    let Some(members) = state.channel_members.get(channel_id) else {
        warn!(channel = %channel_id, "broadcast requested for channel with no members");
        return;
    };

    let member_ids: Vec<ConnectionId> = members.iter().map(|id| *id).collect();
    drop(members);

    let payload = GatewayPayload::Dispatch {
        t: "MESSAGE_CREATE".into(),
        d: json!({
            "channel_id": channel_id,
            "content": content,
        }),
    };
    let message = Message::Text(serde_json::to_string(&payload).unwrap().into());
    #[cfg(test)]
    state.dispatch_counter.fetch_add(1, Ordering::Relaxed);

    let mut stale_members = Vec::new();

    for member_id in member_ids {
        match state.connections.get(&member_id) {
            Some(tx) => {
                if tx.send(message.clone()).is_err() {
                    warn!(
                        ?member_id,
                        channel = %channel_id,
                        "failed to send message payload"
                    );
                }
            }
            None => {
                debug!(
                    ?member_id,
                    channel = %channel_id,
                    "removing stale channel member missing connection"
                );
                stale_members.push(member_id);
            }
        }
    }

    for member_id in stale_members {
        remove_channel_membership(state, channel_id, &member_id);
        remove_connection_channel(state, &member_id, channel_id);
    }
}

pub fn cleanup_connection(state: &Arc<AppState>, connection_id: &ConnectionId) {
    state.connections.remove(connection_id);
    if let Some((_, channels)) = state.connection_channels.remove(connection_id) {
        for channel_id in channels.into_iter() {
            remove_channel_membership(state, &channel_id, connection_id);
        }
    }
}

pub fn is_subscribed(
    state: &Arc<AppState>,
    connection_id: ConnectionId,
    channel_id: &ChannelId,
) -> bool {
    state
        .connection_channels
        .get(&connection_id)
        .map(|set| set.contains(channel_id))
        .unwrap_or(false)
}

fn remove_channel_membership(
    state: &Arc<AppState>,
    channel_id: &ChannelId,
    connection_id: &ConnectionId,
) {
    if let Some(entry) = state.channel_members.get_mut(channel_id) {
        entry.value().remove(connection_id);
        let empty = entry.value().is_empty();
        drop(entry);
        if empty {
            state.channel_members.remove(channel_id);
        }
    }
}

fn remove_connection_channel(
    state: &Arc<AppState>,
    connection_id: &ConnectionId,
    channel_id: &ChannelId,
) {
    if let Some(entry) = state.connection_channels.get_mut(connection_id) {
        entry.value().remove(channel_id);
        let empty = entry.value().is_empty();
        drop(entry);
        if empty {
            state.connection_channels.remove(connection_id);
        }
    }
}
