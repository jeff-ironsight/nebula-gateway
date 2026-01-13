use crate::{
    protocol::{ErrorCode, ErrorEvent, GatewayPayload, MessageCreateEvent, ReadyEvent},
    state::AppState,
    types::{ChannelId, ConnectionId, UserId},
};
use axum::extract::ws::Message;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;
use tracing::{debug, info, warn};
use ulid::Ulid;

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

pub fn broadcast_message_to_channel(
    state: &Arc<AppState>,
    channel_id: &ChannelId,
    author_user_id: &UserId,
    content: &str,
) {
    let Some(members) = state.channel_members.get(channel_id) else {
        warn!(channel = %channel_id, "broadcast requested for channel with no members");
        return;
    };

    let member_ids: Vec<ConnectionId> = members.iter().map(|id| *id).collect();
    drop(members);

    let event = MessageCreateEvent {
        id: Ulid::new(),
        channel_id: channel_id.clone(),
        author_user_id: *author_user_id,
        content: content.to_string(),
    };
    let payload = GatewayPayload::Dispatch {
        t: "MESSAGE_CREATE".into(),
        d: serde_json::to_value(event).expect("message payload should serialize"),
    };
    debug!("sending message to channel {}", channel_id);

    #[cfg(test)]
    state.dispatch_counter.fetch_add(1, Ordering::Relaxed);

    let mut stale_members = Vec::new();

    for member_id in member_ids {
        match state.connections.get(&member_id) {
            Some(tx) => {
                if tx.send(text_msg(&payload).clone()).is_err() {
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

pub fn dispatch_hello_to_connection(state: &Arc<AppState>, connection_id: &ConnectionId) {
    let payload = GatewayPayload::Hello {
        heartbeat_interval_ms: 25_000,
    };
    if let Some(tx) = state.connections.get(connection_id) {
        if tx.send(text_msg(&payload)).is_err() {
            warn!(?connection_id, "failed to send hello payload");
        }
    } else {
        debug!(
            ?connection_id,
            "cannot send hello payload to missing connection"
        );
    }
}

pub fn dispatch_ready_to_connection(
    state: &Arc<AppState>,
    connection_id: &ConnectionId,
    user_id: &UserId,
) {
    let event = ReadyEvent {
        connection_id: *connection_id,
        user_id: *user_id,
        heartbeat_interval_ms: 25_000,
    };
    let payload = GatewayPayload::Dispatch {
        t: "READY".into(),
        d: serde_json::to_value(event).expect("ready payload should serialize"),
    };

    if let Some(tx) = state.connections.get(connection_id) {
        if tx.send(text_msg(&payload)).is_err() {
            warn!(?connection_id, "failed to send ready payload");
        }
    } else {
        debug!(
            ?connection_id,
            "cannot send ready payload to missing connection"
        );
    }
}

pub fn dispatch_error_to_connection(
    state: &Arc<AppState>,
    connection_id: &ConnectionId,
    code: ErrorCode,
) {
    let event = ErrorEvent { code };
    let payload = GatewayPayload::Dispatch {
        t: "ERROR".into(),
        d: serde_json::to_value(event).expect("error payload should serialize"),
    };

    if let Some(tx) = state.connections.get(connection_id) {
        if tx.send(text_msg(&payload)).is_err() {
            warn!(?connection_id, "failed to send error payload");
        }
    } else {
        debug!(
            ?connection_id,
            "cannot send error payload to missing connection"
        );
    }
}

pub fn cleanup_connection(state: &Arc<AppState>, connection_id: &ConnectionId) {
    state.connections.remove(connection_id);
    state.sessions.remove(connection_id);
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

pub fn require_identified(state: &Arc<AppState>, connection_id: &ConnectionId) -> Option<UserId> {
    state.sessions.get(connection_id).map(|s| s.user_id)
}

fn text_msg<T: serde::Serialize>(value: &T) -> Message {
    Message::Text(serde_json::to_string(value).unwrap().into())
}
