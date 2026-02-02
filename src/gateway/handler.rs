use crate::{
    data::{ChannelRepository, MessageRepository, ServerRepository},
    protocol::{
        ErrorCode, ErrorEvent, GatewayPayload, MessageCreateEvent, ReadyChannel, ReadyEvent,
        ReadyServer, SubscribedEvent,
    },
    state::AppState,
    types::{ChannelId, ConnectionId, UserId},
};
use axum::extract::ws::Message;
use chrono::Utc;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::Ordering;
use tracing::{debug, info, warn};
use ulid::Ulid;

pub fn subscribe_to_channel(
    state: &Arc<AppState>,
    channel_id: ChannelId,
    connection_id: ConnectionId,
) {
    let subscribers = state.channel_subscribers.entry(channel_id).or_default();
    let already_subscribed = !subscribers.insert(connection_id);
    drop(subscribers);

    if already_subscribed {
        debug!(?connection_id, channel = %channel_id, "connection already subscribed to channel");
    } else {
        info!(?connection_id, channel = %channel_id, "subscribed to channel");
    }

    state
        .connection_channels
        .entry(connection_id)
        .or_default()
        .insert(channel_id);
}

pub fn subscribe_to_channels(
    state: &Arc<AppState>,
    channel_ids: &[ChannelId],
    connection_id: ConnectionId,
) {
    for &channel_id in channel_ids {
        subscribe_to_channel(state, channel_id, connection_id);
    }
}

pub async fn broadcast_message_to_channel(
    state: &Arc<AppState>,
    channel_id: &ChannelId,
    author_user_id: &UserId,
    author_username: &str,
    content: &str,
) {
    let Some(subscribers) = state.channel_subscribers.get(channel_id) else {
        warn!(channel = %channel_id, "broadcast requested for channel with no subscribers");
        return;
    };

    let subscriber_ids: Vec<ConnectionId> = subscribers.iter().map(|id| *id).collect();
    drop(subscribers);

    let message_id = Ulid::new();
    let timestamp = Utc::now();

    // Persist message before broadcasting
    let messages = MessageRepository::new(&state.db);
    if let Err(e) = messages
        .create(&message_id.to_string(), channel_id, author_user_id, content)
        .await
    {
        warn!(channel = %channel_id, error = %e, "failed to persist message");
        return;
    }

    let event = MessageCreateEvent {
        id: message_id,
        channel_id: *channel_id,
        author_user_id: *author_user_id,
        author_username: author_username.to_string(),
        content: content.to_string(),
        timestamp: timestamp.to_rfc3339(),
    };
    let payload = GatewayPayload::Dispatch {
        t: "MESSAGE_CREATE".into(),
        d: serde_json::to_value(event).expect("message payload should serialize"),
    };
    debug!(channel = %channel_id, "broadcasting message to channel subscribers");

    #[cfg(test)]
    state.dispatch_counter.fetch_add(1, Ordering::Relaxed);

    let mut stale_subscribers = Vec::new();

    for subscriber_id in subscriber_ids {
        match state.connections.get(&subscriber_id) {
            Some(tx) => {
                if tx.send(text_msg(&payload).clone()).is_err() {
                    warn!(
                        ?subscriber_id,
                        channel = %channel_id,
                        "failed to send message payload"
                    );
                    stale_subscribers.push(subscriber_id);
                }
            }
            None => {
                debug!(
                    ?subscriber_id,
                    channel = %channel_id,
                    "removing stale channel subscriber missing connection"
                );
                stale_subscribers.push(subscriber_id);
            }
        }
    }

    for subscriber_id in stale_subscribers {
        remove_channel_subscription(state, channel_id, &subscriber_id);
        remove_connection_channel(state, &subscriber_id, channel_id);
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

pub async fn dispatch_ready_to_connection(
    state: &Arc<AppState>,
    connection_id: &ConnectionId,
    user_id: &UserId,
    username: &str,
    is_developer: bool,
) {
    let servers = match fetch_user_servers_with_channels(state, user_id).await {
        Ok(servers) => servers,
        Err(e) => {
            warn!(?connection_id, error = %e, "failed to fetch user servers for ready event");
            Vec::new()
        }
    };

    let event = ReadyEvent {
        connection_id: *connection_id,
        user_id: *user_id,
        username: username.to_string(),
        is_developer,
        heartbeat_interval_ms: 25_000,
        servers,
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

async fn fetch_user_servers_with_channels(
    state: &Arc<AppState>,
    user_id: &UserId,
) -> Result<Vec<ReadyServer>, sqlx::Error> {
    let server_repo = ServerRepository::new(&state.db);
    let channel_repo = ChannelRepository::new(&state.db);

    let servers = server_repo.get_servers_for_user(user_id).await?;

    let mut ready_servers = Vec::with_capacity(servers.len());
    for server in servers {
        let channels = channel_repo.get_channels_for_server(&server.id).await?;
        let ready_channels = channels
            .into_iter()
            .map(|c| ReadyChannel {
                id: c.id,
                server_id: c.server_id,
                name: c.name,
            })
            .collect();

        ready_servers.push(ReadyServer {
            id: server.id,
            name: server.name,
            owner_user_id: server.owner_user_id,
            my_role: server.my_role,
            channels: ready_channels,
        });
    }

    Ok(ready_servers)
}

pub fn dispatch_subscribed_to_connection(
    state: &Arc<AppState>,
    connection_id: &ConnectionId,
    channel_ids: Vec<ChannelId>,
) {
    let event = SubscribedEvent { channel_ids };
    let payload = GatewayPayload::Dispatch {
        t: "SUBSCRIBED".into(),
        d: serde_json::to_value(event).expect("subscribed payload should serialize"),
    };

    if let Some(tx) = state.connections.get(connection_id) {
        if tx.send(text_msg(&payload)).is_err() {
            warn!(?connection_id, "failed to send subscribed payload");
        }
    } else {
        debug!(
            ?connection_id,
            "cannot send subscribed payload to missing connection"
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
            remove_channel_subscription(state, &channel_id, connection_id);
        }
    }
}

pub fn is_subscribed_to_channel(
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

fn remove_channel_subscription(
    state: &Arc<AppState>,
    channel_id: &ChannelId,
    connection_id: &ConnectionId,
) {
    if let Some(entry) = state.channel_subscribers.get_mut(channel_id) {
        entry.value().remove(connection_id);
        let empty = entry.value().is_empty();
        drop(entry);
        if empty {
            state.channel_subscribers.remove(channel_id);
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
