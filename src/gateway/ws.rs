use crate::gateway::handler::{
    dispatch_hello_to_connection, dispatch_ready_to_connection, require_identified,
};
use crate::state::Session;
use crate::{
    gateway::handler::{
        broadcast_message_to_channel, cleanup_connection, is_subscribed, subscribe_connection,
    },
    protocol::GatewayPayload,
    state::AppState,
    types::ConnectionId,
};
use axum::{
    Error,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::{
    sync::mpsc,
    time::{Duration, timeout},
};
use tracing::{debug, info, warn};
use uuid::Uuid;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        if let Err(err) = handle_socket(state, socket).await {
            warn!("ws closed with error: {:?}", err);
        }
    })
}

async fn handle_socket(state: Arc<AppState>, socket: WebSocket) -> Result<(), Error> {
    let connection_id = ConnectionId::from(Uuid::new_v4());
    info!(?connection_id, "ws connected");

    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Message>();

    // Store sender so other tasks can send to this connection
    state.connections.insert(connection_id, outbound_tx.clone());

    // Writer task: drain outbound_rx -> websocket
    let mut send_task = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            if ws_sender.send(message).await.is_err() {
                break;
            }
        }
    });

    dispatch_hello_to_connection(&state, &connection_id);

    let mut reader_result: Result<(), Error> = Ok(());

    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(Message::Text(text)) => {
                debug!(?connection_id, "ws recv: {}", text.as_str());

                match serde_json::from_str::<GatewayPayload>(text.as_str()) {
                    Ok(GatewayPayload::Identify { user_id }) => {
                        state.sessions.insert(connection_id, Session { user_id });
                        debug!(?connection_id, ?user_id, "connection identified");
                        dispatch_ready_to_connection(&state, &connection_id, &user_id);
                    }
                    Ok(GatewayPayload::Subscribe { channel_id }) => {
                        let Some(_user_id) = require_identified(&state, &connection_id) else {
                            continue;
                        };
                        subscribe_connection(&state, channel_id, connection_id);
                    }
                    Ok(GatewayPayload::MessageCreate {
                        channel_id,
                        content,
                    }) => {
                        let Some(_user_id) = require_identified(&state, &connection_id) else {
                            continue;
                        };
                        if !is_subscribed(&state, connection_id, &channel_id) {
                            debug!(
                                ?connection_id,
                                channel = %channel_id,
                                "message create ignored; not subscribed"
                            );
                            continue;
                        }
                        broadcast_message_to_channel(&state, &channel_id, &connection_id, &content);
                    }
                    Ok(_other) => {
                        // Ignore unhandled payloads for now
                    }
                    Err(err) => {
                        warn!(?connection_id, error = %err, "invalid gateway payload");
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(e) => {
                reader_result = Err(e);
                break;
            }
        }
    }

    cleanup_connection(&state, &connection_id);
    drop(outbound_tx);
    if timeout(Duration::from_millis(200), &mut send_task)
        .await
        .is_err()
    {
        debug!(?connection_id, "send task timeout; aborting");
        send_task.abort();
        let _ = send_task.await;
    }

    info!(?connection_id, "ws disconnected");
    reader_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app,
        gateway::handler::{
            broadcast_message_to_channel, cleanup_connection, subscribe_connection,
        },
        protocol::ReadyEvent,
        state::AppState,
        types::{ChannelId, UserId},
    };
    use futures_util::{SinkExt, StreamExt};
    use serde_json::json;
    use std::sync::atomic::Ordering;
    use tokio::net::TcpListener;
    use tokio::{
        sync::mpsc,
        time::{Duration, sleep, timeout},
    };
    use tokio_tungstenite::{connect_async, tungstenite};
    use uuid::Uuid;

    async fn identify_connection(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        user_id: Uuid,
    ) {
        let identify = serde_json::to_string(&GatewayPayload::Identify {
            user_id: UserId::from(user_id),
        })
        .unwrap();
        socket
            .send(tungstenite::Message::Text(identify.into()))
            .await
            .unwrap();

        let message = socket.next().await.unwrap().unwrap();
        let payload_text = message.into_text().unwrap();
        let payload: GatewayPayload = serde_json::from_str(&payload_text).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "READY");
                let ready: ReadyEvent = serde_json::from_value(d).unwrap();
                assert_eq!(ready.user_id, UserId::from(user_id));
                assert_eq!(ready.heartbeat_interval_ms, 25_000);
            }
            other => panic!("expected READY dispatch, got {:?}", other),
        }
    }

    #[test]
    fn subscribe_connection_is_idempotent() {
        let state = Arc::new(AppState::new());
        let channel_id = ChannelId::from("general");
        let connection_id = ConnectionId::from(Uuid::new_v4());

        subscribe_connection(&state, channel_id.clone(), connection_id);
        subscribe_connection(&state, channel_id.clone(), connection_id);

        let members = state.channel_members.get(&channel_id).unwrap();
        assert_eq!(members.len(), 1);
        drop(members);

        let channels = state.connection_channels.get(&connection_id).unwrap();
        assert_eq!(channels.len(), 1);
    }

    #[tokio::test]
    async fn broadcast_removes_stale_members() {
        let state = Arc::new(AppState::new());
        let channel_id = ChannelId::from("general");
        let stale_connection = ConnectionId::from(Uuid::new_v4());
        let active_connection = ConnectionId::from(Uuid::new_v4());

        {
            let members = state.channel_members.entry(channel_id.clone()).or_default();
            members.insert(stale_connection);
            members.insert(active_connection);
        }
        state
            .connection_channels
            .entry(stale_connection)
            .or_default()
            .insert(channel_id.clone());
        state
            .connection_channels
            .entry(active_connection)
            .or_default()
            .insert(channel_id.clone());

        let (tx, mut rx) = mpsc::unbounded_channel();
        state.connections.insert(active_connection, tx);

        broadcast_message_to_channel(&state, &channel_id, &active_connection, "hello");

        let message = rx.recv().await.unwrap();
        match message {
            Message::Text(text) => {
                let payload: GatewayPayload = serde_json::from_str(text.as_ref()).unwrap();
                assert!(matches!(
                    payload,
                    GatewayPayload::Dispatch { t, .. } if t == "MESSAGE_CREATE"
                ));
            }
            other => panic!("expected text message, got {:?}", other),
        }

        let members = state.channel_members.get(&channel_id).unwrap();
        assert_eq!(members.len(), 1);
        assert!(members.iter().any(|id| *id == active_connection));
        drop(members);

        assert!(state.connection_channels.get(&stale_connection).is_none());
        assert!(state.connection_channels.get(&active_connection).is_some());
    }

    #[test]
    fn cleanup_connection_removes_all_channels() {
        let state = Arc::new(AppState::new());
        let connection_id = ConnectionId::from(Uuid::new_v4());
        let (tx, _rx) = mpsc::unbounded_channel();
        state.connections.insert(connection_id, tx);

        let channels = vec![ChannelId::from("alpha"), ChannelId::from("beta")];
        for channel in channels.iter().cloned() {
            subscribe_connection(&state, channel, connection_id);
        }

        cleanup_connection(&state, &connection_id);

        assert!(state.connections.get(&connection_id).is_none());
        assert!(state.connection_channels.get(&connection_id).is_none());

        for channel in channels {
            assert!(state.channel_members.get(&channel).is_none());
        }
    }

    #[tokio::test]
    async fn hello_payload_is_sent_on_connect() {
        let state = Arc::new(AppState::new());
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();

        let message = socket.next().await.unwrap().unwrap();
        let text = message.into_text().unwrap();
        let expected = serde_json::to_string(&GatewayPayload::Hello {
            heartbeat_interval_ms: 25_000,
        })
        .unwrap();

        assert_eq!(text, expected);
        assert_eq!(state.connections.len(), 1);
        assert_eq!(state.connection_channels.len(), 0);

        socket.close(None).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while !state.connections.is_empty() || !state.connection_channels.is_empty() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        server.abort();
    }

    #[tokio::test]
    async fn subscribe_is_ignored_when_not_identified() {
        let state = Arc::new(AppState::new());
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap();

        let channel_id = ChannelId::from("general");
        let subscribe = serde_json::to_string(&GatewayPayload::Subscribe {
            channel_id: channel_id.clone(),
        })
        .unwrap();
        socket
            .send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(state.channel_members.get(&channel_id).is_none());
        assert!(state.connection_channels.is_empty());

        socket.close(None).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while !state.connections.is_empty() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        server.abort();
    }

    #[tokio::test]
    async fn message_create_is_ignored_when_not_identified() {
        let state = Arc::new(AppState::new());
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap();

        let channel_id = ChannelId::from("general");
        let message = serde_json::to_string(&GatewayPayload::MessageCreate {
            channel_id: channel_id.clone(),
            content: "hello world".into(),
        })
        .unwrap();
        socket
            .send(tungstenite::Message::Text(message.into()))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(state.dispatch_counter.load(Ordering::Relaxed), 0);
        assert!(state.channel_members.get(&channel_id).is_none());

        socket.close(None).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while !state.connections.is_empty() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        server.abort();
    }

    #[tokio::test]
    async fn message_create_broadcasts_to_channel_subscribers() {
        let state = Arc::new(AppState::new());
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut alice, _) = connect_async(&url).await.unwrap();
        let (mut bob, _) = connect_async(&url).await.unwrap();

        alice.next().await.unwrap().unwrap();
        bob.next().await.unwrap().unwrap();
        identify_connection(&mut alice, Uuid::new_v4()).await;
        identify_connection(&mut bob, Uuid::new_v4()).await;

        let channel_id = ChannelId::from("general");
        let subscribe = serde_json::to_string(&GatewayPayload::Subscribe {
            channel_id: channel_id.clone(),
        })
        .unwrap();
        alice
            .send(tungstenite::Message::Text(subscribe.clone().into()))
            .await
            .unwrap();
        bob.send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();

        timeout(Duration::from_secs(1), async {
            loop {
                if let Some(members) = state.channel_members.get(&channel_id)
                    && members.len() == 2
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(state.connection_channels.len(), 2);

        let message = serde_json::to_string(&GatewayPayload::MessageCreate {
            channel_id: channel_id.clone(),
            content: "hello world".into(),
        })
        .unwrap();
        alice
            .send(tungstenite::Message::Text(message.into()))
            .await
            .unwrap();

        let next = bob.next().await.unwrap().unwrap();
        let payload_text = next.into_text().unwrap();
        let payload: GatewayPayload = serde_json::from_str(&payload_text).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "MESSAGE_CREATE");
                assert_eq!(d.get("channel_id"), Some(&json!(channel_id)));
                assert_eq!(d.get("content"), Some(&json!("hello world")));
                assert!(d.get("id").and_then(|value| value.as_str()).is_some());
                assert!(
                    d.get("author_connection_id")
                        .and_then(|value| value.as_str())
                        .is_some()
                );
                assert!(d.get("timestamp").is_none());
            }
            other => panic!("expected dispatch payload, got {:?}", other),
        }

        alice.close(None).await.unwrap();
        bob.close(None).await.unwrap();

        timeout(Duration::from_secs(1), async {
            while !state.connections.is_empty()
                || !state.channel_members.is_empty()
                || !state.connection_channels.is_empty()
            {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        server.abort();
    }

    #[tokio::test]
    async fn message_create_is_ignored_when_not_subscribed() {
        let state = Arc::new(AppState::new());
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut alice, _) = connect_async(&url).await.unwrap();
        let (mut bob, _) = connect_async(&url).await.unwrap();

        alice.next().await.unwrap().unwrap();
        bob.next().await.unwrap().unwrap();
        identify_connection(&mut alice, Uuid::new_v4()).await;
        identify_connection(&mut bob, Uuid::new_v4()).await;

        let channel_id = ChannelId::from("general");
        let subscribe = serde_json::to_string(&GatewayPayload::Subscribe {
            channel_id: channel_id.clone(),
        })
        .unwrap();
        bob.send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();

        timeout(Duration::from_secs(1), async {
            while state
                .channel_members
                .get(&channel_id)
                .map(|set| set.len())
                .unwrap_or(0)
                < 1
            {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let message = serde_json::to_string(&GatewayPayload::MessageCreate {
            channel_id: channel_id.clone(),
            content: "hello world".into(),
        })
        .unwrap();
        alice
            .send(tungstenite::Message::Text(message.into()))
            .await
            .unwrap();

        alice.close(None).await.unwrap();
        bob.close(None).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while !state.connections.is_empty()
                || !state.channel_members.is_empty()
                || !state.connection_channels.is_empty()
            {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        assert_eq!(
            state.dispatch_counter.load(Ordering::Relaxed),
            0,
            "no dispatch should be emitted for an unsubscribed sender"
        );

        server.abort();
    }
}
