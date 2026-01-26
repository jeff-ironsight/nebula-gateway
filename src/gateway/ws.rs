use crate::gateway::handler::{
    dispatch_error_to_connection, dispatch_hello_to_connection, dispatch_ready_to_connection,
    require_identified,
};
use crate::state::Session;
use crate::{
    gateway::handler::{
        broadcast_message_to_channel, cleanup_connection, is_subscribed, subscribe_connection,
    },
    protocol::{ErrorCode, GatewayPayload},
    state::AppState,
    types::{ConnectionId, Token, UserId},
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
use serde_json::from_str;
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel;
use tokio::{
    spawn,
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
    let (outbound_tx, mut outbound_rx) = unbounded_channel::<Message>();

    // Store sender so other tasks can send to this connection
    state.connections.insert(connection_id, outbound_tx.clone());

    // Writer task: drain outbound_rx -> websocket
    let mut send_task = spawn(async move {
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

                match from_str::<GatewayPayload>(text.as_str()) {
                    Ok(GatewayPayload::Identify { token }) => {
                        let Some(user_id) = resolve_user_id(&state, &token).await else {
                            dispatch_error_to_connection(
                                &state,
                                &connection_id,
                                ErrorCode::InvalidToken,
                            );
                            debug!(?connection_id, "identify failed; invalid token");
                            continue;
                        };
                        let username = state
                            .get_username_by_user_id(&user_id)
                            .await
                            .ok()
                            .flatten()
                            .unwrap_or_default();
                        state.sessions.insert(connection_id, Session { user_id });
                        debug!(?connection_id, ?user_id, "connection identified");
                        dispatch_ready_to_connection(&state, &connection_id, &user_id, &username);
                    }
                    Ok(GatewayPayload::Subscribe { channel_id }) => {
                        let Some(_user_id) = require_identified(&state, &connection_id) else {
                            dispatch_error_to_connection(
                                &state,
                                &connection_id,
                                ErrorCode::NotIdentified,
                            );
                            debug!(
                                ?connection_id,
                                channel = %channel_id,
                                "subscribe ignored; not identified"
                            );
                            continue;
                        };
                        subscribe_connection(&state, channel_id, connection_id);
                    }
                    Ok(GatewayPayload::MessageCreate {
                        channel_id,
                        content,
                    }) => {
                        let Some(_user_id) = require_identified(&state, &connection_id) else {
                            dispatch_error_to_connection(
                                &state,
                                &connection_id,
                                ErrorCode::NotIdentified,
                            );
                            debug!(
                                ?connection_id,
                                channel = %channel_id,
                                "message create ignored; not identified"
                            );
                            continue;
                        };
                        if !is_subscribed(&state, connection_id, &channel_id) {
                            dispatch_error_to_connection(
                                &state,
                                &connection_id,
                                ErrorCode::NotSubscribed,
                            );
                            debug!(
                                ?connection_id,
                                channel = %channel_id,
                                "message create ignored; not subscribed"
                            );
                            continue;
                        }
                        broadcast_message_to_channel(&state, &channel_id, &_user_id, &content);
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

async fn resolve_user_id(state: &AppState, token: &Token) -> Option<UserId> {
    let auth0 = state.auth0.as_ref()?;

    match auth0.verify(&token.0).await {
        Ok(claims) => match state.get_or_create_user_by_auth_sub(&claims.sub).await {
            Ok(user_id) => Some(user_id),
            Err(err) => {
                debug!(error = %err, "auth0 user mapping failed");
                None
            }
        },
        Err(err) => {
            debug!(error = ?err, "auth0 token verification failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app,
        auth0::{Auth0Settings, Auth0Verifier},
        gateway::handler::{
            broadcast_message_to_channel, cleanup_connection, subscribe_connection,
        },
        protocol::{ErrorCode, ReadyEvent},
        state::{AppState, test_db},
        types::{ChannelId, Token, UserId},
    };
    use axum::serve;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{from_value, json, to_string};
    use std::sync::atomic::Ordering;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::{
        sync::mpsc,
        time::{Duration, sleep, timeout},
    };
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};
    use uuid::Uuid;

    const ERROR_NOT_IDENTIFIED: ErrorCode = ErrorCode::NotIdentified;

    async fn identify_connection(
        socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
        token: Token,
        user_id: UserId,
        username: &str,
    ) {
        let identify = to_string(&GatewayPayload::Identify { token }).unwrap();
        socket
            .send(tungstenite::Message::Text(identify.into()))
            .await
            .unwrap();

        let message = socket.next().await.unwrap().unwrap();
        let payload_text = message.into_text().unwrap();
        let payload: GatewayPayload = from_str(&payload_text).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "READY");
                let ready: ReadyEvent = from_value(d).unwrap();
                assert_eq!(ready.user_id, user_id);
                assert_eq!(ready.username, username);
                assert_eq!(ready.heartbeat_interval_ms, 25_000);
            }
            other => panic!("expected READY dispatch, got {:?}", other),
        }
    }

    async fn expect_error_dispatch(
        socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
        code: ErrorCode,
    ) {
        let message = timeout(Duration::from_secs(1), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let payload_text = message.into_text().unwrap();
        let payload: GatewayPayload = from_str(&payload_text).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "ERROR");
                assert_eq!(d.get("code"), Some(&json!(code)));
            }
            other => panic!("expected ERROR dispatch, got {:?}", other),
        }
    }

    fn test_auth0() -> Auth0Verifier {
        Auth0Verifier::new_test(Auth0Settings {
            issuer: "https://test-issuer".into(),
            audience: "test-audience".into(),
            userinfo_url: "https://example.invalid/userinfo".into(),
            userinfo_cache_ttl: Duration::from_secs(60),
        })
    }

    async fn seed_auth_user(state: &AppState, user_id: UserId, sub: &str) {
        sqlx::query("insert into users (id, username, auth_sub) values ($1, $2, $3)")
            .bind(user_id.0)
            .bind(sub)
            .bind(sub)
            .execute(&state.db)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn subscribe_connection_is_idempotent() {
        let state = Arc::new(AppState::new(test_db().await, None));
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
        let state = Arc::new(AppState::new(test_db().await, None));
        let channel_id = ChannelId::from("general");
        let stale_connection = ConnectionId::from(Uuid::new_v4());
        let active_connection = ConnectionId::from(Uuid::new_v4());
        let active_user_id = UserId::from(Uuid::new_v4());

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

        broadcast_message_to_channel(&state, &channel_id, &active_user_id, "hello");

        let message = rx.recv().await.unwrap();
        match message {
            Message::Text(text) => {
                let payload: GatewayPayload = from_str(text.as_ref()).unwrap();
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

    #[tokio::test]
    async fn cleanup_connection_removes_all_channels() {
        let state = Arc::new(AppState::new(test_db().await, None));
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
        let state = Arc::new(AppState::new(test_db().await, None));
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();

        let message = socket.next().await.unwrap().unwrap();
        let text = message.into_text().unwrap();
        let expected = to_string(&GatewayPayload::Hello {
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
        let state = Arc::new(AppState::new(test_db().await, None));
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
        let subscribe = to_string(&GatewayPayload::Subscribe {
            channel_id: channel_id.clone(),
        })
        .unwrap();
        socket
            .send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();

        expect_error_dispatch(&mut socket, ERROR_NOT_IDENTIFIED).await;
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
        let state = Arc::new(AppState::new(test_db().await, None));
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
        let message = to_string(&GatewayPayload::MessageCreate {
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
        let state = Arc::new(AppState::new(test_db().await, Some(test_auth0())));
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut alice, _) = connect_async(&url).await.unwrap();
        let (mut bob, _) = connect_async(&url).await.unwrap();

        alice.next().await.unwrap().unwrap();
        bob.next().await.unwrap().unwrap();
        let alice_user_id = UserId::from(Uuid::new_v4());
        let bob_user_id = UserId::from(Uuid::new_v4());
        let alice_sub = format!("auth0|alice-{}", Uuid::new_v4());
        let bob_sub = format!("auth0|bob-{}", Uuid::new_v4());
        let alice_token = Token(alice_sub.clone());
        let bob_token = Token(bob_sub.clone());
        seed_auth_user(&state, alice_user_id, &alice_sub).await;
        seed_auth_user(&state, bob_user_id, &bob_sub).await;
        identify_connection(&mut alice, alice_token, alice_user_id, &alice_sub).await;
        identify_connection(&mut bob, bob_token, bob_user_id, &bob_sub).await;

        let channel_id = ChannelId::from("general");
        let subscribe = to_string(&GatewayPayload::Subscribe {
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

        let message = to_string(&GatewayPayload::MessageCreate {
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
        let payload: GatewayPayload = from_str(&payload_text).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "MESSAGE_CREATE");
                assert_eq!(d.get("channel_id"), Some(&json!(channel_id)));
                assert_eq!(d.get("content"), Some(&json!("hello world")));
                assert!(d.get("id").and_then(|value| value.as_str()).is_some());
                assert_eq!(d.get("author_user_id"), Some(&json!(alice_user_id)));
                assert!(
                    d.get("timestamp")
                        .and_then(|value| value.as_str())
                        .is_some()
                );
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
        let state = Arc::new(AppState::new(test_db().await, Some(test_auth0())));
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut alice, _) = connect_async(&url).await.unwrap();
        let (mut bob, _) = connect_async(&url).await.unwrap();

        alice.next().await.unwrap().unwrap();
        bob.next().await.unwrap().unwrap();
        let alice_user_id = UserId::from(Uuid::new_v4());
        let bob_user_id = UserId::from(Uuid::new_v4());
        let alice_sub = format!("auth0|alice-{}", Uuid::new_v4());
        let bob_sub = format!("auth0|bob-{}", Uuid::new_v4());
        let alice_token = Token(alice_sub.clone());
        let bob_token = Token(bob_sub.clone());
        seed_auth_user(&state, alice_user_id, &alice_sub).await;
        seed_auth_user(&state, bob_user_id, &bob_sub).await;
        identify_connection(&mut alice, alice_token, alice_user_id, &alice_sub).await;
        identify_connection(&mut bob, bob_token, bob_user_id, &bob_sub).await;

        let channel_id = ChannelId::from("general");
        let subscribe = to_string(&GatewayPayload::Subscribe {
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

        let message = to_string(&GatewayPayload::MessageCreate {
            channel_id: channel_id.clone(),
            content: "hello world".into(),
        })
        .unwrap();
        alice
            .send(tungstenite::Message::Text(message.into()))
            .await
            .unwrap();

        expect_error_dispatch(&mut alice, ErrorCode::NotSubscribed).await;

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
