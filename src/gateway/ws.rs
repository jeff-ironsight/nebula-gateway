use crate::data::{ChannelRepository, UserRepository};
use crate::gateway::handler::{
    broadcast_message_to_channel, cleanup_connection, dispatch_error_to_connection,
    dispatch_hello_to_connection, dispatch_ready_to_connection, dispatch_subscribed_to_connection,
    is_subscribed_to_channel, require_identified, subscribe_to_channels,
};
use crate::state::Session;
use crate::{
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
                        let Some(result) = resolve_user(&state, &token).await else {
                            dispatch_error_to_connection(
                                &state,
                                &connection_id,
                                ErrorCode::InvalidToken,
                            );
                            debug!(?connection_id, "identify failed; invalid token");
                            continue;
                        };
                        let users = UserRepository::new(&state.db);
                        let username = users
                            .get_username_by_id(&result.user_id)
                            .await
                            .ok()
                            .flatten()
                            .unwrap_or_default();
                        state.sessions.insert(
                            connection_id,
                            Session {
                                user_id: result.user_id,
                            },
                        );
                        debug!(?connection_id, user_id = ?result.user_id, "connection identified");
                        dispatch_ready_to_connection(
                            &state,
                            &connection_id,
                            &result.user_id,
                            &username,
                            result.is_developer,
                        )
                        .await;
                    }
                    Ok(GatewayPayload::Subscribe {}) => {
                        let Some(user_id) = require_identified(&state, &connection_id) else {
                            dispatch_error_to_connection(
                                &state,
                                &connection_id,
                                ErrorCode::NotIdentified,
                            );
                            debug!(?connection_id, "subscribe ignored; not identified");
                            continue;
                        };

                        let channels = ChannelRepository::new(&state.db);
                        let user_channels = match channels.get_channels_for_user(&user_id).await {
                            Ok(channels) => channels,
                            Err(e) => {
                                warn!(?connection_id, error = %e, "failed to get user channels");
                                continue;
                            }
                        };

                        let channel_ids: Vec<_> = user_channels.iter().map(|c| c.id).collect();

                        subscribe_to_channels(&state, &channel_ids, connection_id);
                        dispatch_subscribed_to_connection(&state, &connection_id, channel_ids);

                        info!(
                            ?connection_id,
                            channels = user_channels.len(),
                            "subscribed to all user channels"
                        );
                    }
                    Ok(GatewayPayload::MessageCreate {
                        channel_id,
                        content,
                    }) => {
                        let Some(user_id) = require_identified(&state, &connection_id) else {
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

                        if !is_subscribed_to_channel(&state, connection_id, &channel_id) {
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

                        let username = {
                            let users = UserRepository::new(&state.db);
                            users.get_username_by_id(&user_id).await.ok().flatten()
                        };

                        let Some(username) = username else {
                            dispatch_error_to_connection(
                                &state,
                                &connection_id,
                                ErrorCode::UsernameRequired,
                            );
                            debug!(
                                ?connection_id,
                                channel = %channel_id,
                                "message create rejected; no username set"
                            );
                            continue;
                        };

                        broadcast_message_to_channel(
                            &state,
                            &channel_id,
                            &user_id,
                            &username,
                            &content,
                        )
                        .await;
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

struct IdentifyResult {
    user_id: UserId,
    is_developer: bool,
}

async fn resolve_user(state: &AppState, token: &Token) -> Option<IdentifyResult> {
    let auth0 = state.auth0.as_ref()?;

    match auth0.verify(&token.0).await {
        Ok(claims) => {
            let users = UserRepository::new(&state.db);
            match users.get_or_create_by_auth_sub(&claims.sub).await {
                Ok(user_id) => Some(IdentifyResult {
                    user_id,
                    is_developer: claims.is_developer(),
                }),
                Err(err) => {
                    debug!(error = %err, "auth0 user mapping failed");
                    None
                }
            }
        }
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
        data::{ChannelRepository, ServerRepository},
        gateway::handler::{
            broadcast_message_to_channel, cleanup_connection, subscribe_to_channel,
        },
        protocol::{ErrorCode, ReadyEvent},
        state::{AppState, test_db},
        types::{ChannelId, Token, UserId},
    };
    use axum::serve;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{from_str as json_from_str, from_value, json, to_string};
    use std::sync::atomic::Ordering;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{Duration, sleep, timeout};
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};
    use uuid::Uuid;

    const ERROR_NOT_IDENTIFIED: ErrorCode = ErrorCode::NotIdentified;

    async fn identify_connection(
        socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
        token: Token,
        user_id: UserId,
        username: &str,
    ) {
        identify_connection_with_developer(socket, token, user_id, username, false).await;
    }

    async fn identify_connection_with_developer(
        socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>,
        token: Token,
        user_id: UserId,
        username: &str,
        is_developer: bool,
    ) {
        let identify = to_string(&GatewayPayload::Identify { token }).unwrap();
        socket
            .send(tungstenite::Message::Text(identify.into()))
            .await
            .unwrap();

        let message = socket.next().await.unwrap().unwrap();
        let payload_text = message.into_text().unwrap();
        let payload: GatewayPayload = json_from_str(&payload_text).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "READY");
                let ready: ReadyEvent = from_value(d).unwrap();
                assert_eq!(ready.user_id, user_id);
                assert_eq!(ready.username, username);
                assert_eq!(ready.heartbeat_interval_ms, 25_000);
                assert_eq!(ready.is_developer, is_developer);
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
        let payload: GatewayPayload = json_from_str(&payload_text).unwrap();
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
            issuer: "https://test-issuer/".into(),
            audience: "test-audience".into(),
            jwks_url: "https://example.invalid/.well-known/jwks.json".into(),
            jwks_cache_ttl: Duration::from_secs(60),
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
    async fn subscribe_to_channel_is_idempotent() {
        let state = Arc::new(AppState::new(test_db().await, None));
        let channel_id = ChannelId::from(Uuid::new_v4());
        let connection_id = ConnectionId::from(Uuid::new_v4());

        subscribe_to_channel(&state, channel_id, connection_id);
        subscribe_to_channel(&state, channel_id, connection_id);

        let subscribers = state.channel_subscribers.get(&channel_id).unwrap();
        assert_eq!(subscribers.len(), 1);
        drop(subscribers);

        let channels = state.connection_channels.get(&connection_id).unwrap();
        assert_eq!(channels.len(), 1);
    }

    #[tokio::test]
    async fn broadcast_removes_stale_subscribers() {
        let state = Arc::new(AppState::new(test_db().await, None));

        // Create user, server, and channel in DB for message persistence
        let users = crate::data::UserRepository::new(&state.db);
        let active_user_id = users
            .get_or_create_by_auth_sub("auth0|broadcast-stale-test")
            .await
            .unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Broadcast Test", &active_user_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "test-channel")
            .await
            .unwrap();

        let stale_connection = ConnectionId::from(Uuid::new_v4());
        let active_connection = ConnectionId::from(Uuid::new_v4());

        {
            let subscribers = state.channel_subscribers.entry(channel_id).or_default();
            subscribers.insert(stale_connection);
            subscribers.insert(active_connection);
        }
        state
            .connection_channels
            .entry(stale_connection)
            .or_default()
            .insert(channel_id);
        state
            .connection_channels
            .entry(active_connection)
            .or_default()
            .insert(channel_id);

        let (tx, mut rx) = unbounded_channel();
        state.connections.insert(active_connection, tx);

        broadcast_message_to_channel(&state, &channel_id, &active_user_id, "active_user", "hello")
            .await;

        let message = rx.recv().await.unwrap();
        match message {
            Message::Text(text) => {
                let payload: GatewayPayload = json_from_str(text.as_ref()).unwrap();
                assert!(matches!(
                    payload,
                    GatewayPayload::Dispatch { t, .. } if t == "MESSAGE_CREATE"
                ));
            }
            other => panic!("expected text message, got {:?}", other),
        }

        let subscribers = state.channel_subscribers.get(&channel_id).unwrap();
        assert_eq!(subscribers.len(), 1);
        assert!(subscribers.iter().any(|id| *id == active_connection));
        drop(subscribers);

        assert!(state.connection_channels.get(&stale_connection).is_none());
        assert!(state.connection_channels.get(&active_connection).is_some());
    }

    #[tokio::test]
    async fn broadcast_removes_closed_senders() {
        let state = Arc::new(AppState::new(test_db().await, None));

        // Create user, server, and channel in DB for message persistence
        let users = crate::data::UserRepository::new(&state.db);
        let active_user_id = users
            .get_or_create_by_auth_sub("auth0|broadcast-closed-test")
            .await
            .unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Broadcast Closed Test", &active_user_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "test-channel")
            .await
            .unwrap();

        let closed_connection = ConnectionId::from(Uuid::new_v4());
        let active_connection = ConnectionId::from(Uuid::new_v4());

        {
            let subscribers = state.channel_subscribers.entry(channel_id).or_default();
            subscribers.insert(closed_connection);
            subscribers.insert(active_connection);
        }
        state
            .connection_channels
            .entry(closed_connection)
            .or_default()
            .insert(channel_id);
        state
            .connection_channels
            .entry(active_connection)
            .or_default()
            .insert(channel_id);

        let (closed_tx, closed_rx) = unbounded_channel();
        drop(closed_rx);
        state.connections.insert(closed_connection, closed_tx);

        let (active_tx, mut active_rx) = unbounded_channel();
        state.connections.insert(active_connection, active_tx);

        broadcast_message_to_channel(&state, &channel_id, &active_user_id, "active_user", "hello")
            .await;

        let message = active_rx.recv().await.unwrap();
        match message {
            Message::Text(text) => {
                let payload: GatewayPayload = json_from_str(text.as_ref()).unwrap();
                assert!(matches!(
                    payload,
                    GatewayPayload::Dispatch { t, .. } if t == "MESSAGE_CREATE"
                ));
            }
            other => panic!("expected text message, got {:?}", other),
        }

        let subscribers = state.channel_subscribers.get(&channel_id).unwrap();
        assert_eq!(subscribers.len(), 1);
        assert!(subscribers.iter().any(|id| *id == active_connection));
        drop(subscribers);

        assert!(state.connection_channels.get(&closed_connection).is_none());
        assert!(state.connection_channels.get(&active_connection).is_some());
    }

    #[tokio::test]
    async fn cleanup_connection_removes_all_channels() {
        let state = Arc::new(AppState::new(test_db().await, None));
        let connection_id = ConnectionId::from(Uuid::new_v4());
        let (tx, _rx) = unbounded_channel();
        state.connections.insert(connection_id, tx);

        let channels = vec![
            ChannelId::from(Uuid::new_v4()),
            ChannelId::from(Uuid::new_v4()),
        ];
        for channel in channels.iter().cloned() {
            subscribe_to_channel(&state, channel, connection_id);
        }

        cleanup_connection(&state, &connection_id);

        assert!(state.connections.get(&connection_id).is_none());
        assert!(state.connection_channels.get(&connection_id).is_none());

        for channel in channels {
            assert!(state.channel_subscribers.get(&channel).is_none());
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
        let server = spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap();

        let subscribe = r#"{"op":"Subscribe","d":{}}"#;
        socket
            .send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();

        expect_error_dispatch(&mut socket, ERROR_NOT_IDENTIFIED).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
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
    async fn subscribe_subscribes_to_user_channels() {
        let state = Arc::new(AppState::new(test_db().await, Some(test_auth0())));
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap(); // Hello

        // Create user with server and channels
        let user_id = UserId::from(Uuid::new_v4());
        let user_sub = format!("auth0|sub-test-{}", Uuid::new_v4());
        seed_auth_user(&state, user_id, &user_sub).await;

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .unwrap();

        // "general" is auto-created by create_server
        let channels = ChannelRepository::new(&state.db);
        let server_channels = channels.get_channels_for_server(&server_id).await.unwrap();
        let channel1 = server_channels[0].id;
        let channel2 = channels.create_channel(&server_id, "random").await.unwrap();

        // Identify
        identify_connection(&mut socket, Token(user_sub.clone()), user_id, &user_sub).await;

        // Subscribe
        let subscribe = r#"{"op":"Subscribe","d":{}}"#;
        socket
            .send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();

        // Expect SUBSCRIBED event
        let message = timeout(Duration::from_secs(1), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let payload: GatewayPayload = json_from_str(&message.into_text().unwrap()).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "SUBSCRIBED");
                let channel_ids: Vec<ChannelId> =
                    serde_json::from_value(d.get("channel_ids").unwrap().clone()).unwrap();
                // User has default server channel + 2 created channels
                assert!(channel_ids.contains(&channel1));
                assert!(channel_ids.contains(&channel2));
            }
            other => panic!("expected SUBSCRIBED dispatch, got {:?}", other),
        }

        socket.close(None).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn message_create_is_ignored_when_not_identified() {
        let state = Arc::new(AppState::new(test_db().await, None));
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap();

        let channel_id = ChannelId::from(Uuid::new_v4());
        let message = to_string(&GatewayPayload::MessageCreate {
            channel_id,
            content: "hello world".into(),
        })
        .unwrap();
        socket
            .send(tungstenite::Message::Text(message.into()))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(state.dispatch_counter.load(Ordering::Relaxed), 0);
        assert!(state.channel_subscribers.get(&channel_id).is_none());

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

        // Create users with shared server
        let alice_user_id = UserId::from(Uuid::new_v4());
        let bob_user_id = UserId::from(Uuid::new_v4());
        let alice_sub = format!("auth0|alice-{}", Uuid::new_v4());
        let bob_sub = format!("auth0|bob-{}", Uuid::new_v4());
        seed_auth_user(&state, alice_user_id, &alice_sub).await;
        seed_auth_user(&state, bob_user_id, &bob_sub).await;

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Shared Server", &alice_user_id)
            .await
            .unwrap();
        servers
            .add_member(&server_id, &bob_user_id, "member")
            .await
            .unwrap();

        // "general" is auto-created by create_server
        let channels = ChannelRepository::new(&state.db);
        let server_channels = channels.get_channels_for_server(&server_id).await.unwrap();
        let channel_id = server_channels[0].id;

        // Identify both
        identify_connection(
            &mut alice,
            Token(alice_sub.clone()),
            alice_user_id,
            &alice_sub,
        )
        .await;
        identify_connection(&mut bob, Token(bob_sub.clone()), bob_user_id, &bob_sub).await;

        // Both subscribe
        let subscribe = r#"{"op":"Subscribe","d":{}}"#;
        alice
            .send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();
        bob.send(tungstenite::Message::Text(subscribe.into()))
            .await
            .unwrap();

        // Consume SUBSCRIBED events
        alice.next().await.unwrap().unwrap();
        bob.next().await.unwrap().unwrap();

        // Wait for subscriptions to be set up
        timeout(Duration::from_secs(1), async {
            loop {
                if let Some(subs) = state.channel_subscribers.get(&channel_id)
                    && subs.len() == 2
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        // Alice sends message
        let message = to_string(&GatewayPayload::MessageCreate {
            channel_id,
            content: "hello world".into(),
        })
        .unwrap();
        alice
            .send(tungstenite::Message::Text(message.into()))
            .await
            .unwrap();

        // Bob receives it
        let next = bob.next().await.unwrap().unwrap();
        let payload_text = next.into_text().unwrap();
        let payload: GatewayPayload = json_from_str(&payload_text).unwrap();
        match payload {
            GatewayPayload::Dispatch { t, d } => {
                assert_eq!(t, "MESSAGE_CREATE");
                assert_eq!(d.get("channel_id"), Some(&json!(channel_id)));
                assert_eq!(d.get("content"), Some(&json!("hello world")));
                assert_eq!(d.get("author_user_id"), Some(&json!(alice_user_id)));
            }
            other => panic!("expected dispatch payload, got {:?}", other),
        }

        alice.close(None).await.unwrap();
        bob.close(None).await.unwrap();
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

        alice.next().await.unwrap().unwrap();
        let alice_user_id = UserId::from(Uuid::new_v4());
        let alice_sub = format!("auth0|alice-{}", Uuid::new_v4());
        seed_auth_user(&state, alice_user_id, &alice_sub).await;
        identify_connection(
            &mut alice,
            Token(alice_sub.clone()),
            alice_user_id,
            &alice_sub,
        )
        .await;

        // Alice tries to send to a channel she's not subscribed to
        let channel_id = ChannelId::from(Uuid::new_v4());
        let message = to_string(&GatewayPayload::MessageCreate {
            channel_id,
            content: "hello world".into(),
        })
        .unwrap();
        alice
            .send(tungstenite::Message::Text(message.into()))
            .await
            .unwrap();

        expect_error_dispatch(&mut alice, ErrorCode::NotSubscribed).await;
        assert_eq!(
            state.dispatch_counter.load(Ordering::Relaxed),
            0,
            "no dispatch should be emitted for an unsubscribed sender"
        );

        alice.close(None).await.unwrap();
        server.abort();
    }

    fn test_auth0_with_developer(sub: &str) -> Auth0Verifier {
        use crate::auth0::{AppClaims, Auth0Claims};

        Auth0Verifier::new_test_with_claims(
            Auth0Settings {
                issuer: "https://test-issuer/".into(),
                audience: "test-audience".into(),
                jwks_url: "https://example.invalid/.well-known/jwks.json".into(),
                jwks_cache_ttl: Duration::from_secs(60),
            },
            Auth0Claims {
                sub: sub.to_string(),
                iss: None,
                aud: None,
                exp: None,
                app: Some(AppClaims { is_developer: true }),
            },
        )
    }

    #[tokio::test]
    async fn identify_returns_is_developer_true_for_developer_user() {
        let dev_sub = format!("auth0|dev-{}", Uuid::new_v4());
        let state = Arc::new(AppState::new(
            test_db().await,
            Some(test_auth0_with_developer(&dev_sub)),
        ));
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap();

        let dev_user_id = UserId::from(Uuid::new_v4());
        seed_auth_user(&state, dev_user_id, &dev_sub).await;

        identify_connection_with_developer(
            &mut socket,
            Token(dev_sub.clone()),
            dev_user_id,
            &dev_sub,
            true,
        )
        .await;

        socket.close(None).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn identify_returns_is_developer_false_for_regular_user() {
        let state = Arc::new(AppState::new(test_db().await, Some(test_auth0())));
        let router = app::build_router(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let url = format!("ws://{}/ws", addr);
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.next().await.unwrap().unwrap();

        let user_id = UserId::from(Uuid::new_v4());
        let user_sub = format!("auth0|user-{}", Uuid::new_v4());
        seed_auth_user(&state, user_id, &user_sub).await;

        identify_connection_with_developer(
            &mut socket,
            Token(user_sub.clone()),
            user_id,
            &user_sub,
            false,
        )
        .await;

        socket.close(None).await.unwrap();
        server.abort();
    }
}
