use crate::{protocol::GatewayPayload, state::AppState};
use axum::{
    Error,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::{info, warn};

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

async fn handle_socket(state: Arc<AppState>, mut socket: WebSocket) -> Result<(), Error> {
    info!("ws connected");

    let hello = GatewayPayload::Hello {
        heartbeat_interval_ms: 25_000,
    };
    socket.send(text_msg(&hello)).await?;

    // For now just read and log anything the client sends
    while let Some(result) = socket.recv().await {
        match result {
            Ok(Message::Text(text)) => {
                info!("ws recv: {}", text.as_str());

                // Later:
                // let payload: GatewayPayload = serde_json::from_str(text.as_str())?;
                let _ = &state; // keep state “used” for now
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {} // Binary/Ping/Pong ignored for now
            Err(e) => return Err(e),
        }
    }

    info!("ws disconnected");
    Ok(())
}

fn text_msg<T: serde::Serialize>(value: &T) -> Message {
    Message::Text(serde_json::to_string(value).unwrap().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{app, state::AppState};
    use futures_util::StreamExt;
    use tokio::net::TcpListener;
    use tokio_tungstenite::connect_async;

    #[tokio::test]
    async fn hello_payload_is_sent_on_connect() {
        let router = app::build_router(Arc::new(AppState::new()));
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

        socket.close(None).await.unwrap();
        server.abort();
    }
}
