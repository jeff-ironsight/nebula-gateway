use crate::data::messages::MessageRow;
use crate::data::{ChannelRepository, MessageRepository, ServerRepository};
use crate::rest::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::types::ChannelId;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/channels/{channel_id}/messages", get(get_channel_messages))
}

#[derive(Deserialize)]
struct GetMessagesQuery {
    limit: Option<i64>,
    before: Option<String>,
}

#[derive(Serialize)]
struct MessageResponse {
    id: String,
    channel_id: Uuid,
    author_user_id: Uuid,
    author_username: String,
    content: String,
    created_at: String,
}

impl From<MessageRow> for MessageResponse {
    fn from(row: MessageRow) -> Self {
        Self {
            id: row.id,
            channel_id: row.channel_id.0,
            author_user_id: row.author_user_id.0,
            author_username: row.author_username,
            content: row.content,
            created_at: row.created_at.to_rfc3339(),
        }
    }
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

async fn get_channel_messages(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(channel_id): Path<Uuid>,
    Query(query): Query<GetMessagesQuery>,
) -> Result<Json<Vec<MessageResponse>>, Response> {
    let channel_id = ChannelId::from(channel_id);
    let channels = ChannelRepository::new(&state.db);

    // Verify channel exists
    let channel = channels
        .get_by_id(&channel_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get channel");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ApiError {
                    error: "Channel not found".to_string(),
                }),
            )
                .into_response()
        })?;

    // Verify user is member of the channel's server
    let servers = ServerRepository::new(&state.db);
    let is_member = servers
        .is_member(&channel.server_id, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check server membership");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    if !is_member {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "Not a member of this server".to_string(),
            }),
        )
            .into_response());
    }

    // Fetch messages with pagination
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let before = query.before.as_deref();

    let messages = MessageRepository::new(&state.db);
    let rows = messages
        .get_by_channel(&channel_id, limit, before)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get messages");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    let response: Vec<MessageResponse> = rows.into_iter().map(MessageResponse::from).collect();
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth0::{Auth0Settings, Auth0Verifier};
    use crate::data::UserRepository;
    use crate::state::test_db;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use std::time::Duration;
    use tower::ServiceExt;

    fn test_auth0() -> Auth0Verifier {
        Auth0Verifier::new_test(Auth0Settings {
            issuer: "https://test-issuer/".into(),
            audience: "test-audience".into(),
            jwks_url: "https://example.invalid/.well-known/jwks.json".into(),
            jwks_cache_ttl: Duration::from_secs(60),
        })
    }

    #[tokio::test]
    async fn get_messages_returns_channel_messages() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create user and server
        let auth_sub = format!("auth0|get-messages-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "test-channel")
            .await
            .unwrap();

        // Create some messages
        let messages = MessageRepository::new(&state.db);
        messages
            .create(
                &format!("01H{}", Uuid::new_v4()),
                &channel_id,
                &user_id,
                "First message",
            )
            .await
            .unwrap();
        messages
            .create(
                &format!("01H{}", Uuid::new_v4()),
                &channel_id,
                &user_id,
                "Second message",
            )
            .await
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}/messages", channel_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let messages: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(messages.len(), 2);
        // Most recent first
        assert_eq!(messages[0]["content"], "Second message");
        assert_eq!(messages[1]["content"], "First message");
    }

    #[tokio::test]
    async fn get_messages_respects_limit() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|get-messages-limit-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "test-channel")
            .await
            .unwrap();

        let messages = MessageRepository::new(&state.db);
        for i in 1..=5 {
            messages
                .create(
                    &format!("01H{}", Uuid::new_v4()),
                    &channel_id,
                    &user_id,
                    &format!("Message {}", i),
                )
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}/messages?limit=2", channel_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let messages: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["content"], "Message 5");
        assert_eq!(messages[1]["content"], "Message 4");
    }

    #[tokio::test]
    async fn get_messages_returns_404_for_nonexistent_channel() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|get-messages-404-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let fake_channel_id = Uuid::new_v4();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}/messages", fake_channel_id))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_messages_returns_403_for_non_member() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create requesting user (not a member of the server)
        let auth_sub = format!("auth0|get-messages-403-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        // Create another user who owns a server with a channel
        let owner_auth_sub = format!("auth0|owner-{}", Uuid::new_v4());
        let owner_id = users
            .get_or_create_by_auth_sub(&owner_auth_sub)
            .await
            .unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Private Server", &owner_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "private-channel")
            .await
            .unwrap();

        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}/messages", channel_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_messages_returns_401_for_unauthenticated() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}/messages", Uuid::new_v4()))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
