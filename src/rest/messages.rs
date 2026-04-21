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

fn internal_error(error: impl std::fmt::Display, context: &str) -> Response {
    tracing::error!(error = %error, context, "Internal error");
    ApiError {
        error: "Internal error".to_string(),
    }
    .into_response()
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
    let channel = match channels.get_by_id(&channel_id).await {
        Ok(channel) => channel,
        Err(e) => return Err(internal_error(e, "Failed to get channel")),
    }
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
    let is_member = match servers.is_member(&channel.server_id, &user.user_id).await {
        Ok(is_member) => is_member,
        Err(e) => return Err(internal_error(e, "Failed to check server membership")),
    };

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
    let rows = match messages.get_by_channel(&channel_id, limit, before).await {
        Ok(rows) => rows,
        Err(e) => return Err(internal_error(e, "Failed to get messages")),
    };

    let response: Vec<MessageResponse> = rows.into_iter().map(MessageResponse::from).collect();
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth0::{Auth0Settings, Auth0Verifier};
    use crate::data::UserRepository;
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
            jwks_cache_ttl: Duration::from_mins(1),
        })
    }

    #[sqlx::test]
    async fn get_messages_returns_channel_messages(pool: sqlx::PgPool) {
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
            .header("Authorization", format!("Bearer {auth_sub}"))
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

    #[sqlx::test]
    async fn get_messages_respects_limit(pool: sqlx::PgPool) {
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
                    &format!("Message {i}"),
                )
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}/messages?limit=2", channel_id.0))
            .header("Authorization", format!("Bearer {auth_sub}"))
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

    #[sqlx::test]
    async fn get_messages_returns_404_for_nonexistent_channel(pool: sqlx::PgPool) {
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|get-messages-404-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let fake_channel_id = Uuid::new_v4();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{fake_channel_id}/messages"))
            .header("Authorization", format!("Bearer {auth_sub}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test]
    async fn get_messages_returns_403_for_non_member(pool: sqlx::PgPool) {
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
            .header("Authorization", format!("Bearer {auth_sub}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test]
    async fn get_messages_returns_401_for_unauthenticated(pool: sqlx::PgPool) {
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

    #[sqlx::test]
    async fn get_messages_respects_before_cursor(pool: sqlx::PgPool) {
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|get-messages-before-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Before Cursor Server", &user_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "before-channel")
            .await
            .unwrap();

        let messages = MessageRepository::new(&state.db);
        for i in 1..=4 {
            let id = format!("01HBEFORE{i:03}");
            messages
                .create(&id, &channel_id, &user_id, &format!("Message {i}"))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Fetch first page (most recent 2)
        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}/messages?limit=2", channel_id.0))
            .header("Authorization", format!("Bearer {auth_sub}"))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let page1: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0]["content"], "Message 4");
        assert_eq!(page1[1]["content"], "Message 3");

        // Fetch second page using the before cursor (ID of the last message on page 1)
        let cursor = page1[1]["id"].as_str().unwrap();
        let request = Request::builder()
            .method("GET")
            .uri(format!(
                "/channels/{}/messages?limit=2&before={cursor}",
                channel_id.0
            ))
            .header("Authorization", format!("Bearer {auth_sub}"))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let page2: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0]["content"], "Message 2");
        assert_eq!(page2[1]["content"], "Message 1");
    }

    #[sqlx::test]
    async fn get_messages_returns_bad_request_when_channel_lookup_fails(pool: sqlx::PgPool) {
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        state.db.close().await;

        let Err(response) = get_channel_messages(
            State(state),
            AuthenticatedUser {
                user_id: crate::types::UserId(Uuid::new_v4()),
            },
            Path(Uuid::new_v4()),
            Query(GetMessagesQuery {
                limit: None,
                before: None,
            }),
        )
        .await
        else {
            panic!("expected error response");
        };

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "Internal error");
    }
}
