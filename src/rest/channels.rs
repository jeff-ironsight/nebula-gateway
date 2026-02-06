use crate::data::{ChannelRepository, ServerRepository};
use crate::rest::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::types::ChannelId;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/channels/{id}", get(get_channel).delete(delete_channel))
}

#[derive(Serialize)]
struct ChannelResponse {
    id: Uuid,
    server_id: Uuid,
    name: String,
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

async fn get_channel(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(channel_id): Path<Uuid>,
) -> Result<Json<ChannelResponse>, Response> {
    let channel_id = ChannelId::from(channel_id);
    let channels = ChannelRepository::new(&state.db);

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

    Ok(Json(ChannelResponse {
        id: channel.id.0,
        server_id: channel.server_id.0,
        name: channel.name,
    }))
}

async fn delete_channel(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(channel_id): Path<Uuid>,
) -> Result<StatusCode, Response> {
    let channel_id = ChannelId::from(channel_id);
    let channels = ChannelRepository::new(&state.db);

    let channel = channels
        .get_by_id(&channel_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get channel for deletion");
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

    // Verify user is owner or admin of the channel's server
    let servers = ServerRepository::new(&state.db);
    let is_owner_or_admin = servers
        .is_owner_or_admin(&channel.server_id, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check server membership");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    if !is_owner_or_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "Not an owner or admin of this server".to_string(),
            }),
        )
            .into_response());
    }

    channels.delete_channel(&channel_id).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to delete channel");
        ApiError {
            error: "Internal error".to_string(),
        }
        .into_response()
    })?;

    Ok(StatusCode::NO_CONTENT)
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
    async fn get_channel_returns_channel_for_member() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create user and server
        let auth_sub = format!("auth0|get-channel-{}", Uuid::new_v4());
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

        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}", channel_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(channel["name"], "test-channel");
        assert_eq!(channel["server_id"], server_id.0.to_string());
    }

    #[tokio::test]
    async fn get_channel_returns_404_for_nonexistent() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|get-404-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let fake_channel_id = Uuid::new_v4();
        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}", fake_channel_id))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "Channel not found");
    }

    #[tokio::test]
    async fn get_channel_returns_403_for_non_member() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create requesting user (not a member of any server)
        let auth_sub = format!("auth0|get-403-{}", Uuid::new_v4());
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

        // Request as non-member
        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}", channel_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "Not a member of this server");
    }

    #[tokio::test]
    async fn get_channel_returns_401_for_unauthenticated() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state);

        let request = Request::builder()
            .method("GET")
            .uri(format!("/channels/{}", Uuid::new_v4()))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn delete_channel_returns_204_for_owner() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let owner_sub = format!("auth0|delete-owner-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Delete Server", &owner_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "to-delete")
            .await
            .unwrap();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/channels/{}", channel_id.0))
            .header("Authorization", format!("Bearer {}", owner_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let deleted = channels.get_by_id(&channel_id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn delete_channel_returns_403_for_non_admin() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let owner_sub = format!("auth0|delete-owner-{}", Uuid::new_v4());
        let other_sub = format!("auth0|delete-other-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();
        let _other_id = users.get_or_create_by_auth_sub(&other_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Delete Server", &owner_id)
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        let channel_id = channels
            .create_channel(&server_id, "keep-me")
            .await
            .unwrap();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/channels/{}", channel_id.0))
            .header("Authorization", format!("Bearer {}", other_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let still_there = channels.get_by_id(&channel_id).await.unwrap();
        assert!(still_there.is_some());
    }

    #[tokio::test]
    async fn delete_channel_returns_404_for_missing() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|delete-missing-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/channels/{}", Uuid::new_v4()))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_channel_returns_401_for_unauthenticated() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state);

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/channels/{}", Uuid::new_v4()))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
