use crate::data::{ChannelRepository, ServerRepository};
use crate::rest::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::types::{ChannelType, ServerId};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/servers", get(list_servers).post(create_server))
        .route("/servers/{id}", delete(delete_server))
        .route(
            "/servers/{id}/channels",
            get(list_channels).post(create_channel),
        )
}

#[derive(Serialize)]
pub(crate) struct ServerResponse {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) owner_user_id: Option<Uuid>,
    pub(crate) my_role: String,
    pub(crate) channels: Vec<ChannelResponse>,
}

#[derive(Serialize)]
pub(crate) struct ChannelResponse {
    pub(crate) id: Uuid,
    pub(crate) server_id: Uuid,
    pub(crate) name: String,
    pub(crate) channel_type: ChannelType,
}

#[derive(Deserialize)]
struct CreateServerRequest {
    name: String,
}

#[derive(Deserialize)]
struct CreateChannelRequest {
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

async fn list_servers(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<ServerResponse>>, Response> {
    let servers = ServerRepository::new(&state.db);
    let channels = ChannelRepository::new(&state.db);

    let user_servers = servers
        .get_servers_for_user(&user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list servers");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    let mut result = Vec::with_capacity(user_servers.len());
    for server in user_servers {
        let server_channels = channels
            .get_channels_for_server(&server.id)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to list channels for server");
                ApiError {
                    error: "Internal error".to_string(),
                }
                .into_response()
            })?;

        result.push(ServerResponse {
            id: server.id.0,
            name: server.name,
            owner_user_id: server.owner_user_id.map(|u| u.0),
            my_role: server.my_role,
            channels: server_channels
                .into_iter()
                .map(|c| ChannelResponse {
                    id: c.id.0,
                    server_id: c.server_id.0,
                    name: c.name,
                    channel_type: c.channel_type,
                })
                .collect(),
        });
    }

    Ok(Json(result))
}

async fn create_server(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(request): Json<CreateServerRequest>,
) -> Result<Json<ServerResponse>, Response> {
    if request.name.trim().is_empty() {
        return Err(ApiError {
            error: "Server name cannot be empty".to_string(),
        }
        .into_response());
    }

    let servers = ServerRepository::new(&state.db);
    let server_id = servers
        .create_server(&request.name, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create server");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    // Fetch the auto-created channels
    let channel_repo = ChannelRepository::new(&state.db);
    let channels = channel_repo
        .get_channels_for_server(&server_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get channels for new server");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    Ok(Json(ServerResponse {
        id: server_id.0,
        name: request.name,
        owner_user_id: Some(user.user_id.0),
        my_role: "owner".to_string(),
        channels: channels
            .into_iter()
            .map(|c| ChannelResponse {
                id: c.id.0,
                server_id: c.server_id.0,
                name: c.name,
                channel_type: c.channel_type,
            })
            .collect(),
    }))
}

async fn delete_server(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(server_id): Path<Uuid>,
) -> Result<StatusCode, Response> {
    let server_id = ServerId::from(server_id);

    // Verify user is owner of server
    let servers = ServerRepository::new(&state.db);
    let is_owner = servers
        .is_owner(&server_id, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check server ownership");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    if !is_owner {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "Not the owner of this server".to_string(),
            }),
        )
            .into_response());
    }

    servers.delete_server(&server_id).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to delete server");
        ApiError {
            error: "Internal error".to_string(),
        }
        .into_response()
    })?;

    Ok(StatusCode::NO_CONTENT)
}

async fn list_channels(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<ChannelResponse>>, Response> {
    let server_id = ServerId::from(server_id);

    // Verify user is member of server
    let servers = ServerRepository::new(&state.db);
    let is_member = servers
        .is_member(&server_id, &user.user_id)
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

    let channels = ChannelRepository::new(&state.db);
    let server_channels = channels
        .get_channels_for_server(&server_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to list channels");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    Ok(Json(
        server_channels
            .into_iter()
            .map(|c| ChannelResponse {
                id: c.id.0,
                server_id: c.server_id.0,
                name: c.name,
                channel_type: c.channel_type,
            })
            .collect(),
    ))
}

async fn create_channel(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(server_id): Path<Uuid>,
    Json(request): Json<CreateChannelRequest>,
) -> Result<Json<ChannelResponse>, Response> {
    let server_id = ServerId::from(server_id);

    if request.name.trim().is_empty() {
        return Err(ApiError {
            error: "Channel name cannot be empty".to_string(),
        }
        .into_response());
    }

    // Verify user is owner or admin of server
    let servers = ServerRepository::new(&state.db);
    let is_owner_or_admin = servers
        .is_owner_or_admin(&server_id, &user.user_id)
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

    let channels = ChannelRepository::new(&state.db);
    let channel_id = channels
        .create_channel(&server_id, &request.name)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create channel");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    Ok(Json(ChannelResponse {
        id: channel_id.0,
        server_id: server_id.0,
        name: request.name,
        channel_type: ChannelType::Text,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth0::{Auth0Settings, Auth0Verifier};
    use crate::data::{ChannelRepository, UserRepository};
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
    async fn list_servers_returns_default_server_for_new_user() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create a user with unique auth sub
        let auth_sub = format!("auth0|list-default-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let request = Request::builder()
            .method("GET")
            .uri("/servers")
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let servers: Vec<Value> = serde_json::from_slice(&body).unwrap();

        // New users are auto-joined to the default "Nebula" server
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0]["name"], "Nebula");
    }

    #[tokio::test]
    async fn create_server_and_list() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create a user with unique auth sub
        let auth_sub = format!("auth0|create-list-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        // Create a server
        let create_request = Request::builder()
            .method("POST")
            .uri("/servers")
            .header("Authorization", format!("Bearer {}", auth_sub))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"name": "My Server"}"#))
            .unwrap();

        let response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(created["name"], "My Server");
        // Should include the auto-created "general" channel
        let channels = created["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0]["name"], "general");

        // List servers
        let list_request = Request::builder()
            .method("GET")
            .uri("/servers")
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let servers: Vec<Value> = serde_json::from_slice(&body).unwrap();

        // User has default server (auto-joined) + the one they created
        assert_eq!(servers.len(), 2);
        assert!(servers.iter().any(|s| s["name"] == "My Server"));
        assert!(servers.iter().any(|s| s["name"] == "Nebula"));
    }

    #[tokio::test]
    async fn create_server_rejects_empty_name() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|reject-empty-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let request = Request::builder()
            .method("POST")
            .uri("/servers")
            .header("Authorization", format!("Bearer {}", auth_sub))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"name": "  "}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_channels_requires_membership() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create user with unique auth sub
        let auth_sub = format!("auth0|list-channels-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        // Create another user who owns a server
        let other_auth_sub = format!("auth0|other-{}", Uuid::new_v4());
        let other_user_id = users
            .get_or_create_by_auth_sub(&other_auth_sub)
            .await
            .unwrap();
        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Other Server", &other_user_id)
            .await
            .unwrap();

        // Try to list channels - should be forbidden
        let request = Request::builder()
            .method("GET")
            .uri(format!("/servers/{}/channels", server_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_channel_and_list() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create user and server with unique auth sub
        // Note: create_server auto-creates a "general" channel
        let auth_sub = format!("auth0|create-channel-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();
        let servers = ServerRepository::new(&state.db);
        let server_id = servers.create_server("My Server", &_user_id).await.unwrap();

        // Create another channel
        let create_request = Request::builder()
            .method("POST")
            .uri(format!("/servers/{}/channels", server_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"name": "random"}"#))
            .unwrap();

        let response = app.clone().oneshot(create_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(created["name"], "random");

        // List channels - should have "general" (auto-created) + "random"
        let list_request = Request::builder()
            .method("GET")
            .uri(format!("/servers/{}/channels", server_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(list_request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channels: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(channels.len(), 2);
        assert_eq!(channels[0]["name"], "general");
        assert_eq!(channels[1]["name"], "random");
    }

    #[tokio::test]
    async fn unauthenticated_request_returns_401() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state);

        let request = Request::builder()
            .method("GET")
            .uri("/servers")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_channel_rejects_empty_name() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create user and server with unique auth sub
        let auth_sub = format!("auth0|reject-channel-empty-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();
        let servers = ServerRepository::new(&state.db);
        let server_id = servers.create_server("My Server", &_user_id).await.unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/servers/{}/channels", server_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"name": "   "}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_channel_only_for_server_admins_and_owners() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create user and server with unique auth sub
        let auth_sub = format!("auth0|non-admin-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();
        let servers = ServerRepository::new(&state.db);
        let server_id = servers.create_server("My Server", &_user_id).await.unwrap();

        // Create another user who is not an admin or owner
        let other_auth_sub = format!("auth0|other-non-admin-{}", Uuid::new_v4());
        let _other_user_id = users
            .get_or_create_by_auth_sub(&other_auth_sub)
            .await
            .unwrap();

        // Try to create a channel - should be forbidden
        let request = Request::builder()
            .method("POST")
            .uri(format!("/servers/{}/channels", server_id.0))
            .header("Authorization", format!("Bearer {}", other_auth_sub))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"name": "random"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_server_returns_204_for_owner() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let owner_sub = format!("auth0|delete-owner-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers.create_server("Delete Me", &owner_id).await.unwrap();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/servers/{}", server_id.0))
            .header("Authorization", format!("Bearer {}", owner_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_server_returns_403_for_non_owner() {
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
            .create_server("Protected Server", &owner_id)
            .await
            .unwrap();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/servers/{}", server_id.0))
            .header("Authorization", format!("Bearer {}", other_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_channels_returns_channels_for_member() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let owner_sub = format!("auth0|channels-owner-{}", Uuid::new_v4());
        let member_sub = format!("auth0|channels-member-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();
        let member_id = users.get_or_create_by_auth_sub(&member_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Member Server", &owner_id)
            .await
            .unwrap();
        servers
            .add_member(&server_id, &member_id, "member")
            .await
            .unwrap();

        let channels = ChannelRepository::new(&state.db);
        channels.create_channel(&server_id, "random").await.unwrap();

        let request = Request::builder()
            .method("GET")
            .uri(format!("/servers/{}/channels", server_id.0))
            .header("Authorization", format!("Bearer {}", member_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channels: Vec<Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(channels.len(), 2);
        assert!(channels.iter().any(|c| c["name"] == "general"));
        assert!(channels.iter().any(|c| c["name"] == "random"));
    }

    #[tokio::test]
    async fn create_channel_allows_admin() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let owner_sub = format!("auth0|admin-owner-{}", Uuid::new_v4());
        let admin_sub = format!("auth0|admin-user-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();
        let admin_id = users.get_or_create_by_auth_sub(&admin_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Admin Server", &owner_id)
            .await
            .unwrap();
        servers
            .add_member(&server_id, &admin_id, "admin")
            .await
            .unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/servers/{}/channels", server_id.0))
            .header("Authorization", format!("Bearer {}", admin_sub))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"name": "ops"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
