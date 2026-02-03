use crate::data::{InviteRepository, ServerRepository};
use crate::gateway::handler::dispatch_member_join_to_server;
use crate::rest::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::types::ServerId;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/servers/{id}/invites", post(create_invite))
        .route("/invites/{code}", get(preview_invite).delete(revoke_invite))
        .route("/invites/{code}/use", post(use_invite))
}

#[derive(Deserialize)]
struct CreateInviteRequest {
    max_uses: Option<i32>,
    expires_in_hours: Option<i64>,
}

#[derive(Serialize)]
struct InviteResponse {
    code: String,
    server_id: Uuid,
    max_uses: Option<i32>,
    use_count: i32,
    expires_at: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
struct InvitePreviewResponse {
    code: String,
    server_id: Uuid,
    server_name: String,
    member_count: i64,
}

#[derive(Serialize)]
struct UseInviteResponse {
    server_id: Uuid,
    already_member: bool,
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

async fn create_invite(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(server_id): Path<Uuid>,
    Json(request): Json<CreateInviteRequest>,
) -> Result<Json<InviteResponse>, Response> {
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

    let expires_at = request
        .expires_in_hours
        .map(|hours| Utc::now() + Duration::hours(hours));

    let invites = InviteRepository::new(&state.db);
    let invite = invites
        .create(&server_id, &user.user_id, request.max_uses, expires_at)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create invite");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    Ok(Json(InviteResponse {
        code: invite.code.0,
        server_id: invite.server_id.0,
        max_uses: invite.max_uses,
        use_count: invite.use_count,
        expires_at: invite.expires_at.map(|t| t.to_rfc3339()),
        created_at: invite.created_at.to_rfc3339(),
    }))
}

async fn preview_invite(
    State(state): State<Arc<AppState>>,
    Path(code): Path<String>,
) -> Result<Json<InvitePreviewResponse>, Response> {
    let invites = InviteRepository::new(&state.db);
    let preview = invites.get_preview(&code).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to get invite preview");
        ApiError {
            error: "Internal error".to_string(),
        }
        .into_response()
    })?;

    let Some(preview) = preview else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "Invite not found or expired".to_string(),
            }),
        )
            .into_response());
    };

    Ok(Json(InvitePreviewResponse {
        code: preview.code.0,
        server_id: preview.server_id.0,
        server_name: preview.server_name,
        member_count: preview.member_count,
    }))
}

async fn use_invite(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(code): Path<String>,
) -> Result<Json<UseInviteResponse>, Response> {
    let invites = InviteRepository::new(&state.db);
    let servers = ServerRepository::new(&state.db);

    let server_id = invites.get_server_id_for_invite(&code).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to get server for invite");
        ApiError {
            error: "Internal error".to_string(),
        }
        .into_response()
    })?;

    let Some(server_id) = server_id else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "Invite not found".to_string(),
            }),
        )
            .into_response());
    };

    let was_already_member = servers
        .is_member(&server_id, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check membership");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    let result = invites
        .use_invite(&code, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to use invite");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    let Some(joined_server_id) = result else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "Invite is invalid, expired, or has reached max uses".to_string(),
            }),
        )
            .into_response());
    };

    // Dispatch MEMBER_JOIN event if this is a new member
    if !was_already_member {
        dispatch_member_join_to_server(&state, &joined_server_id, &user.user_id).await;
    }

    Ok(Json(UseInviteResponse {
        server_id: joined_server_id.0,
        already_member: was_already_member,
    }))
}

async fn revoke_invite(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(code): Path<String>,
) -> Result<StatusCode, Response> {
    let invites = InviteRepository::new(&state.db);
    let servers = ServerRepository::new(&state.db);

    // Get the server for this invite to check permissions
    let server_id = invites.get_server_id_for_invite(&code).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to get server for invite");
        ApiError {
            error: "Internal error".to_string(),
        }
        .into_response()
    })?;

    let Some(server_id) = server_id else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "Invite not found".to_string(),
            }),
        )
            .into_response());
    };

    // User must be the creator OR an admin/owner of the server
    let is_creator = invites
        .is_creator(&code, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check invite creator");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    let is_admin = servers
        .is_owner_or_admin(&server_id, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check server admin status");
            ApiError {
                error: "Internal error".to_string(),
            }
            .into_response()
        })?;

    if !is_creator && !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiError {
                error: "Only the invite creator or server admins can revoke invites".to_string(),
            }),
        )
            .into_response());
    }

    invites.delete(&code).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to delete invite");
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
    use axum::http::Request;
    use serde_json::Value;
    use std::time::Duration as StdDuration;
    use tower::ServiceExt;

    fn test_auth0() -> Auth0Verifier {
        Auth0Verifier::new_test(Auth0Settings {
            issuer: "https://test-issuer/".into(),
            audience: "test-audience".into(),
            jwks_url: "https://example.invalid/.well-known/jwks.json".into(),
            jwks_cache_ttl: StdDuration::from_secs(60),
        })
    }

    #[tokio::test]
    async fn create_invite_requires_membership() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        // Create two users
        let auth_sub = format!("auth0|invite-non-member-{}", Uuid::new_v4());
        let owner_sub = format!("auth0|invite-owner-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let _user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();

        // Owner creates a server
        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Private Server", &owner_id)
            .await
            .unwrap();

        // Non-member tries to create invite
        let request = Request::builder()
            .method("POST")
            .uri(format!("/servers/{}/invites", server_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .header("Content-Type", "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_invite_returns_code() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|invite-creator-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers.create_server("My Server", &user_id).await.unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/servers/{}/invites", server_id.0))
            .header("Authorization", format!("Bearer {}", auth_sub))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"max_uses": 5}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let invite: Value = serde_json::from_slice(&body).unwrap();

        assert!(invite["code"].as_str().unwrap().len() == 8);
        assert_eq!(invite["max_uses"], 5);
        assert_eq!(invite["use_count"], 0);
    }

    #[tokio::test]
    async fn preview_invite_is_public() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let auth_sub = format!("auth0|preview-test-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let user_id = users.get_or_create_by_auth_sub(&auth_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Preview Server", &user_id)
            .await
            .unwrap();

        let invites = InviteRepository::new(&state.db);
        let invite = invites
            .create(&server_id, &user_id, None, None)
            .await
            .unwrap();

        // Preview without auth
        let request = Request::builder()
            .method("GET")
            .uri(format!("/invites/{}", invite.code.0))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let preview: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(preview["server_name"], "Preview Server");
        assert_eq!(preview["member_count"], 1);
    }

    #[tokio::test]
    async fn use_invite_adds_user_to_server() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let owner_sub = format!("auth0|use-owner-{}", Uuid::new_v4());
        let joiner_sub = format!("auth0|use-joiner-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();
        let joiner_id = users.get_or_create_by_auth_sub(&joiner_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Join Server", &owner_id)
            .await
            .unwrap();

        let invites = InviteRepository::new(&state.db);
        let invite = invites
            .create(&server_id, &owner_id, None, None)
            .await
            .unwrap();

        // Joiner uses invite
        let request = Request::builder()
            .method("POST")
            .uri(format!("/invites/{}/use", invite.code.0))
            .header("Authorization", format!("Bearer {}", joiner_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(result["already_member"], false);

        // Verify membership
        let is_member = servers.is_member(&server_id, &joiner_id).await.unwrap();
        assert!(is_member);
    }

    #[tokio::test]
    async fn revoke_invite_requires_creator_or_admin() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = router().with_state(state.clone());

        let owner_sub = format!("auth0|revoke-owner-{}", Uuid::new_v4());
        let other_sub = format!("auth0|revoke-other-{}", Uuid::new_v4());
        let users = UserRepository::new(&state.db);
        let owner_id = users.get_or_create_by_auth_sub(&owner_sub).await.unwrap();
        let _other_id = users.get_or_create_by_auth_sub(&other_sub).await.unwrap();

        let servers = ServerRepository::new(&state.db);
        let server_id = servers
            .create_server("Revoke Server", &owner_id)
            .await
            .unwrap();

        let invites = InviteRepository::new(&state.db);
        let invite = invites
            .create(&server_id, &owner_id, None, None)
            .await
            .unwrap();

        // Non-creator/non-admin tries to revoke
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/invites/{}", invite.code.0))
            .header("Authorization", format!("Bearer {}", other_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Owner can revoke
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/invites/{}", invite.code.0))
            .header("Authorization", format!("Bearer {}", owner_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
