use crate::data::UserRepository;
use crate::state::AppState;
use crate::types::UserId;
use axum::Json;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use std::sync::Arc;

/// Extracts and validates the authenticated user from the Authorization header.
/// Returns 401 if the token is missing or invalid.
pub struct AuthenticatedUser {
    pub user_id: UserId,
}

#[derive(Debug, Serialize)]
struct AuthError {
    error: String,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
    }
}

impl FromRequestParts<Arc<AppState>> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_bearer_token(&parts.headers).ok_or_else(|| {
            AuthError {
                error: "Missing or invalid Authorization header".to_string(),
            }
            .into_response()
        })?;

        let auth0 = state.auth0.as_ref().ok_or_else(|| {
            AuthError {
                error: "Auth not configured".to_string(),
            }
            .into_response()
        })?;

        let claims = auth0.verify(token).await.map_err(|e| {
            AuthError {
                error: format!("Token verification failed: {:?}", e),
            }
            .into_response()
        })?;

        let users = UserRepository::new(&state.db);
        let user_id = users
            .get_or_create_by_auth_sub(&claims.sub)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get/create user from auth sub");
                AuthError {
                    error: "Internal error".to_string(),
                }
                .into_response()
            })?;

        Ok(AuthenticatedUser { user_id })
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth0::{Auth0Settings, Auth0Verifier};
    use crate::state::test_db;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, Request, StatusCode};
    use axum::routing::get;
    use serde_json::Value;
    use std::time::Duration;
    use tower::ServiceExt;
    use uuid::Uuid;

    fn test_auth0() -> Auth0Verifier {
        Auth0Verifier::new_test(Auth0Settings {
            issuer: "https://test-issuer/".into(),
            audience: "test-audience".into(),
            jwks_url: "https://example.invalid/.well-known/jwks.json".into(),
            jwks_cache_ttl: Duration::from_secs(60),
        })
    }

    // Simple handler that requires authentication
    async fn protected_handler(user: AuthenticatedUser) -> Json<serde_json::Value> {
        Json(serde_json::json!({ "user_id": user.user_id.0.to_string() }))
    }

    fn test_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/protected", get(protected_handler))
            .with_state(state)
    }

    #[test]
    fn extract_bearer_token_returns_token() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer my-token".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("my-token"));
    }

    #[test]
    fn extract_bearer_token_returns_none_for_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_returns_none_for_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic abc123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_returns_none_for_empty_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer ".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some(""));
    }

    #[tokio::test]
    async fn authenticated_user_returns_401_without_auth_header() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "Missing or invalid Authorization header");
    }

    #[tokio::test]
    async fn authenticated_user_returns_401_without_auth0_configured() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, None)); // No auth0
        let app = test_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("Authorization", "Bearer some-token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"], "Auth not configured");
    }

    #[tokio::test]
    async fn authenticated_user_creates_user_on_first_auth() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));
        let app = test_router(state.clone());

        let auth_sub = format!("auth0|new-user-{}", Uuid::new_v4());

        let request = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: Value = serde_json::from_slice(&body).unwrap();

        // Should return a valid UUID
        let user_id_str = result["user_id"].as_str().unwrap();
        assert!(Uuid::parse_str(user_id_str).is_ok());
    }

    #[tokio::test]
    async fn authenticated_user_returns_same_user_on_subsequent_auth() {
        let pool = test_db().await;
        let state = Arc::new(AppState::new(pool, Some(test_auth0())));

        let auth_sub = format!("auth0|repeat-user-{}", Uuid::new_v4());

        // First request
        let app1 = test_router(state.clone());
        let request1 = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response1 = app1.oneshot(request1).await.unwrap();
        let body1 = axum::body::to_bytes(response1.into_body(), usize::MAX)
            .await
            .unwrap();
        let result1: Value = serde_json::from_slice(&body1).unwrap();

        // Second request with same token
        let app2 = test_router(state);
        let request2 = Request::builder()
            .method("GET")
            .uri("/protected")
            .header("Authorization", format!("Bearer {}", auth_sub))
            .body(Body::empty())
            .unwrap();

        let response2 = app2.oneshot(request2).await.unwrap();
        let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
            .await
            .unwrap();
        let result2: Value = serde_json::from_slice(&body2).unwrap();

        // Should return the same user_id
        assert_eq!(result1["user_id"], result2["user_id"]);
    }
}
