use crate::{gateway, rest, state::AppState};
use axum::{Router, routing::get};
use std::sync::Arc;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ws", get(gateway::ws_handler))
        .nest("/api", rest::router())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        body::to_bytes,
        http::{Request, StatusCode},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::Value;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::{
        state::{test_auth_secret, test_db},
        types::Token,
    };

    #[tokio::test]
    async fn non_route_returns_not_found() {
        let router = build_router(Arc::new(AppState::new(test_db().await, test_auth_secret())));
        let request = Request::builder()
            .method("GET")
            .uri("/does-not-exist")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn login_creates_token_and_persists_state() {
        let state = Arc::new(AppState::new(test_db().await, test_auth_secret()));
        let router = build_router(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/api/login")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let token = payload
            .get("token")
            .and_then(|value| value.as_str())
            .expect("token missing");
        let user_id = payload
            .get("user_id")
            .and_then(|value| value.as_str())
            .expect("user_id missing");

        let token_bytes = URL_SAFE_NO_PAD.decode(token).expect("token base64url");
        assert_eq!(token_bytes.len(), 32);
        let user_uuid = Uuid::parse_str(user_id).expect("user_id uuid");
        assert!(state.auth_tokens.contains_key(&Token(token.to_string())));
        let stored_user_id = state
            .auth_tokens
            .get(&Token(token.to_string()))
            .map(|entry| entry.value().0)
            .expect("token stored");
        assert_eq!(stored_user_id, user_uuid);
    }
}
