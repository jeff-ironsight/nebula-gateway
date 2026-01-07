use std::sync::Arc;

use axum::{Router, routing::get};

use crate::{gateway, state::AppState};

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ws", get(gateway::ws_handler))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn non_ws_route_returns_not_found() {
        let router = build_router(Arc::new(AppState::new()));

        let request = Request::builder()
            .method("GET")
            .uri("/does-not-exist")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
