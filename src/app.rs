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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[sqlx::test]
    async fn non_route_returns_not_found(pool: sqlx::PgPool) {
        let router = build_router(Arc::new(AppState::new(pool, None)));
        let request = Request::builder()
            .method("GET")
            .uri("/does-not-exist")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
