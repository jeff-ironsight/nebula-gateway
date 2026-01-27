use crate::state::AppState;
use axum::{Router, extract::State, http::StatusCode, routing::get};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/healthz", get(healthz))
}

async fn healthz(State(state): State<Arc<AppState>>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::state::test_db;

    #[tokio::test]
    async fn healthz_returns_ok_when_db_is_up() {
        let state = Arc::new(AppState::new(test_db().await, None));
        let app = router().with_state(state);
        let request = Request::builder()
            .method("GET")
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.expect("healthz response");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
