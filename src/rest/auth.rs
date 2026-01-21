use axum::{Json, Router, extract::State, routing::post};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    state::AppState,
    types::{Token, UserId, token_hmac},
};

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub token: Token,
    pub user_id: UserId,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/login", post(login))
}

async fn login(State(state): State<Arc<AppState>>) -> Json<LoginResponse> {
    // MVP: fake user
    let user_id = UserId::from(Uuid::new_v4());
    let token = Token::new();
    let username = format!("user-{}", user_id.0);
    let token_hash = token_hmac(&state.auth_secret, &token);

    let mut tx = state.db.begin().await.expect("begin transaction");
    sqlx::query("insert into users (id, username) values ($1, $2)")
        .bind(user_id.0)
        .bind(username)
        .execute(&mut *tx)
        .await
        .expect("insert user");

    sqlx::query("insert into sessions (token_hash, user_id) values ($1, $2)")
        .bind(token_hash)
        .bind(user_id.0)
        .execute(&mut *tx)
        .await
        .expect("insert session");

    tx.commit().await.expect("commit transaction");

    state.auth_tokens.insert(token.clone(), user_id);

    Json(LoginResponse { token, user_id })
}
