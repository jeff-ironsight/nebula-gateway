use crate::auth0::Auth0Verifier;
use crate::types::{ChannelId, ConnectionId, OutboundTx, UserId};
use dashmap::{DashMap, DashSet};
use sqlx::PgPool;
#[cfg(test)]
use sqlx::postgres::PgPoolOptions;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
use std::time::Duration;
#[cfg(test)]
use testcontainers_modules::postgres::Postgres;
#[cfg(test)]
use testcontainers_modules::testcontainers::{ContainerAsync, runners::AsyncRunner};
#[cfg(test)]
use tokio::sync::OnceCell;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub user_id: UserId,
    // later: last_heartbeat, seq, presence, etc.
}

pub struct AppState {
    pub db: PgPool,
    pub connections: DashMap<ConnectionId, OutboundTx>,
    pub sessions: DashMap<ConnectionId, Session>,
    pub channel_members: DashMap<ChannelId, DashSet<ConnectionId>>,
    pub connection_channels: DashMap<ConnectionId, DashSet<ChannelId>>,
    pub auth0: Option<Auth0Verifier>,

    #[cfg(test)]
    pub dispatch_counter: AtomicUsize,
}

impl AppState {
    pub fn new(db: PgPool, auth0: Option<Auth0Verifier>) -> Self {
        Self {
            db,
            connections: DashMap::new(),
            sessions: DashMap::new(),
            channel_members: DashMap::new(),
            connection_channels: DashMap::new(),
            auth0,

            #[cfg(test)]
            dispatch_counter: AtomicUsize::new(0),
        }
    }

    pub async fn get_or_create_user_by_auth_sub(&self, sub: &str) -> Result<UserId, sqlx::Error> {
        let mut tx = self.db.begin().await?;

        if let Some(user_id) =
            sqlx::query_scalar::<_, Uuid>("select id from users where auth_sub = $1")
                .bind(sub)
                .fetch_optional(&mut *tx)
                .await?
        {
            tx.commit().await?;
            return Ok(UserId::from(user_id));
        }

        let user_id = Uuid::new_v4();
        sqlx::query!(
            "insert into users (id, username, auth_sub) values ($1, $2, $3)",
            user_id,
            Option::<String>::None,
            sub
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(UserId::from(user_id))
    }

    pub async fn get_username_by_user_id(
        &self,
        user_id: &UserId,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar::<_, Option<String>>("select username from users where id = $1")
            .bind(user_id.0)
            .fetch_optional(&self.db)
            .await
            .map(|value| value.flatten())
    }
}

#[cfg(test)]
struct TestDb {
    url: String,
    _container: ContainerAsync<Postgres>,
}

#[cfg(test)]
async fn test_db_container() -> &'static TestDb {
    static DB: OnceCell<TestDb> = OnceCell::const_new();

    DB.get_or_init(|| async {
        let container = Postgres::default()
            .start()
            .await
            .expect("start postgres container");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("resolve postgres port");
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
        TestDb {
            url,
            _container: container,
        }
    })
    .await
}

#[cfg(test)]
pub async fn test_db() -> PgPool {
    let db = test_db_container().await;
    let pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db.url)
        .await
        .expect("connect test database");
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("run test migrations");
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_or_create_user_by_auth_sub_is_idempotent() {
        let state = AppState::new(test_db().await, None);
        let first = state
            .get_or_create_user_by_auth_sub("auth0|abc123")
            .await
            .expect("create user");
        let second = state
            .get_or_create_user_by_auth_sub("auth0|abc123")
            .await
            .expect("fetch user");

        assert_eq!(first.0, second.0);
    }

    #[tokio::test]
    async fn get_username_by_user_id_returns_none_for_missing_username() {
        let state = AppState::new(test_db().await, None);
        let user_id = state
            .get_or_create_user_by_auth_sub("auth0|no-username")
            .await
            .expect("create user");

        let username = state
            .get_username_by_user_id(&user_id)
            .await
            .expect("fetch username");

        assert!(username.is_none());
    }
}
