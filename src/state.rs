use crate::types::{ChannelId, ConnectionId, OutboundTx, Token, UserId};
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

#[derive(Debug, Clone, Copy)]
pub struct Session {
    pub user_id: UserId,
    // later: last_heartbeat, seq, presence, etc.
}

pub struct AppState {
    pub db: PgPool,
    pub auth_secret: Vec<u8>,
    pub connections: DashMap<ConnectionId, OutboundTx>,
    pub auth_tokens: DashMap<Token, UserId>,
    pub sessions: DashMap<ConnectionId, Session>,
    pub channel_members: DashMap<ChannelId, DashSet<ConnectionId>>,
    pub connection_channels: DashMap<ConnectionId, DashSet<ChannelId>>,

    #[cfg(test)]
    pub dispatch_counter: AtomicUsize,
}

impl AppState {
    pub fn new(db: PgPool, auth_secret: Vec<u8>) -> Self {
        Self {
            db,
            auth_secret,
            connections: DashMap::new(),
            auth_tokens: DashMap::new(),
            sessions: DashMap::new(),
            channel_members: DashMap::new(),
            connection_channels: DashMap::new(),

            #[cfg(test)]
            dispatch_counter: AtomicUsize::new(0),
        }
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
pub fn test_auth_secret() -> Vec<u8> {
    "test-secret".as_bytes().to_vec()
}
