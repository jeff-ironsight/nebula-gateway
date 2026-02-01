use crate::types::{DEFAULT_SERVER_ID, UserId};
use sqlx::PgPool;
use uuid::Uuid;

pub struct UserRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> UserRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_or_create_by_auth_sub(&self, sub: &str) -> Result<UserId, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

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

        // Auto-join new users to the default server
        sqlx::query!(
            "insert into server_members (server_id, user_id, role) values ($1, $2, 'member')",
            DEFAULT_SERVER_ID.0,
            user_id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(UserId::from(user_id))
    }

    pub async fn get_username_by_id(
        &self,
        user_id: &UserId,
    ) -> Result<Option<String>, sqlx::Error> {
        sqlx::query_scalar::<_, Option<String>>("select username from users where id = $1")
            .bind(user_id.0)
            .fetch_optional(self.pool)
            .await
            .map(|value| value.flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::ServerRepository;
    use crate::state::test_db;

    #[tokio::test]
    async fn get_or_create_by_auth_sub_is_idempotent() {
        let pool = test_db().await;
        let repo = UserRepository::new(&pool);

        let first = repo
            .get_or_create_by_auth_sub("auth0|abc123")
            .await
            .expect("create user");
        let second = repo
            .get_or_create_by_auth_sub("auth0|abc123")
            .await
            .expect("fetch user");

        assert_eq!(first.0, second.0);
    }

    #[tokio::test]
    async fn get_username_by_id_returns_none_for_missing_username() {
        let pool = test_db().await;
        let repo = UserRepository::new(&pool);

        let user_id = repo
            .get_or_create_by_auth_sub("auth0|no-username")
            .await
            .expect("create user");

        let username = repo
            .get_username_by_id(&user_id)
            .await
            .expect("fetch username");

        assert!(username.is_none());
    }

    #[tokio::test]
    async fn new_user_is_auto_joined_to_default_server() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|auto-join-test")
            .await
            .expect("create user");

        // User should be a member of the default server
        let is_member = servers
            .is_member(&DEFAULT_SERVER_ID, &user_id)
            .await
            .expect("check membership");

        assert!(is_member);
    }

    #[tokio::test]
    async fn new_user_sees_default_server_in_server_list() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|server-list-test")
            .await
            .expect("create user");

        let user_servers = servers
            .get_servers_for_user(&user_id)
            .await
            .expect("get servers");

        assert!(!user_servers.is_empty());
        assert!(user_servers.iter().any(|s| s.id == DEFAULT_SERVER_ID));
        assert!(user_servers.iter().any(|s| s.name == "Nebula"));
    }
}
