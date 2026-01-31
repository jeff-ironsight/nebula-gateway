use crate::types::{ServerId, UserId};
use sqlx::PgPool;
use uuid::Uuid;

/// Well-known UUID for the global default server
pub const DEFAULT_SERVER_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);

pub struct Server {
    pub id: ServerId,
    pub name: String,
    pub owner_user_id: Option<UserId>,
}

pub struct ServerRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> ServerRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_servers_for_user(&self, user_id: &UserId) -> Result<Vec<Server>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
            r#"
            select s.id, s.name, s.owner_user_id
            from servers s
            join server_members sm on sm.server_id = s.id
            where sm.user_id = $1
            order by s.name
            "#,
        )
        .bind(user_id.0)
        .fetch_all(self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, name, owner_user_id)| Server {
                id: ServerId::from(id),
                name,
                owner_user_id: owner_user_id.map(UserId::from),
            })
            .collect())
    }

    pub async fn create_server(
        &self,
        name: &str,
        owner_user_id: &UserId,
    ) -> Result<ServerId, sqlx::Error> {
        let server_id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            "insert into servers (id, name, owner_user_id) values ($1, $2, $3)",
            server_id,
            name,
            owner_user_id.0
        )
        .execute(&mut *tx)
        .await?;

        // Owner is automatically a member with 'owner' role
        sqlx::query!(
            "insert into server_members (server_id, user_id, role) values ($1, $2, 'owner')",
            server_id,
            owner_user_id.0
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(ServerId::from(server_id))
    }

    pub async fn add_member(
        &self,
        server_id: &ServerId,
        user_id: &UserId,
        role: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            insert into server_members (server_id, user_id, role)
            values ($1, $2, $3)
            on conflict (server_id, user_id) do nothing
            "#,
            server_id.0,
            user_id.0,
            role
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn is_member(
        &self,
        server_id: &ServerId,
        user_id: &UserId,
    ) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from server_members where server_id = $1 and user_id = $2)",
        )
        .bind(server_id.0)
        .bind(user_id.0)
        .fetch_one(self.pool)
        .await?;
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::UserRepository;
    use crate::state::test_db;

    #[tokio::test]
    async fn create_server_adds_owner_as_member() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|server-test")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .expect("create server");

        let is_member = servers
            .is_member(&server_id, &user_id)
            .await
            .expect("check membership");

        assert!(is_member);
    }

    #[tokio::test]
    async fn get_servers_for_user_returns_member_servers() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|list-servers-test")
            .await
            .expect("create user");

        servers
            .create_server("My Server", &user_id)
            .await
            .expect("create server");

        let user_servers = servers
            .get_servers_for_user(&user_id)
            .await
            .expect("get servers");

        assert_eq!(user_servers.len(), 1);
        assert_eq!(user_servers[0].name, "My Server");
    }
}
