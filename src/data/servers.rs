use crate::types::{ServerId, UserId};
use sqlx::PgPool;
use uuid::Uuid;

pub struct Server {
    pub id: ServerId,
    pub name: String,
    pub owner_user_id: Option<UserId>,
    pub my_role: String,
}

pub struct ServerRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> ServerRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_servers_for_user(&self, user_id: &UserId) -> Result<Vec<Server>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (Uuid, String, Option<Uuid>, String)>(
            r#"
            select s.id, s.name, s.owner_user_id, sm.role
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
            .map(|(id, name, owner_user_id, my_role)| Server {
                id: ServerId::from(id),
                name,
                owner_user_id: owner_user_id.map(UserId::from),
                my_role,
            })
            .collect())
    }

    pub async fn get_server_for_user(
        &self,
        server_id: &ServerId,
        user_id: &UserId,
    ) -> Result<Option<Server>, sqlx::Error> {
        let row = sqlx::query_as::<_, (Uuid, String, Option<Uuid>, String)>(
            r#"
            select s.id, s.name, s.owner_user_id, sm.role
            from servers s
            join server_members sm on sm.server_id = s.id
            where sm.user_id = $1 and s.id = $2
            "#,
        )
        .bind(user_id.0)
        .bind(server_id.0)
        .fetch_optional(self.pool)
        .await?;

        Ok(row.map(|(id, name, owner_user_id, my_role)| Server {
            id: ServerId::from(id),
            name,
            owner_user_id: owner_user_id.map(UserId::from),
            my_role,
        }))
    }

    pub async fn create_server(
        &self,
        name: &str,
        owner_user_id: &UserId,
    ) -> Result<ServerId, sqlx::Error> {
        let server_id = Uuid::new_v4();
        let channel_id = Uuid::new_v4();
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

        // Create default "general" channel
        sqlx::query("insert into channels (id, server_id, name) values ($1, $2, 'general')")
            .bind(channel_id)
            .bind(server_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(ServerId::from(server_id))
    }

    pub async fn delete_server(&self, server_id: &ServerId) -> Result<(), sqlx::Error> {
        sqlx::query!("delete from servers where id = $1", server_id.0)
            .execute(self.pool)
            .await?;
        Ok(())
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

    pub async fn is_owner_or_admin(
        &self,
        server_id: &ServerId,
        user_id: &UserId,
    ) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from server_members where server_id = $1 and user_id = $2 and role in ('owner', 'admin'))",
        )
            .bind(server_id.0)
            .bind(user_id.0)
            .fetch_one(self.pool)
            .await?;
        Ok(exists)
    }

    pub async fn is_owner(
        &self,
        server_id: &ServerId,
        user_id: &UserId,
    ) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from server_members where server_id = $1 and user_id = $2 and role = 'owner')",
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
    use crate::data::{ChannelRepository, UserRepository};
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
    async fn create_server_creates_general_channel() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let channels = ChannelRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|server-channel-test")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .expect("create server");

        let server_channels = channels
            .get_channels_for_server(&server_id)
            .await
            .expect("get channels");

        assert_eq!(server_channels.len(), 1);
        assert_eq!(server_channels[0].name, "general");
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

        // User has default server (auto-joined) + the one they created
        assert_eq!(user_servers.len(), 2);
        assert!(user_servers.iter().any(|s| s.name == "My Server"));
        assert!(user_servers.iter().any(|s| s.name == "Nebula"));
    }

    #[tokio::test]
    async fn get_server_for_user_returns_only_member_server() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|get-server-owner")
            .await
            .expect("create user");
        let member_id = users
            .get_or_create_by_auth_sub("auth0|get-server-member")
            .await
            .expect("create user");
        let other_id = users
            .get_or_create_by_auth_sub("auth0|get-server-other")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Target Server", &owner_id)
            .await
            .expect("create server");

        servers
            .add_member(&server_id, &member_id, "member")
            .await
            .expect("add member");

        let member_server = servers
            .get_server_for_user(&server_id, &member_id)
            .await
            .expect("get server");
        assert!(member_server.is_some());

        let non_member = servers
            .get_server_for_user(&server_id, &other_id)
            .await
            .expect("get server");
        assert!(non_member.is_none());
    }

    #[tokio::test]
    async fn add_member_is_idempotent() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|add-member-owner")
            .await
            .expect("create user");
        let member_id = users
            .get_or_create_by_auth_sub("auth0|add-member-user")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Add Member Server", &owner_id)
            .await
            .expect("create server");

        servers
            .add_member(&server_id, &member_id, "member")
            .await
            .expect("add member");
        servers
            .add_member(&server_id, &member_id, "member")
            .await
            .expect("add member again");

        let is_member = servers
            .is_member(&server_id, &member_id)
            .await
            .expect("check membership");
        assert!(is_member);
    }

    #[tokio::test]
    async fn is_owner_or_admin_and_is_owner_work() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|owner-check")
            .await
            .expect("create user");
        let admin_id = users
            .get_or_create_by_auth_sub("auth0|admin-check")
            .await
            .expect("create user");
        let member_id = users
            .get_or_create_by_auth_sub("auth0|member-check")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Role Server", &owner_id)
            .await
            .expect("create server");

        servers
            .add_member(&server_id, &admin_id, "admin")
            .await
            .expect("add admin");
        servers
            .add_member(&server_id, &member_id, "member")
            .await
            .expect("add member");

        assert!(
            servers
                .is_owner_or_admin(&server_id, &owner_id)
                .await
                .expect("owner or admin")
        );
        assert!(
            servers
                .is_owner_or_admin(&server_id, &admin_id)
                .await
                .expect("owner or admin")
        );
        assert!(
            !servers
                .is_owner_or_admin(&server_id, &member_id)
                .await
                .expect("owner or admin")
        );

        assert!(
            servers
                .is_owner(&server_id, &owner_id)
                .await
                .expect("owner")
        );
        assert!(
            !servers
                .is_owner(&server_id, &admin_id)
                .await
                .expect("owner")
        );
    }

    #[tokio::test]
    async fn delete_server_removes_server() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|delete-server")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Delete Server", &owner_id)
            .await
            .expect("create server");

        servers
            .delete_server(&server_id)
            .await
            .expect("delete server");

        let remaining = servers
            .get_servers_for_user(&owner_id)
            .await
            .expect("get servers");

        assert!(!remaining.iter().any(|s| s.id == server_id));
    }
}
