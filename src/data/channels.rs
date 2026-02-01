use crate::types::{ChannelId, ServerId};
use sqlx::PgPool;
use uuid::Uuid;

/// Well-known UUID for the default "general" channel
pub const DEFAULT_CHANNEL_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);

pub struct Channel {
    pub id: ChannelId,
    pub server_id: ServerId,
    pub name: String,
}

pub struct ChannelRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> ChannelRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_channels_for_server(
        &self,
        server_id: &ServerId,
    ) -> Result<Vec<Channel>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            r#"
            select id, server_id, name
            from channels
            where server_id = $1
            order by name
            "#,
        )
        .bind(server_id.0)
        .fetch_all(self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, server_id, name)| Channel {
                id: ChannelId::from(id),
                server_id: ServerId::from(server_id),
                name,
            })
            .collect())
    }

    pub async fn create_channel(
        &self,
        server_id: &ServerId,
        name: &str,
    ) -> Result<ChannelId, sqlx::Error> {
        let channel_id = Uuid::new_v4();
        sqlx::query!(
            "insert into channels (id, server_id, name) values ($1, $2, $3)",
            channel_id,
            server_id.0,
            name
        )
        .execute(self.pool)
        .await?;
        Ok(ChannelId::from(channel_id))
    }

    pub async fn get_by_id(&self, channel_id: &ChannelId) -> Result<Option<Channel>, sqlx::Error> {
        let row = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            "select id, server_id, name from channels where id = $1",
        )
        .bind(channel_id.0)
        .fetch_optional(self.pool)
        .await?;

        Ok(row.map(|(id, server_id, name)| Channel {
            id: ChannelId::from(id),
            server_id: ServerId::from(server_id),
            name,
        }))
    }

    pub async fn get_channels_for_user(
        &self,
        user_id: &crate::types::UserId,
    ) -> Result<Vec<Channel>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (Uuid, Uuid, String)>(
            r#"
            select c.id, c.server_id, c.name
            from channels c
            join server_members sm on sm.server_id = c.server_id
            where sm.user_id = $1
            order by c.name
            "#,
        )
        .bind(user_id.0)
        .fetch_all(self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, server_id, name)| Channel {
                id: ChannelId::from(id),
                server_id: ServerId::from(server_id),
                name,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{ServerRepository, UserRepository};
    use crate::state::test_db;

    #[tokio::test]
    async fn create_and_get_channel() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let channels = ChannelRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|channel-test")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .expect("create server");

        let channel_id = channels
            .create_channel(&server_id, "test-channel")
            .await
            .expect("create channel");

        let channel = channels
            .get_by_id(&channel_id)
            .await
            .expect("get channel")
            .expect("channel exists");

        assert_eq!(channel.name, "test-channel");
        assert_eq!(channel.server_id, server_id);
    }

    #[tokio::test]
    async fn get_channels_for_server() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let channels = ChannelRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|channels-list-test")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .expect("create server");

        channels
            .create_channel(&server_id, "general")
            .await
            .expect("create channel");
        channels
            .create_channel(&server_id, "random")
            .await
            .expect("create channel");

        let server_channels = channels
            .get_channels_for_server(&server_id)
            .await
            .expect("get channels");

        assert_eq!(server_channels.len(), 2);
        assert_eq!(server_channels[0].name, "general");
        assert_eq!(server_channels[1].name, "random");
    }
}
