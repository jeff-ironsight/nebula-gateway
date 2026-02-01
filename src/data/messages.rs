use crate::types::{ChannelId, UserId};
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub struct MessageRow {
    pub id: String,
    pub channel_id: ChannelId,
    pub author_user_id: UserId,
    pub author_username: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

pub struct MessageRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> MessageRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        id: &str,
        channel_id: &ChannelId,
        author_user_id: &UserId,
        content: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            insert into messages (id, channel_id, author_user_id, content)
            values ($1, $2, $3, $4)
            "#,
            id,
            channel_id.0,
            author_user_id.0,
            content
        )
        .execute(self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_by_channel(
        &self,
        channel_id: &ChannelId,
        limit: i64,
        before: Option<&str>,
    ) -> Result<Vec<MessageRow>, sqlx::Error> {
        let rows = match before {
            Some(before_id) => {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        uuid::Uuid,
                        uuid::Uuid,
                        Option<String>,
                        String,
                        DateTime<Utc>,
                    ),
                >(
                    r#"
                    select m.id, m.channel_id, m.author_user_id, u.username, m.content, m.created_at
                    from messages m
                    join users u on u.id = m.author_user_id
                    where m.channel_id = $1
                      and m.created_at < (select created_at from messages where id = $2)
                    order by m.created_at desc
                    limit $3
                    "#,
                )
                .bind(channel_id.0)
                .bind(before_id)
                .bind(limit)
                .fetch_all(self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<
                    _,
                    (
                        String,
                        uuid::Uuid,
                        uuid::Uuid,
                        Option<String>,
                        String,
                        DateTime<Utc>,
                    ),
                >(
                    r#"
                    select m.id, m.channel_id, m.author_user_id, u.username, m.content, m.created_at
                    from messages m
                    join users u on u.id = m.author_user_id
                    where m.channel_id = $1
                    order by m.created_at desc
                    limit $2
                    "#,
                )
                .bind(channel_id.0)
                .bind(limit)
                .fetch_all(self.pool)
                .await?
            }
        };

        Ok(rows
            .into_iter()
            .map(
                |(id, channel_id, author_user_id, username, content, created_at)| MessageRow {
                    id,
                    channel_id: ChannelId::from(channel_id),
                    author_user_id: UserId::from(author_user_id),
                    author_username: username.unwrap_or_default(),
                    content,
                    created_at,
                },
            )
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{ChannelRepository, ServerRepository, UserRepository};
    use crate::state::test_db;

    #[tokio::test]
    async fn create_and_get_messages() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let channels = ChannelRepository::new(&pool);
        let messages = MessageRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|message-test")
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

        messages
            .create("01HTEST001", &channel_id, &user_id, "Hello world")
            .await
            .expect("create message");

        messages
            .create("01HTEST002", &channel_id, &user_id, "Second message")
            .await
            .expect("create message 2");

        let fetched = messages
            .get_by_channel(&channel_id, 50, None)
            .await
            .expect("get messages");

        assert_eq!(fetched.len(), 2);
        // Most recent first
        assert_eq!(fetched[0].content, "Second message");
        assert_eq!(fetched[1].content, "Hello world");
        // Username is empty until user sets it via onboarding
        assert_eq!(fetched[0].author_username, "");
    }

    #[tokio::test]
    async fn get_messages_with_pagination() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let channels = ChannelRepository::new(&pool);
        let messages = MessageRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|message-page-test")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Page Server", &user_id)
            .await
            .expect("create server");

        let channel_id = channels
            .create_channel(&server_id, "page-channel")
            .await
            .expect("create channel");

        // Create messages with small delays to ensure ordering
        for i in 1..=5 {
            messages
                .create(
                    &format!("01HPAGE{:03}", i),
                    &channel_id,
                    &user_id,
                    &format!("Message {}", i),
                )
                .await
                .expect("create message");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Get first page (most recent)
        let page1 = messages
            .get_by_channel(&channel_id, 2, None)
            .await
            .expect("get page 1");

        assert_eq!(page1.len(), 2);
        assert_eq!(page1[0].content, "Message 5");
        assert_eq!(page1[1].content, "Message 4");

        // Get second page (before message 4)
        let page2 = messages
            .get_by_channel(&channel_id, 2, Some(&page1[1].id))
            .await
            .expect("get page 2");

        assert_eq!(page2.len(), 2);
        assert_eq!(page2[0].content, "Message 3");
        assert_eq!(page2[1].content, "Message 2");
    }

    #[tokio::test]
    async fn get_messages_empty_channel() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let channels = ChannelRepository::new(&pool);
        let messages = MessageRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|empty-channel-test")
            .await
            .expect("create user");

        let server_id = servers
            .create_server("Empty Server", &user_id)
            .await
            .expect("create server");

        let channel_id = channels
            .create_channel(&server_id, "empty-channel")
            .await
            .expect("create channel");

        let fetched = messages
            .get_by_channel(&channel_id, 50, None)
            .await
            .expect("get messages");

        assert!(fetched.is_empty());
    }
}
