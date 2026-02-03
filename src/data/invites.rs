use crate::types::{InviteCode, InviteId, ServerId, UserId};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct Invite {
    pub id: InviteId,
    pub code: InviteCode,
    pub server_id: ServerId,
    pub creator_id: UserId,
    pub max_uses: Option<i32>,
    pub use_count: i32,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub struct InvitePreview {
    pub code: InviteCode,
    pub server_id: ServerId,
    pub server_name: String,
    pub member_count: i64,
}

pub struct InviteRepository<'a> {
    pool: &'a PgPool,
}

impl<'a> InviteRepository<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        server_id: &ServerId,
        creator_id: &UserId,
        max_uses: Option<i32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Invite, sqlx::Error> {
        let id = Uuid::new_v4();
        let code = InviteCode::generate();

        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Uuid,
                Uuid,
                Option<i32>,
                i32,
                Option<DateTime<Utc>>,
                DateTime<Utc>,
            ),
        >(
            r#"
            insert into server_invites (id, code, server_id, creator_id, max_uses, expires_at)
            values ($1, $2, $3, $4, $5, $6)
            returning id, code, server_id, creator_id, max_uses, use_count, expires_at, created_at
            "#,
        )
        .bind(id)
        .bind(&code.0)
        .bind(server_id.0)
        .bind(creator_id.0)
        .bind(max_uses)
        .bind(expires_at)
        .fetch_one(self.pool)
        .await?;

        Ok(Invite {
            id: InviteId::from(row.0),
            code: InviteCode(row.1),
            server_id: ServerId::from(row.2),
            creator_id: UserId::from(row.3),
            max_uses: row.4,
            use_count: row.5,
            expires_at: row.6,
            created_at: row.7,
        })
    }

    pub async fn get_by_code(&self, code: &str) -> Result<Option<Invite>, sqlx::Error> {
        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Uuid,
                Uuid,
                Option<i32>,
                i32,
                Option<DateTime<Utc>>,
                DateTime<Utc>,
            ),
        >(
            r#"
            select id, code, server_id, creator_id, max_uses, use_count, expires_at, created_at
            from server_invites
            where code = $1
            "#,
        )
        .bind(code)
        .fetch_optional(self.pool)
        .await?;

        Ok(row.map(|r| Invite {
            id: InviteId::from(r.0),
            code: InviteCode(r.1),
            server_id: ServerId::from(r.2),
            creator_id: UserId::from(r.3),
            max_uses: r.4,
            use_count: r.5,
            expires_at: r.6,
            created_at: r.7,
        }))
    }

    pub async fn get_preview(&self, code: &str) -> Result<Option<InvitePreview>, sqlx::Error> {
        let row = sqlx::query_as::<_, (String, Uuid, String, i64)>(
            r#"
            select i.code, s.id, s.name, count(sm.user_id) as member_count
            from server_invites i
            join servers s on s.id = i.server_id
            left join server_members sm on sm.server_id = s.id
            where i.code = $1
              and (i.expires_at is null or i.expires_at > now())
              and (i.max_uses is null or i.use_count < i.max_uses)
            group by i.code, s.id, s.name
            "#,
        )
        .bind(code)
        .fetch_optional(self.pool)
        .await?;

        Ok(row.map(|r| InvitePreview {
            code: InviteCode(r.0),
            server_id: ServerId::from(r.1),
            server_name: r.2,
            member_count: r.3,
        }))
    }

    /// Use an invite to join a server. Returns the server ID if successful, None if invalid/expired/used up.
    pub async fn use_invite(
        &self,
        code: &str,
        user_id: &UserId,
    ) -> Result<Option<ServerId>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Lock and validate the invite
        let invite = sqlx::query_as::<_, (Uuid, i32, Option<i32>, Option<DateTime<Utc>>)>(
            r#"
            select server_id, use_count, max_uses, expires_at
            from server_invites
            where code = $1
            for update
            "#,
        )
        .bind(code)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((server_id, use_count, max_uses, expires_at)) = invite else {
            return Ok(None);
        };

        // Check if expired
        if let Some(exp) = expires_at
            && exp < Utc::now()
        {
            return Ok(None);
        }

        // Check if max uses exceeded
        if let Some(max) = max_uses
            && use_count >= max
        {
            return Ok(None);
        }

        // Check if already a member
        let already_member = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from server_members where server_id = $1 and user_id = $2)",
        )
        .bind(server_id)
        .bind(user_id.0)
        .fetch_one(&mut *tx)
        .await?;

        if already_member {
            // Already a member, return server_id but don't increment use count
            tx.commit().await?;
            return Ok(Some(ServerId::from(server_id)));
        }

        // Add as member
        sqlx::query(
            "insert into server_members (server_id, user_id, role) values ($1, $2, 'member')",
        )
        .bind(server_id)
        .bind(user_id.0)
        .execute(&mut *tx)
        .await?;

        // Increment use count
        sqlx::query("update server_invites set use_count = use_count + 1 where code = $1")
            .bind(code)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(Some(ServerId::from(server_id)))
    }

    pub async fn delete(&self, code: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("delete from server_invites where code = $1")
            .bind(code)
            .execute(self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn is_creator(&self, code: &str, user_id: &UserId) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar::<_, bool>(
            "select exists(select 1 from server_invites where code = $1 and creator_id = $2)",
        )
        .bind(code)
        .bind(user_id.0)
        .fetch_one(self.pool)
        .await?;
        Ok(exists)
    }

    pub async fn get_server_id_for_invite(
        &self,
        code: &str,
    ) -> Result<Option<ServerId>, sqlx::Error> {
        let server_id =
            sqlx::query_scalar::<_, Uuid>("select server_id from server_invites where code = $1")
                .bind(code)
                .fetch_optional(self.pool)
                .await?;
        Ok(server_id.map(ServerId::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{ServerRepository, UserRepository};
    use crate::state::test_db;
    use chrono::Duration;

    #[tokio::test]
    async fn create_invite_generates_unique_code() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|invite-test-1")
            .await
            .expect("create user");
        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .expect("create server");

        let invite = invites
            .create(&server_id, &user_id, None, None)
            .await
            .expect("create invite");

        assert_eq!(invite.code.0.len(), 8);
        assert_eq!(invite.server_id, server_id);
        assert_eq!(invite.creator_id, user_id);
        assert!(invite.max_uses.is_none());
        assert!(invite.expires_at.is_none());
        assert_eq!(invite.use_count, 0);
    }

    #[tokio::test]
    async fn get_by_code_returns_invite() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|invite-test-2")
            .await
            .expect("create user");
        let server_id = servers
            .create_server("Test Server", &user_id)
            .await
            .expect("create server");

        let created = invites
            .create(&server_id, &user_id, Some(10), None)
            .await
            .expect("create invite");

        let fetched = invites
            .get_by_code(&created.code.0)
            .await
            .expect("get invite")
            .expect("invite exists");

        assert_eq!(fetched.id, created.id);
        assert_eq!(fetched.max_uses, Some(10));
    }

    #[tokio::test]
    async fn get_preview_returns_server_info() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|invite-preview-test")
            .await
            .expect("create user");
        let server_id = servers
            .create_server("Preview Server", &user_id)
            .await
            .expect("create server");

        let invite = invites
            .create(&server_id, &user_id, None, None)
            .await
            .expect("create invite");

        let preview = invites
            .get_preview(&invite.code.0)
            .await
            .expect("get preview")
            .expect("preview exists");

        assert_eq!(preview.server_name, "Preview Server");
        assert_eq!(preview.server_id, server_id);
        assert_eq!(preview.member_count, 1); // Owner is a member
    }

    #[tokio::test]
    async fn use_invite_adds_member_and_increments_count() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|invite-owner")
            .await
            .expect("create owner");
        let joiner_id = users
            .get_or_create_by_auth_sub("auth0|invite-joiner")
            .await
            .expect("create joiner");
        let server_id = servers
            .create_server("Join Server", &owner_id)
            .await
            .expect("create server");

        let invite = invites
            .create(&server_id, &owner_id, None, None)
            .await
            .expect("create invite");

        // Use invite
        let result = invites
            .use_invite(&invite.code.0, &joiner_id)
            .await
            .expect("use invite");
        assert_eq!(result, Some(server_id));

        // Verify membership
        let is_member = servers
            .is_member(&server_id, &joiner_id)
            .await
            .expect("check membership");
        assert!(is_member);

        // Verify use count incremented
        let updated = invites
            .get_by_code(&invite.code.0)
            .await
            .expect("get invite")
            .expect("invite exists");
        assert_eq!(updated.use_count, 1);
    }

    #[tokio::test]
    async fn use_invite_returns_none_for_expired_invite() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|expired-owner")
            .await
            .expect("create owner");
        let joiner_id = users
            .get_or_create_by_auth_sub("auth0|expired-joiner")
            .await
            .expect("create joiner");
        let server_id = servers
            .create_server("Expired Server", &owner_id)
            .await
            .expect("create server");

        // Create expired invite
        let expired_at = Utc::now() - Duration::hours(1);
        let invite = invites
            .create(&server_id, &owner_id, None, Some(expired_at))
            .await
            .expect("create invite");

        let result = invites
            .use_invite(&invite.code.0, &joiner_id)
            .await
            .expect("use invite");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn use_invite_returns_none_when_max_uses_reached() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|maxuses-owner")
            .await
            .expect("create owner");
        let joiner1_id = users
            .get_or_create_by_auth_sub("auth0|maxuses-joiner1")
            .await
            .expect("create joiner1");
        let joiner2_id = users
            .get_or_create_by_auth_sub("auth0|maxuses-joiner2")
            .await
            .expect("create joiner2");
        let server_id = servers
            .create_server("MaxUses Server", &owner_id)
            .await
            .expect("create server");

        // Create invite with max 1 use
        let invite = invites
            .create(&server_id, &owner_id, Some(1), None)
            .await
            .expect("create invite");

        // First use should succeed
        let result1 = invites
            .use_invite(&invite.code.0, &joiner1_id)
            .await
            .expect("use invite 1");
        assert!(result1.is_some());

        // Second use should fail
        let result2 = invites
            .use_invite(&invite.code.0, &joiner2_id)
            .await
            .expect("use invite 2");
        assert!(result2.is_none());
    }

    #[tokio::test]
    async fn use_invite_idempotent_for_existing_member() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let owner_id = users
            .get_or_create_by_auth_sub("auth0|idempotent-owner")
            .await
            .expect("create owner");
        let server_id = servers
            .create_server("Idempotent Server", &owner_id)
            .await
            .expect("create server");

        let invite = invites
            .create(&server_id, &owner_id, None, None)
            .await
            .expect("create invite");

        // Owner uses their own invite (already a member)
        let result = invites
            .use_invite(&invite.code.0, &owner_id)
            .await
            .expect("use invite");
        assert_eq!(result, Some(server_id));

        // Use count should NOT increment
        let updated = invites
            .get_by_code(&invite.code.0)
            .await
            .expect("get invite")
            .expect("invite exists");
        assert_eq!(updated.use_count, 0);
    }

    #[tokio::test]
    async fn delete_removes_invite() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let user_id = users
            .get_or_create_by_auth_sub("auth0|delete-test")
            .await
            .expect("create user");
        let server_id = servers
            .create_server("Delete Server", &user_id)
            .await
            .expect("create server");

        let invite = invites
            .create(&server_id, &user_id, None, None)
            .await
            .expect("create invite");

        let deleted = invites.delete(&invite.code.0).await.expect("delete invite");
        assert!(deleted);

        let fetched = invites
            .get_by_code(&invite.code.0)
            .await
            .expect("get invite");
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn is_creator_returns_true_for_creator() {
        let pool = test_db().await;
        let users = UserRepository::new(&pool);
        let servers = ServerRepository::new(&pool);
        let invites = InviteRepository::new(&pool);

        let creator_id = users
            .get_or_create_by_auth_sub("auth0|creator-test")
            .await
            .expect("create creator");
        let other_id = users
            .get_or_create_by_auth_sub("auth0|other-test")
            .await
            .expect("create other");
        let server_id = servers
            .create_server("Creator Server", &creator_id)
            .await
            .expect("create server");

        let invite = invites
            .create(&server_id, &creator_id, None, None)
            .await
            .expect("create invite");

        let is_creator = invites
            .is_creator(&invite.code.0, &creator_id)
            .await
            .expect("check creator");
        assert!(is_creator);

        let is_other_creator = invites
            .is_creator(&invite.code.0, &other_id)
            .await
            .expect("check other");
        assert!(!is_other_creator);
    }
}
