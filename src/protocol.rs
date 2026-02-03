use crate::types::{ChannelId, ChannelType, ConnectionId, ServerId, Token, UserId};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", content = "d")]
pub enum GatewayPayload {
    Hello {
        heartbeat_interval_ms: u64,
    },
    Identify {
        token: Token,
    },
    Subscribe {},
    MessageCreate {
        channel_id: ChannelId,
        content: String,
    },
    Dispatch {
        t: String,
        d: serde_json::Value,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubscribedEvent {
    pub channel_ids: Vec<ChannelId>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageCreateEvent {
    pub id: Ulid,
    pub channel_id: ChannelId,
    pub author_user_id: UserId,
    pub author_username: String,
    pub content: String,
    pub timestamp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReadyChannel {
    pub id: ChannelId,
    pub server_id: ServerId,
    pub name: String,
    pub channel_type: ChannelType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReadyServer {
    pub id: ServerId,
    pub name: String,
    pub owner_user_id: Option<UserId>,
    pub my_role: String,
    pub channels: Vec<ReadyChannel>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReadyEvent {
    pub connection_id: ConnectionId,
    pub user_id: UserId,
    pub username: String,
    pub heartbeat_interval_ms: u64,
    pub is_developer: bool,
    pub servers: Vec<ReadyServer>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    NotIdentified,
    NotSubscribed,
    InvalidToken,
    UsernameRequired,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorEvent {
    pub code: ErrorCode,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberJoinEvent {
    pub server_id: ServerId,
    pub user_id: UserId,
    pub username: Option<String>,
    pub joined_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn hello_round_trip() {
        let payload = GatewayPayload::Hello {
            heartbeat_interval_ms: 25_000,
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            json,
            r#"{"op":"Hello","d":{"heartbeat_interval_ms":25000}}"#
        );

        let parsed: GatewayPayload = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            GatewayPayload::Hello {
                heartbeat_interval_ms: 25_000
            }
        ));
    }

    #[test]
    fn identify_payload_serializes_with_ids() {
        let payload = GatewayPayload::Identify {
            token: Token(uuid::Uuid::nil().to_string()),
        };

        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            json,
            json!({"op":"Identify","d":{"token":"00000000-0000-0000-0000-000000000000"}})
        );
    }

    #[test]
    fn error_event_serializes_with_code() {
        let event = ErrorEvent {
            code: ErrorCode::NotIdentified,
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json, json!({"code":"NOT_IDENTIFIED"}));
    }

    #[test]
    fn message_create_event_round_trip() {
        let message = MessageCreateEvent {
            id: Ulid::new(),
            channel_id: ChannelId::from(uuid::Uuid::nil()),
            author_user_id: UserId::from(uuid::Uuid::nil()),
            author_username: "test-user".into(),
            content: "hello".into(),
            timestamp: Utc::now().to_rfc3339(),
        };

        let json = serde_json::to_string(&message).unwrap();
        let parsed: MessageCreateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, message.id);
        assert_eq!(parsed.channel_id, message.channel_id);
        assert_eq!(parsed.author_user_id, message.author_user_id);
        assert_eq!(parsed.content, message.content);
    }

    #[test]
    fn ready_event_round_trip() {
        let ready = ReadyEvent {
            connection_id: ConnectionId::from(uuid::Uuid::new_v4()),
            user_id: UserId(uuid::Uuid::nil()),
            username: "test-user".into(),
            heartbeat_interval_ms: 25_000,
            is_developer: true,
            servers: vec![],
        };

        let json = serde_json::to_string(&ready).unwrap();
        let parsed: ReadyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connection_id, ready.connection_id);
        assert_eq!(parsed.user_id, ready.user_id);
        assert_eq!(parsed.username, ready.username);
        assert_eq!(parsed.heartbeat_interval_ms, ready.heartbeat_interval_ms);
        assert_eq!(parsed.is_developer, ready.is_developer);
        assert_eq!(parsed.servers.len(), 0);
    }
}
