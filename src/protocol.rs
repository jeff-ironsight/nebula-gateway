use crate::types::{ChannelId, ConnectionId, UserId};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", content = "d")]
pub enum GatewayPayload {
    Hello {
        heartbeat_interval_ms: u64,
    },
    Identify {
        user_id: UserId,
    },
    Subscribe {
        channel_id: ChannelId,
    },
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
pub struct MessageCreateEvent {
    pub id: Ulid,
    pub channel_id: ChannelId,
    pub author_connection_id: ConnectionId,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReadyEvent {
    pub connection_id: ConnectionId,
    pub user_id: UserId,
    pub heartbeat_interval_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorEvent {
    pub code: String,
}

#[cfg(test)]
mod tests {
    use super::*;
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
            user_id: UserId(uuid::Uuid::nil()),
        };

        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            json,
            json!({"op":"Identify","d":{"user_id":"00000000-0000-0000-0000-000000000000"}})
        );
    }

    #[test]
    fn message_create_event_round_trip() {
        let message = MessageCreateEvent {
            id: Ulid::new(),
            channel_id: ChannelId::from("general"),
            author_connection_id: ConnectionId::from(uuid::Uuid::nil()),
            content: "hello".into(),
        };

        let json = serde_json::to_string(&message).unwrap();
        let parsed: MessageCreateEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, message.id);
        assert_eq!(parsed.channel_id, message.channel_id);
        assert_eq!(parsed.author_connection_id, message.author_connection_id);
        assert_eq!(parsed.content, message.content);
    }

    #[test]
    fn ready_event_round_trip() {
        let ready = ReadyEvent {
            connection_id: ConnectionId::from(uuid::Uuid::new_v4()),
            user_id: UserId(uuid::Uuid::nil()),
            heartbeat_interval_ms: 25_000,
        };

        let json = serde_json::to_string(&ready).unwrap();
        let parsed: ReadyEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connection_id, ready.connection_id);
        assert_eq!(parsed.user_id, ready.user_id);
        assert_eq!(parsed.heartbeat_interval_ms, ready.heartbeat_interval_ms);
    }
}
