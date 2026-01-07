use crate::types::{ChannelId, UserId};
use serde::{Deserialize, Serialize};

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
}
