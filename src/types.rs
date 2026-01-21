use axum::extract::ws::Message;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChannelId(pub Arc<str>);

impl From<&str> for ChannelId {
    fn from(value: &str) -> Self {
        Self(Arc::from(value))
    }
}
impl From<String> for ChannelId {
    fn from(value: String) -> Self {
        Self(Arc::from(value))
    }
}
impl AsRef<str> for ChannelId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for ChannelId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(ChannelId::from(value))
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectionId(pub Uuid);

impl From<Uuid> for ConnectionId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

impl From<Uuid> for UserId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

pub type OutboundTx = mpsc::UnboundedSender<Message>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Token(pub String);

impl Token {
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut bytes)
            .expect("failed to generate token bytes");
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }
}

pub fn token_hmac(secret: &[u8], token: &Token) -> Vec<u8> {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).expect("invalid HMAC secret");
    mac.update(token.0.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
