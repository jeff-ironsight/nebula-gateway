use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Auth0Settings {
    pub issuer: String,
    pub audience: String,
    pub userinfo_url: String,
    pub userinfo_cache_ttl: Duration,
}

#[derive(Debug)]
pub struct Auth0Verifier {
    settings: Auth0Settings,
    client: Client,
    userinfo_cache: RwLock<HashMap<String, CachedUserInfo>>,
    #[cfg(test)]
    test_bypass: bool,
}

#[derive(Debug)]
struct CachedUserInfo {
    fetched_at: Instant,
    claims: Auth0Claims,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Auth0Claims {
    pub sub: String,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    #[serde(default)]
    pub exp: Option<usize>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Auth0Error {
    UserInfoStatus(u16),
    UserInfoFetch(String),
    InvalidIssuer,
    InvalidAudience,
    MissingIssuer,
    MissingAudience,
}

impl Auth0Verifier {
    pub fn new(settings: Auth0Settings) -> Self {
        Self {
            settings,
            client: Client::new(),
            userinfo_cache: RwLock::new(HashMap::new()),
            #[cfg(test)]
            test_bypass: false,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<Auth0Claims, Auth0Error> {
        #[cfg(test)]
        if self.test_bypass {
            return Ok(Auth0Claims {
                sub: token.to_string(),
                iss: None,
                aud: None,
                exp: None,
            });
        }

        if let Some(claims) = self.get_cached(token).await {
            return Ok(claims);
        }

        let response = self
            .client
            .get(&self.settings.userinfo_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| Auth0Error::UserInfoFetch(err.to_string()))?;

        if !response.status().is_success() {
            return Err(Auth0Error::UserInfoStatus(response.status().as_u16()));
        }

        let claims = response
            .json::<Auth0Claims>()
            .await
            .map_err(|err| Auth0Error::UserInfoFetch(err.to_string()))?;

        let Some(iss) = claims.iss.as_deref() else {
            return Err(Auth0Error::MissingIssuer);
        };
        if iss != self.settings.issuer {
            return Err(Auth0Error::InvalidIssuer);
        }

        let Some(aud) = claims.aud.as_ref() else {
            return Err(Auth0Error::MissingAudience);
        };
        if !aud_contains(aud, &self.settings.audience) {
            return Err(Auth0Error::InvalidAudience);
        }

        self.store_cached(token, claims.clone()).await;
        Ok(claims)
    }

    async fn get_cached(&self, token: &str) -> Option<Auth0Claims> {
        let cache = self.userinfo_cache.read().await;
        cache.get(token).and_then(|entry| {
            if entry.fetched_at.elapsed() <= self.settings.userinfo_cache_ttl {
                Some(entry.claims.clone())
            } else {
                None
            }
        })
    }

    async fn store_cached(&self, token: &str, claims: Auth0Claims) {
        let mut cache = self.userinfo_cache.write().await;
        cache.insert(
            token.to_string(),
            CachedUserInfo {
                fetched_at: Instant::now(),
                claims,
            },
        );
    }

    #[cfg(test)]
    pub fn new_test(settings: Auth0Settings) -> Self {
        let mut verifier = Self::new(settings);
        verifier.test_bypass = true;
        verifier
    }
}

fn aud_contains(aud: &serde_json::Value, expected: &str) -> bool {
    match aud {
        serde_json::Value::String(value) => value == expected,
        serde_json::Value::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|candidate| candidate == expected)
        }),
        _ => false,
    }
}

impl Clone for Auth0Verifier {
    fn clone(&self) -> Self {
        Self {
            settings: self.settings.clone(),
            client: self.client.clone(),
            userinfo_cache: RwLock::new(HashMap::new()),
            #[cfg(test)]
            test_bypass: self.test_bypass,
        }
    }
}
