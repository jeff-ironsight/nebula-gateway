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

        if let Some(iss) = claims.iss.as_deref()
            && iss != self.settings.issuer
        {
            return Err(Auth0Error::InvalidIssuer);
        }

        if let Some(aud) = claims.aud.as_ref()
            && !aud_contains(aud, &self.settings.audience)
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn aud_contains_handles_string_and_array() {
        let single = serde_json::Value::String("expected".to_string());
        assert!(aud_contains(&single, "expected"));
        assert!(!aud_contains(&single, "other"));

        let array = serde_json::json!(["first", "expected"]);
        assert!(aud_contains(&array, "expected"));
        assert!(!aud_contains(&array, "missing"));

        let non_string = serde_json::json!(42);
        assert!(!aud_contains(&non_string, "expected"));
    }

    #[tokio::test]
    async fn verify_bypass_returns_sub() {
        let settings = Auth0Settings {
            issuer: "https://issuer.example".to_string(),
            audience: "https://audience.example".to_string(),
            userinfo_url: "https://userinfo.example".to_string(),
            userinfo_cache_ttl: Duration::from_secs(60),
        };

        let verifier = Auth0Verifier::new_test(settings);
        let claims = verifier.verify("token-123").await.expect("verify");

        assert_eq!(claims.sub, "token-123");
    }

    #[tokio::test]
    async fn cache_respects_ttl() {
        let settings = Auth0Settings {
            issuer: "https://issuer.example".to_string(),
            audience: "https://audience.example".to_string(),
            userinfo_url: "https://userinfo.example".to_string(),
            userinfo_cache_ttl: Duration::from_millis(50),
        };

        let verifier = Auth0Verifier::new(settings);
        let claims = Auth0Claims {
            sub: "user-1".to_string(),
            iss: None,
            aud: None,
            exp: None,
        };

        verifier.store_cached("token", claims.clone()).await;
        let cached = verifier.get_cached("token").await.expect("cached");
        assert_eq!(cached.sub, "user-1");

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(verifier.get_cached("token").await.is_none());
    }

    fn settings_for(server: &MockServer) -> Auth0Settings {
        Auth0Settings {
            issuer: "https://issuer.example".to_string(),
            audience: "https://audience.example".to_string(),
            userinfo_url: format!("{}/userinfo", server.uri()),
            userinfo_cache_ttl: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn verify_returns_status_error_on_non_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let verifier = Auth0Verifier::new(settings_for(&server));
        let result = verifier.verify("bad-token").await;

        match result {
            Err(Auth0Error::UserInfoStatus(code)) => assert_eq!(code, 401),
            other => panic!("expected status error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_returns_invalid_issuer() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .and(header("authorization", "Bearer token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "user-123",
                "iss": "https://wrong-issuer.example"
            })))
            .mount(&server)
            .await;

        let verifier = Auth0Verifier::new(settings_for(&server));
        let result = verifier.verify("token-123").await;

        assert!(matches!(result, Err(Auth0Error::InvalidIssuer)));
    }

    #[tokio::test]
    async fn verify_returns_invalid_audience() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "user-123",
                "aud": ["https://other.example"]
            })))
            .mount(&server)
            .await;

        let verifier = Auth0Verifier::new(settings_for(&server));
        let result = verifier.verify("token-456").await;

        assert!(matches!(result, Err(Auth0Error::InvalidAudience)));
    }

    #[tokio::test]
    async fn verify_caches_successful_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .and(header("authorization", "Bearer token-789"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "user-789",
                "iss": "https://issuer.example",
                "aud": "https://audience.example"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let verifier = Auth0Verifier::new(settings_for(&server));
        let claims = verifier.verify("token-789").await.expect("verify");
        assert_eq!(claims.sub, "user-789");

        let cached = verifier.verify("token-789").await.expect("verify cached");
        assert_eq!(cached.sub, "user-789");
    }
}
