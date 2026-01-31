use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Auth0Settings {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub jwks_cache_ttl: Duration,
}

#[derive(Debug)]
pub struct Auth0Verifier {
    settings: Auth0Settings,
    client: Client,
    jwks_cache: RwLock<Option<CachedJwks>>,
    #[cfg(test)]
    test_mode: Option<TestMode>,
}

struct CachedJwks {
    fetched_at: Instant,
    keys: HashMap<String, DecodingKey>,
}

impl std::fmt::Debug for CachedJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedJwks")
            .field("fetched_at", &self.fetched_at)
            .field("keys", &format!("[{} keys]", self.keys.len()))
            .finish()
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
enum TestMode {
    /// Returns token as sub (for multi-user tests)
    TokenAsSub,
    /// Returns fixed claims
    FixedClaims(Auth0Claims),
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AppClaims {
    #[serde(default)]
    pub is_developer: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Auth0Claims {
    pub sub: String,
    #[serde(default)]
    pub iss: Option<String>,
    #[serde(default)]
    pub aud: Option<serde_json::Value>,
    #[serde(default)]
    pub exp: Option<usize>,
    #[serde(rename = "https://nebula.dev/app", default)]
    pub app: Option<AppClaims>,
}

impl Auth0Claims {
    pub fn is_developer(&self) -> bool {
        self.app.as_ref().map(|a| a.is_developer).unwrap_or(false)
    }
}

#[derive(Debug)]
pub enum Auth0Error {
    JwksFetch(String),
    NoKidInToken,
    UnknownKid(String),
    InvalidToken(String),
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

impl Auth0Verifier {
    pub fn new(settings: Auth0Settings) -> Self {
        Self {
            settings,
            client: Client::new(),
            jwks_cache: RwLock::new(None),
            #[cfg(test)]
            test_mode: None,
        }
    }

    pub async fn verify(&self, token: &str) -> Result<Auth0Claims, Auth0Error> {
        #[cfg(test)]
        if let Some(test_mode) = &self.test_mode {
            return Ok(match test_mode {
                TestMode::TokenAsSub => Auth0Claims {
                    sub: token.to_string(),
                    iss: None,
                    aud: None,
                    exp: None,
                    app: None,
                },
                TestMode::FixedClaims(claims) => claims.clone(),
            });
        }

        let header = decode_header(token).map_err(|e| Auth0Error::InvalidToken(e.to_string()))?;

        let kid = header.kid.ok_or(Auth0Error::NoKidInToken)?;

        let decoding_key = self.get_decoding_key(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.settings.issuer]);
        validation.set_audience(&[&self.settings.audience]);

        let token_data = decode::<Auth0Claims>(token, &decoding_key, &validation)
            .map_err(|e| Auth0Error::InvalidToken(e.to_string()))?;

        Ok(token_data.claims)
    }

    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, Auth0Error> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(cached) = cache.as_ref()
                && cached.fetched_at.elapsed() <= self.settings.jwks_cache_ttl
                && let Some(key) = cached.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }

        // Fetch fresh JWKS
        self.refresh_jwks().await?;

        // Try again from cache
        let cache = self.jwks_cache.read().await;
        cache
            .as_ref()
            .and_then(|c| c.keys.get(kid).cloned())
            .ok_or_else(|| Auth0Error::UnknownKid(kid.to_string()))
    }

    async fn refresh_jwks(&self) -> Result<(), Auth0Error> {
        let response = self
            .client
            .get(&self.settings.jwks_url)
            .send()
            .await
            .map_err(|e| Auth0Error::JwksFetch(e.to_string()))?;

        if !response.status().is_success() {
            return Err(Auth0Error::JwksFetch(format!(
                "JWKS endpoint returned {}",
                response.status()
            )));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| Auth0Error::JwksFetch(e.to_string()))?;

        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            if jwk.kty == "RSA"
                && let (Some(n), Some(e)) = (&jwk.n, &jwk.e)
                && let Ok(key) = DecodingKey::from_rsa_components(n, e)
            {
                keys.insert(jwk.kid.clone(), key);
            }
        }

        let mut cache = self.jwks_cache.write().await;
        *cache = Some(CachedJwks {
            fetched_at: Instant::now(),
            keys,
        });

        Ok(())
    }

    #[cfg(test)]
    pub fn new_test(settings: Auth0Settings) -> Self {
        Self {
            settings,
            client: Client::new(),
            jwks_cache: RwLock::new(None),
            test_mode: Some(TestMode::TokenAsSub),
        }
    }

    #[cfg(test)]
    pub fn new_test_with_claims(settings: Auth0Settings, claims: Auth0Claims) -> Self {
        Self {
            settings,
            client: Client::new(),
            jwks_cache: RwLock::new(None),
            test_mode: Some(TestMode::FixedClaims(claims)),
        }
    }
}

impl Clone for Auth0Verifier {
    fn clone(&self) -> Self {
        Self {
            settings: self.settings.clone(),
            client: self.client.clone(),
            jwks_cache: RwLock::new(None),
            #[cfg(test)]
            test_mode: self.test_mode.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_settings(jwks_url: &str) -> Auth0Settings {
        Auth0Settings {
            issuer: "https://issuer.example/".to_string(),
            audience: "https://audience.example".to_string(),
            jwks_url: jwks_url.to_string(),
            jwks_cache_ttl: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn test_mode_returns_token_as_sub() {
        let settings = test_settings("https://example.invalid/.well-known/jwks.json");
        let verifier = Auth0Verifier::new_test(settings);

        let claims = verifier.verify("user-123").await.expect("verify");
        assert_eq!(claims.sub, "user-123");
        assert!(!claims.is_developer());
    }

    #[tokio::test]
    async fn test_mode_with_developer_flag() {
        let settings = test_settings("https://example.invalid/.well-known/jwks.json");
        let claims = Auth0Claims {
            sub: "dev-user".to_string(),
            iss: None,
            aud: None,
            exp: None,
            app: Some(AppClaims { is_developer: true }),
        };
        let verifier = Auth0Verifier::new_test_with_claims(settings, claims);

        let result = verifier.verify("any-token").await.expect("verify");
        assert_eq!(result.sub, "dev-user");
        assert!(result.is_developer());
    }

    #[tokio::test]
    async fn jwks_fetch_failure_returns_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let settings = test_settings(&format!("{}/.well-known/jwks.json", server.uri()));
        let verifier = Auth0Verifier::new(settings);

        let result = verifier.refresh_jwks().await;
        assert!(matches!(result, Err(Auth0Error::JwksFetch(_))));
    }

    #[tokio::test]
    async fn get_decoding_key_caches_jwks() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": "test-key-id",
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let settings = test_settings(&format!("{}/.well-known/jwks.json", server.uri()));
        let verifier = Auth0Verifier::new(settings);

        // First call fetches from network
        let _ = verifier.get_decoding_key("test-key-id").await;
        // Second call uses cache
        let _ = verifier.get_decoding_key("test-key-id").await;

        // Mock expects exactly 1 call - second uses cache
    }

    #[tokio::test]
    async fn verify_rejects_malformed_token() {
        let settings = test_settings("https://example.invalid/.well-known/jwks.json");
        let verifier = Auth0Verifier::new(settings);

        let result = verifier.verify("not-a-valid-jwt").await;
        assert!(matches!(result, Err(Auth0Error::InvalidToken(_))));
    }

    #[tokio::test]
    async fn verify_rejects_token_without_kid() {
        let settings = test_settings("https://example.invalid/.well-known/jwks.json");
        let verifier = Auth0Verifier::new(settings);

        // A valid JWT structure but with no kid in header
        // Header: {"alg":"RS256","typ":"JWT"} (no kid)
        // This is base64url encoded
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.fake-signature";

        let result = verifier.verify(token).await;
        assert!(matches!(result, Err(Auth0Error::NoKidInToken)));
    }

    #[tokio::test]
    async fn verify_rejects_unknown_kid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": "known-key-id",
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }]
            })))
            .mount(&server)
            .await;

        let settings = test_settings(&format!("{}/.well-known/jwks.json", server.uri()));
        let verifier = Auth0Verifier::new(settings);

        // Token with kid="unknown-key-id" in header
        // Header: {"alg":"RS256","typ":"JWT","kid":"unknown-key-id"}
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVua25vd24ta2V5LWlkIn0.eyJzdWIiOiJ0ZXN0In0.fake-signature";

        let result = verifier.verify(token).await;
        assert!(matches!(result, Err(Auth0Error::UnknownKid(kid)) if kid == "unknown-key-id"));
    }

    #[test]
    fn is_developer_returns_false_when_app_is_none() {
        let claims = Auth0Claims {
            sub: "user".to_string(),
            iss: None,
            aud: None,
            exp: None,
            app: None,
        };
        assert!(!claims.is_developer());
    }

    #[test]
    fn is_developer_returns_false_when_flag_is_false() {
        let claims = Auth0Claims {
            sub: "user".to_string(),
            iss: None,
            aud: None,
            exp: None,
            app: Some(AppClaims {
                is_developer: false,
            }),
        };
        assert!(!claims.is_developer());
    }

    #[test]
    fn is_developer_returns_true_when_flag_is_true() {
        let claims = Auth0Claims {
            sub: "user".to_string(),
            iss: None,
            aud: None,
            exp: None,
            app: Some(AppClaims { is_developer: true }),
        };
        assert!(claims.is_developer());
    }

    #[tokio::test]
    async fn jwks_skips_non_rsa_keys() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kid": "ec-key",
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "test",
                        "y": "test"
                    },
                    {
                        "kid": "rsa-key",
                        "kty": "RSA",
                        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                        "e": "AQAB"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let settings = test_settings(&format!("{}/.well-known/jwks.json", server.uri()));
        let verifier = Auth0Verifier::new(settings);

        // RSA key should be found
        let result = verifier.get_decoding_key("rsa-key").await;
        assert!(result.is_ok());

        // EC key should not be found (skipped)
        let result = verifier.get_decoding_key("ec-key").await;
        assert!(matches!(result, Err(Auth0Error::UnknownKid(_))));
    }

    #[tokio::test]
    async fn jwks_skips_rsa_keys_missing_components() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [
                    {
                        "kid": "missing-n",
                        "kty": "RSA",
                        "e": "AQAB"
                    },
                    {
                        "kid": "missing-e",
                        "kty": "RSA",
                        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
                    }
                ]
            })))
            .mount(&server)
            .await;

        let settings = test_settings(&format!("{}/.well-known/jwks.json", server.uri()));
        let verifier = Auth0Verifier::new(settings);

        // Both keys should be skipped due to missing components
        let result = verifier.get_decoding_key("missing-n").await;
        assert!(matches!(result, Err(Auth0Error::UnknownKid(_))));

        let result = verifier.get_decoding_key("missing-e").await;
        assert!(matches!(result, Err(Auth0Error::UnknownKid(_))));
    }

    #[tokio::test]
    async fn expired_cache_triggers_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": "test-key-id",
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }]
            })))
            .expect(2) // Expect 2 calls due to cache expiration
            .mount(&server)
            .await;

        let settings = Auth0Settings {
            issuer: "https://issuer.example/".to_string(),
            audience: "https://audience.example".to_string(),
            jwks_url: format!("{}/.well-known/jwks.json", server.uri()),
            jwks_cache_ttl: Duration::from_millis(1), // Very short TTL
        };
        let verifier = Auth0Verifier::new(settings);

        // First call fetches from network
        let _ = verifier.get_decoding_key("test-key-id").await;

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Second call should fetch again due to expired cache
        let _ = verifier.get_decoding_key("test-key-id").await;

        // Mock expects exactly 2 calls
    }

    #[tokio::test]
    async fn clone_resets_cache() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kid": "test-key-id",
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }]
            })))
            .expect(2) // Original + clone each fetch
            .mount(&server)
            .await;

        let settings = test_settings(&format!("{}/.well-known/jwks.json", server.uri()));
        let verifier = Auth0Verifier::new(settings);

        // Populate cache
        let _ = verifier.get_decoding_key("test-key-id").await;

        // Clone should have empty cache
        let cloned = verifier.clone();
        let _ = cloned.get_decoding_key("test-key-id").await;

        // Mock expects 2 calls - clone doesn't share cache
    }
}
