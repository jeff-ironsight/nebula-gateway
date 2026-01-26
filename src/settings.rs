use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerSettings,
    pub auth: AuthSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    pub bind_addr: String,
    pub database_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthSettings {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub userinfo_url: Option<String>,
    pub userinfo_cache_ttl_seconds: Option<u64>,
}

impl Settings {
    pub fn load() -> Result<Self, ConfigError> {
        let env = std::env::var("NEBULA_ENV").unwrap_or_else(|_| "development".into());

        Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name(&format!("config/{env}")).required(false))
            .add_source(Environment::with_prefix("NEBULA").separator("__"))
            .build()?
            .try_deserialize()
    }
}
