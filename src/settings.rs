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
    pub jwks_url: Option<String>,
    pub jwks_cache_ttl_seconds: Option<u64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::remove_var(key);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                unsafe {
                    std::env::set_var(self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }

    #[test]
    fn load_development_settings_from_config() {
        let _guard = EnvGuard::set("NEBULA_ENV", "development");

        let settings = Settings::load().expect("load settings");
        assert!(!settings.server.bind_addr.is_empty());
        assert!(!settings.server.database_url.is_empty());
        assert!(settings.auth.issuer.is_some());
    }

    #[test]
    fn load_defaults_to_development_and_honors_env_override() {
        let _env_guard = EnvGuard::unset("NEBULA_ENV");
        let _override_guard = EnvGuard::set("NEBULA__SERVER__BIND_ADDR", "0.0.0.0:4000");

        let settings = Settings::load().expect("load settings");
        assert_eq!(settings.server.bind_addr, "0.0.0.0:4000");
    }
}
