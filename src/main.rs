use nebula::auth0::{Auth0Settings, Auth0Verifier};
use nebula::{app, settings::Settings, state::AppState};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let settings = Settings::load().expect("failed to load configuration");

    let db = PgPool::connect(&settings.server.database_url).await?;
    let auth0 = build_auth0(&settings)?;
    let state = Arc::new(AppState::new(db, auth0));

    let app = app::build_router(state);

    let addr = settings.server.bind_addr;
    info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn build_auth0(settings: &Settings) -> Result<Option<Auth0Verifier>, Box<dyn std::error::Error>> {
    let has_auth0 = settings.auth.issuer.is_some() || settings.auth.audience.is_some();
    if !has_auth0 {
        return Ok(None);
    }

    let Some(issuer) = settings.auth.issuer.clone() else {
        return Err("auth.issuer is required when Auth0 settings are configured".into());
    };
    let Some(audience) = settings.auth.audience.clone() else {
        return Err("auth.audience is required when auth.issuer is set".into());
    };

    let jwks_url = settings.auth.jwks_url.clone().unwrap_or_else(|| {
        let mut base = issuer.clone();
        if !base.ends_with('/') {
            base.push('/');
        }
        format!("{base}.well-known/jwks.json")
    });
    let ttl = settings.auth.jwks_cache_ttl_seconds.unwrap_or(3600);

    Ok(Some(Auth0Verifier::new(Auth0Settings {
        issuer,
        audience,
        jwks_url,
        jwks_cache_ttl: std::time::Duration::from_secs(ttl),
    })))
}
