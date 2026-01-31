# Claude Code Guidelines

## Project Overview

Rust WebSocket gateway service using Axum. Handles real-time messaging with Auth0 JWT authentication.

## Key Patterns

**Architecture**: Handler code in `src/gateway/` and `src/rest/`, database queries in `src/data/`, shared state in
`src/state.rs`, protocol types in `src/protocol.rs`.

**Concurrency**: Use `Arc<AppState>` for shared state. In-memory maps use `DashMap`/`DashSet` for lock-free concurrent
access.

**Database**: SQLx with PostgreSQL. Repository pattern in `src/data/` with entity-based modules. Migrations in
`migrations/`.

**Configuration**: Layered config via `config/default.toml` + `config/{NEBULA_ENV}.toml` + `NEBULA__*` env vars.

**Auth**: Auth0 JWT verification with JWKS caching. Tokens verified before user operations.

## Commands

```bash
cargo check          # Fast type-check
cargo test           # Run tests (uses testcontainers for Postgres)
cargo clippy         # Lint
cargo fmt --all      # Format
cargo run            # Start server (needs DATABASE_URL)
```

## Code Style

- Rust 2024 edition, follow `rustfmt` defaults
- Bubble errors with `Result`, never panic in async handlers
- Log via `tracing` macros (`debug!`, `info!`, `warn!`)
- Tests alongside modules in `#[cfg(test)]` blocks
- Doc comments for non-obvious public APIs

## Testing

Tests use `testcontainers` to spin up real Postgres. The `test_db()` helper in `src/state.rs` handles container
lifecycle and runs migrations automatically.
