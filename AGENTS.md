# Repository Guidelines

## Project Structure & Module Organization

`src/main.rs` boots the Axum server, wires the shared `AppState`, and exposes the `/ws` route. Request routing lives in
`src/app.rs`, while gateway concerns sit under `src/gateway/` (`ws.rs` for the WebSocket upgrade path, `handler.rs` for
future event handlers, and `mod.rs` for exports). Shared data models live in `src/protocol.rs`, and cross-connection
state is encapsulated in `src/state.rs`. Cargo metadata and dependencies are defined in `Cargo.toml`; build artifacts
land in `target/`. Structured runtime configuration lives in `config/` (see below).

## Build, Test, and Development Commands

- `cargo run` — start the local WebSocket gateway on `0.0.0.0:3000`.
- `cargo build --release` — produce an optimized binary before packaging or deploying.
- `cargo check` — fast type-check pass for tight feedback loops.
- `cargo fmt --all` / `cargo clippy --all-targets --all-features` — enforce formatting and lint rules.
  Use `RUST_LOG=debug cargo run` to surface tracing output when diagnosing gateway traffic.

## Coding Style & Naming Conventions

This is a Rust 2024 workspace; follow `rustfmt` defaults (4-space indentation, trailing commas, sorted imports). Prefer
descriptive module names (`protocol`, `state`) and PascalCase types (`GatewayPayload`, `AppState`). Public APIs should
document invariants via doc comments when behavior is non-obvious. Avoid panics in async handlers; bubble errors with
`Result` and log via `tracing`.

## Testing Guidelines

Unit tests belong alongside their modules using `#[cfg(test)]` blocks. Integration or protocol-level scenarios should go
in `tests/` (create if absent) and exercise the Axum router via `tower::Service` helpers. Run `cargo test` locally and
document the results; target ≥90% coverage on gateway logic or justify deviations. When adding WebSocket flows, provide
fixture payloads under `tests/data/` for reproducibility.

## Commit & Pull Request Guidelines

History is empty, so establish discipline now: write imperative, present-tense commits (e.g., `Add heartbeat handling`)
and squash stray fixups. Reference issue IDs when available (`Add Identify handler #12`). Pull requests should include a
summary, test plan (`cargo test`, manual WS steps), and screenshots or logs for observability changes. Mention breaking
API changes explicitly and link related design docs.

## Security & Configuration Tips

Avoid checking secrets into the repo; prefer `.env` files ignored by `.gitignore`. Structured config defaults sit in
`config/default.toml`, with dev overrides in `config/development.toml`; switch via `NEBULA_ENV=production` and override
any key using env vars such as `NEBULA__SERVER__BIND_ADDR=127.0.0.1:4000`. Validate user-supplied payloads against
`GatewayPayload`, and sanitize channel IDs before using them as map keys. When introducing new state, wrap shared
structures in `Arc` + `DashMap` or `tokio::sync` primitives and document the locking model.

## Configuration Workflow

`Settings::load()` merges `config/default.toml`, the `config/{env}.toml` file chosen by `NEBULA_ENV` (defaults to
`development`), and `NEBULA__*` environment variables. Example:
`NEBULA_ENV=production NEBULA__SERVER__BIND_ADDR=0.0.0.0:8080 cargo run` binds the server to `0.0.0.0:8080`. Keep
prod-safe defaults in `config/default.toml` and stage-specific overrides in sibling files.
