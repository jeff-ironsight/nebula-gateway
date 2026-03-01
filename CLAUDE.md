# Claude Code Guidelines

## Project Overview

Rust WebSocket gateway service using Axum. Handles real-time messaging with Auth0 JWT authentication.

## Key Patterns

**Architecture**: Handler code in `src/gateway/` and `src/rest/`, database queries in `src/data/`, shared state in
`src/state.rs`, protocol types in `src/protocol.rs`.

**Concurrency**: Use `Arc<AppState>` for shared state. In-memory maps use `DashMap`/`DashSet` for lock-free concurrent
access. Note: `DashSet::iter()` yields `RefMulti<'_, K>`, not `&K` — `.copied()` does not compile on DashSet iterators.

**Database**: SQLx with PostgreSQL. Repository pattern in `src/data/` with entity-based modules. Migrations in
`migrations/`.

**Configuration**: Layered config via `config/default.toml` + `config/{NEBULA_ENV}.toml` + `NEBULA__*` env vars.

**Auth**: Auth0 JWT verification with JWKS caching. Tokens verified before user operations.

## Commands

Prefer the justfile targets over raw cargo invocations:

```bash
just check       # fmt + clippy (auto-fix) + audit + tests — use for local dev
just ci          # fmt --check + clippy -D warnings + audit + tests — strict, no auto-fix
just lint        # fmt + clippy (auto-fix) + audit, no tests
just test        # cargo test --all-features --lib
just fmt         # fmt + clippy fix only
just doc         # cargo doc --no-deps --open
just outdated    # cargo outdated --exit-code 1
just migrate-up  # run SQLx migrations
just run         # start server
just debug       # start server with RUST_LOG=debug
```

Raw cargo when needed:

```bash
cargo check      # fast type-check
cargo run        # start server (needs DATABASE_URL)
```

## Linting

`pedantic` and `nursery` clippy lint groups are enabled in `Cargo.toml` and apply to every `cargo clippy`
invocation automatically — no extra flags needed. The following are explicitly allowed (not required for
an internal service): `missing_errors_doc`, `missing_panics_doc`, `must_use_candidate`, `too_many_lines`.

Key style rules enforced by lints:

- Prefer `is_some_and(|x| ...)` over `.map(...).unwrap_or(false)`
- Inline format args: `format!("{x}")` not `format!("{}", x)`
- Raw strings: only use `r#"..."#` when the string contains literal `"` characters
- `const fn` for simple constructors like `Repository::new(pool)`
- `// SAFETY:` comment required above every `unsafe` block

## Code Style

- Rust 2024 edition, follow `rustfmt` defaults
- Bubble errors with `Result`, never panic in async handlers
- Log via `tracing` macros (`debug!`, `info!`, `warn!`)
- Tests alongside modules in `#[cfg(test)]` blocks
- Doc comments for non-obvious public APIs; backtick identifiers in doc comments

## Testing

Tests use `testcontainers` to spin up real Postgres. The `test_db()` helper in `src/state.rs` handles container
lifecycle and runs migrations automatically.

**Do not use `cargo nextest`** with this project. The test infrastructure uses a process-local `static OnceCell`
to share a single Postgres container across all tests. Nextest runs each test in its own process, which causes
one container to be spawned per test — exhausting Docker's VM disk with 100+ simultaneous containers.
Always run tests with `cargo test --all-features --lib` (or `just test`).
