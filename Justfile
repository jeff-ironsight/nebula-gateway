#!/usr/bin/env just --justfile

set positional-arguments := true

DATABASE_URL := "postgres://root:rootpass@localhost:5432/nebuladb"
COVERAGE_IGNORE_REGEX := "src/main.rs|src/types.rs"

_default:
    @just --list

# Run full lint + tests for CI-ish checks.
[group('LINT')]
check:
	just migrate-up && \
	cargo fmt --all && \
	cargo clippy --all-targets --all-features --fix --allow-dirty && \
	cargo audit && \
	just test

# Strict lint + test check suitable for CI (no auto-fix, fails on any warning).
[group('LINT')]
ci:
	just migrate-up && \
	cargo fmt --all -- --check && \
	cargo clippy --all-targets --all-features -- -D warnings && \
	cargo audit && \
	just test

# Run lint-only checks.
[group('LINT')]
lint:
	just migrate-up && \
	cargo fmt --all && \
	cargo clippy --all-targets --all-features --fix --allow-dirty && \
	cargo audit

# Check for outdated dependencies.
[group('LINT')]
outdated:
	cargo outdated --exit-code 1

# Format and clippy (no tests).
[group('LINT')]
fmt:
	cargo fmt --all && \
	cargo clippy --all-targets --all-features --fix --allow-dirty

# Install dev tools and set up local env.
[group('SETUP')]
dev:
	rustup component add rustfmt clippy llvm-tools-preview
	cargo install cargo-llvm-cov --locked
	cargo install cargo-audit --locked
	cargo install cargo-outdated --locked
	cargo install cargo-nextest --locked
	cargo install sqlx-cli --locked --no-default-features --features postgres
	brew install gnuplot

# Run tests. Note: nextest is incompatible with this project's test infrastructure,
# which uses a process-local OnceCell to share a single Postgres container across
# all tests. Nextest runs each test in its own process, so it would spin up one
# container per test instead of sharing one.
[group('TEST')]
test:
	cargo test --all-features --lib

# Open generated rustdoc.
[group('TEST')]
doc:
	cargo doc --no-deps --open

# Coverage report (macOS open).
[group('TEST')]
coverage:
	just lint
	cargo llvm-cov --workspace --all-features --html --ignore-filename-regex "{{ COVERAGE_IGNORE_REGEX }}"
	open target/llvm-cov/html/index.html

alias cov := coverage
alias cov-mac := coverage
alias coverage-mac := coverage

# Coverage report (Linux open).
[group('TEST')]
coverage-linux:
	just lint
	cargo llvm-cov --workspace --all-features --html --ignore-filename-regex "{{ COVERAGE_IGNORE_REGEX }}"
	xdg-open target/llvm-cov/html/index.html

alias cov-linux := coverage-linux

# Coverage report (Windows open).
[group('TEST')]
coverage-win:
	just lint
	cargo llvm-cov --workspace --all-features --html --ignore-filename-regex "{{ COVERAGE_IGNORE_REGEX }}"
	start target/llvm-cov/html/index.html

alias cov-win := coverage-win

# Benchmark the project using cargo bench
[group('TEST')]
bench:
	cargo bench --bench gateway -- --noise-threshold 0.05

# Build optimized release binary.
[group('BUILD')]
release:
	cargo build --release

# Run with debug logging.
[group('BUILD')]
debug:
	RUST_LOG=debug cargo run

# Run server.
[group('BUILD')]
run:
	cargo run

# Start local docker services.
[group('DOCKER')]
docker:
    #!/usr/bin/env bash
    ids="$(docker ps -q)"
    if [ -n "$ids" ]; then
    	docker stop $ids
    fi
    docker compose -f docker-compose.dev.yml up -d

# Force push.
[group('GIT')]
git-force:
	git push -f

alias yeet := git-force

# Fixup commit helper.
[group('GIT')]
git-fixup hash:
	git add --all && \
	git commit --fixup='{{ hash }}' && \
	git -c sequence.editor=: rebase -i --autosquash '{{ hash }}'^

alias fixup := git-fixup

# Run DB migrations.
[group('MIGRATE')]
migrate-up:
	DATABASE_URL={{ DATABASE_URL }} sqlx migrate run

# Create a new migration.
[group('MIGRATE')]
migrate name:
	DATABASE_URL={{ DATABASE_URL }} sqlx migrate add {{ name }}

# Prepare sqlx metadata.
[group('MIGRATE')]
prepare:
	cargo sqlx prepare

# Run migrations and prepare sqlx.
[group('MIGRATE')]
migrate-prepare: migrate-up prepare
