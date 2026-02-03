#!/usr/bin/env just --justfile

set positional-arguments := true
set dotenv-required := true
set dotenv-load := true

DATABASE_URL := env("DATABASE_URL")
COVERAGE_IGNORE_REGEX := env("COVERAGE_IGNORE_REGEX")

_default:
    @just --list

[group('LINT')]
check:
	just migrate-up && \
	cargo fmt --all && \
	cargo clippy --all-targets --all-features --fix --allow-dirty && \
	cargo audit && \
	cargo test --all-features --lib

[group('LINT')]
lint:
	just migrate-up && \
	cargo fmt --all && \
	cargo clippy --all-targets --all-features --fix --allow-dirty && \
	cargo audit

[group('LINT')]
fmt:
	cargo fmt --all && \
	cargo clippy --all-targets --all-features --fix --allow-dirty

[group('SETUP')]
dev:
	rustup component add rustfmt clippy llvm-tools-preview
	cargo install cargo-llvm-cov --locked
	cargo install cargo-audit --locked
	cargo install cargo-outdated --locked
	cargo install cargo-nextest --locked
	cargo install sqlx-cli --locked --no-default-features --features postgres
	brew install gnuplot
	test -f .env || cp .env.example .env

[group('TEST')]
coverage:
	just lint
	cargo llvm-cov --workspace --all-features --ignore-filename-regex "{{ COVERAGE_IGNORE_REGEX }}"

alias cov := coverage

[group('TEST')]
bench:
	cargo bench --bench gateway -- --noise-threshold 0.05

[group('BUILD')]
release:
	cargo build --release

[group('BUILD')]
debug:
	RUST_LOG=debug cargo run

[group('BUILD')]
run:
	cargo run

[group('DOCKER')]
docker:
    #!/usr/bin/env bash
    ids="$(docker ps -q)"
    if [ -n "$ids" ]; then
    	docker stop $ids
    fi
    docker compose -f docker-compose.dev.yml up -d

[group('GIT')]
git-force:
	git push -f

alias yeet := git-force

[group('GIT')]
git-fixup hash:
	git add --all && \
	git commit --fixup='{{ hash }}' && \
	git -c sequence.editor=: rebase -i --autosquash '{{ hash }}'^

alias fixup := git-fixup

[group('MIGRATE')]
migrate-up:
	DATABASE_URL={{ DATABASE_URL }} sqlx migrate run

[group('MIGRATE')]
migrate name:
	DATABASE_URL={{ DATABASE_URL }} sqlx migrate add {{ name }}

[group('MIGRATE')]
prepare:
	cargo sqlx prepare

migrate-prepare: migrate-up prepare
