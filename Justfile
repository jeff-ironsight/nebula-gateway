#!/usr/bin/env just --justfile

set positional-arguments := true
set dotenv-required := true
set dotenv-load := true

DATABASE_URL := env("DATABASE_URL")

[group('LINT')]
check:
    just migrate-up && cargo fmt --all && cargo clippy --all-targets --all-features --fix --allow-dirty && cargo audit && cargo test --all-features

fmt:
    cargo fmt --all && cargo clippy --all-targets --all-features --fix --allow-dirty

[group('BUILD')]
release:
    cargo build --release

debug:
    RUST_LOG=debug cargo run

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

git-fixup hash:
    git add --all && \
    git commit --fixup='{{ hash }}' && \
    git -c sequence.editor=: rebase -i --autosquash '{{ hash }}'^

alias fixup := git-fixup

[group('MIGRATE')]
migrate-up:
    DATABASE_URL={{ DATABASE_URL }} sqlx migrate run

migrate name:
    DATABASE_URL={{ DATABASE_URL }} sqlx migrate add {{ name }}

prepare:
    cargo sqlx prepare

migrate-prepare: migrate-up prepare
