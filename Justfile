#!/usr/bin/env just --justfile

[group('LINT')]
check:
    cargo fmt --all && cargo clippy --all-targets --all-features --fix --allow-dirty && cargo test --all-features
fmt:
	cargo fmt --all && cargo clippy --all-targets --all-features --fix --allow-dirty

[group('BUILD')]
release:
    cargo build --release
debug:
	RUST_LOG=debug cargo run
run:
	cargo run

[group('GIT')]
git-force:
    git push -f
alias yeet := git-force
git-fixup hash:
    git add --all && \
    git commit --fixup='{{ hash }}' && \
    git -c sequence.editor=: rebase -i --autosquash '{{ hash }}'^
alias fixup := git-fixup