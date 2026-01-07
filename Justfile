#!/usr/bin/env just --justfile

[group('DEV')]
fmt:
    cargo fmt --all && cargo clippy --all-targets --all-features

[group('BUILD')]
release:
    cargo build --release

[group('GIT')]
git-fixup hash:
    git add --all && \
    git commit --fixup='{{ hash }}' && \
    git -c sequence.editor=: rebase -i --autosquash '{{ hash }}'^

[group('TEST')]
hello:
    wscat -c ws://localhost:3000/ws

alias fixup := git-fixup
