<img width="450" height="128" alt="nebula-named-900x512" src="https://github.com/user-attachments/assets/fd7410c7-322c-4ec2-a17b-563b58081cfe" />

---
[![CI](https://github.com/jeff-ironsight/nebula-gateway/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jeff-ironsight/nebula-gateway/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/jeff-ironsight/nebula-gateway/branch/main/graph/badge.svg)](https://codecov.io/gh/jeff-ironsight/nebula-gateway)
[![MSRV](https://img.shields.io/badge/MSRV-1.93-blue)](https://doc.rust-lang.org/1.93.0/)
![Visits](https://visitorbadge.vercel.app//api/badge/f9dc662c-73b2-4b8d-838f-49b2dde231ee?style=flat&color=6686fb&labelColor=2a0ea7)

A **Discord-inspired realtime chat gateway** built in **Rust** using **Axum**, **Tokio**, and **WebSockets**.

Nebula focuses on a clean, idiomatic Rust implementation of a gateway layer:

- WebSocket connections
- Channel subscriptions
- Server-authored message dispatch
- Strongly typed protocol and IDs
- Safe concurrent state management

This project is intentionally **backend-first** and designed as a learning and experimentation ground for building
large-scale realtime systems in Rust.

## Developer Setup

Install common Rust tooling:

```bash
just dev
```
