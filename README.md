# Nebula Gateway

A **Discord-inspired realtime chat gateway** built in **Rust** using **Axum**, **Tokio**, and **WebSockets**.

Nebula focuses on a clean, idiomatic Rust implementation of a gateway layer:

- WebSocket connections
- Channel subscriptions
- Server-authored message dispatch
- Strongly typed protocol and IDs
- Safe concurrent state management

This project is intentionally **backend-first** and designed as a learning and experimentation ground for building
large-scale realtime systems in Rust.

## Environment

Copy the example file and edit values as needed:

```bash
cp .env.example .env
```