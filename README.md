<!--suppress HtmlDeprecatedAttribute -->
<p align="center">
  <img width="450" height="128" alt="Nebula Logo" src="https://github.com/user-attachments/assets/fd7410c7-322c-4ec2-a17b-563b58081cfe" />
</p>

<br>
<p align="center">
  <a href="https://github.com/jeff-ironsight/nebula-gateway/actions/workflows/audit.yml">
    <img src="https://github.com/jeff-ironsight/nebula-gateway/actions/workflows/audit.yml/badge.svg" alt="Cargo Audit">
  </a>
  &nbsp;
  <a href="https://codecov.io/gh/jeff-ironsight/nebula-gateway">
    <img src="https://codecov.io/gh/jeff-ironsight/nebula-gateway/branch/main/graph/badge.svg" alt="Coverage" />
  </a>
  &nbsp;
  <a href="https://libraries.io/github/jeff-ironsight/nebula-gateway">
    <img src="https://img.shields.io/librariesio/github/jeff-ironsight/nebula-gateway" alt="Dependencies" />
  </a>
  &nbsp;
  <a href="https://doc.rust-lang.org/1.93.0/">
    <img src="https://img.shields.io/badge/MSRV-1.93-blue" alt="MSRV" />
  </a>
  &nbsp;
  <a href="https://github.com/jeff-ironsight/nebula-gateway/actions/workflows/ci.yml">
    <img src="https://github.com/jeff-ironsight/nebula-gateway/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" />
  </a>
  <br><br>
  <img src="https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white" alt="Rust" />
  &nbsp;
  <img src="https://img.shields.io/badge/tokio-0B1320?style=flat&logo=tokio&logoColor=white " alt="tokio" />
  &nbsp;
  <img src="https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white" alt="Docker" />
</p>

---

A **Discord-inspired realtime chat gateway** built in **Rust** using **Axum**, **Tokio**, and **WebSockets**.

Nebula focuses on a clean, idiomatic Rust implementation of a gateway layer:

- WebSocket connections
- Channel subscriptions
- Server-authored message dispatch
- Strongly typed protocol and IDs
- Safe concurrent state management

This project is intentionally **backend-first** and designed as a learning and experimentation ground for building
large-scale realtime systems in Rust.

#### Reports:

- Benchmarks: https://jeff-ironsight.github.io/nebula-gateway/bench/
- Coverage: https://jeff-ironsight.github.io/nebula-gateway/coverage/
