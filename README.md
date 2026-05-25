# motosan-sandbox (workspace)

OS-level command sandboxing for Rust. See [`crates/motosan-sandbox/README.md`](crates/motosan-sandbox/README.md) for usage.

## Status

| Phase | Scope | Status |
|---|---|---|
| **0** | Core API + macOS Seatbelt backend | ✅ shipped |
| **1** | Linux helper (Landlock + seccomp; self-reexec) | ✅ shipped |
| **2** | Allowlist proxy + `NetworkPolicy::Proxied { allowlist }` (macOS hard; Linux `Unsupported` until Phase 3) | ✅ shipped |
| 3 | Hard Linux egress (netns + loopback bridge to proxy) | planned |

## Layout

```
motosan-sandbox/
├── Cargo.toml                    # [workspace]
├── LICENSE-MIT
└── crates/
    ├── motosan-sandbox/          # core (Phase 0/1/2)
    └── motosan-sandbox-proxy/    # leaf crate (Phase 2 — `proxy` feature pulls it in)
```

## Build

```bash
cargo test
cargo test --features proxy
cargo test --features cancellation
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```

The Seatbelt enforcement tests (`tests/seatbelt_enforcement.rs`, `tests/seatbelt_proxy_probe.rs`,
`tests/proxy_enforcement.rs`) only run on macOS. The Linux Landlock/seccomp
tests (`tests/linux_enforcement.rs`) only run on Linux (use the Phase 1 dev
container with `--security-opt seccomp=unconfined`).

## License

MIT — see [`LICENSE-MIT`](LICENSE-MIT).
