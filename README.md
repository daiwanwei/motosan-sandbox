# motosan-sandbox (workspace)

OS-level command sandboxing for Rust. See [`crates/motosan-sandbox/README.md`](crates/motosan-sandbox/README.md) for usage.

## Status

| Phase | Scope | Status |
|---|---|---|
| **0** | Core API + macOS Seatbelt backend | ✅ shipped |
| 1 | Linux helper (bwrap + seccomp + Landlock) | planned |
| 2 | Network proxy + `NetworkPolicy::Proxied { allowlist }` | planned |

## Layout

```
motosan-sandbox/
├── Cargo.toml                    # [workspace]
├── LICENSE-MIT
└── crates/
    └── motosan-sandbox/          # the only crate (Phase 0)
```

## Build

```bash
cargo test
cargo test --features cancellation
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```

The Seatbelt enforcement tests (`tests/seatbelt_enforcement.rs`) only run on macOS.

## License

MIT — see [`LICENSE-MIT`](LICENSE-MIT).
