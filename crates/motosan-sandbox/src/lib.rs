//! `motosan-sandbox` — run a command under a filesystem/network policy.
//!
//! Phase 0: core types + macOS Seatbelt. Linux enforcement arrives in Phase 1
//! (until then [`Sandbox::run`] returns [`Error::Unsupported`] on Linux).
