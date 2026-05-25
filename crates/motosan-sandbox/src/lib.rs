//! `motosan-sandbox` — run a command under a filesystem/network policy.
//!
//! Phase 0: core types + macOS Seatbelt. Linux enforcement arrives in Phase 1
//! (until then [`Sandbox::run`] returns [`Error::Unsupported`] on Linux).

mod error;
mod policy;
mod types;

pub use error::Error;
pub use policy::{NetworkPolicy, SandboxPolicy, WorkspaceWrite};
