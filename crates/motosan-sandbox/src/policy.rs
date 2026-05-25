//! Filesystem + network policy. See design §4.
//!
//! `#[non_exhaustive]` on the enums makes adding VARIANTS non-breaking.
//! `WorkspaceWrite` is a separate `#[non_exhaustive]` struct built only via its
//! builder, so adding FIELDS later is also non-breaking.

use std::path::PathBuf;

/// Network access granted to the sandboxed command.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NetworkPolicy {
    /// All network access blocked.
    #[default]
    Blocked,
    /// Full network access.
    Allowed,
    // Phase 2 adds: Proxied { allowlist: Vec<HostPattern> }
}

/// Writable workspace policy: whole filesystem is readable; writes are confined
/// to `writable_roots` minus `read_only_subpaths`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkspaceWrite {
    pub writable_roots: Vec<PathBuf>,
    pub read_only_subpaths: Vec<PathBuf>,
    pub exclude_tmp: bool,
    pub network: NetworkPolicy,
}

impl WorkspaceWrite {
    /// The only constructor. New optional fields get defaulted here, so adding
    /// them later does not break callers.
    pub fn new(writable_roots: Vec<PathBuf>) -> Self {
        Self {
            writable_roots,
            read_only_subpaths: Vec::new(),
            exclude_tmp: false,
            network: NetworkPolicy::Blocked,
        }
    }

    /// Mark a subpath read-only even though it lives under a writable root.
    /// Use for secret material — NOT for `.git` (that breaks `git commit`).
    pub fn read_only(mut self, p: impl Into<PathBuf>) -> Self {
        self.read_only_subpaths.push(p.into());
        self
    }

    pub fn exclude_tmp(mut self, yes: bool) -> Self {
        self.exclude_tmp = yes;
        self
    }

    pub fn network(mut self, n: NetworkPolicy) -> Self {
        self.network = n;
        self
    }
}

/// Top-level sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxPolicy {
    /// No sandbox — run unrestricted. Used for escalated retries.
    DangerFullAccess,
    /// Read-only filesystem; network per `NetworkPolicy`.
    ReadOnly { network: NetworkPolicy },
    /// Writable roots + read-everywhere; network per `NetworkPolicy`.
    WorkspaceWrite(WorkspaceWrite),
}

impl SandboxPolicy {
    /// Effective network policy for this sandbox policy.
    /// `DangerFullAccess` implies full network.
    pub fn network(&self) -> NetworkPolicy {
        match self {
            SandboxPolicy::DangerFullAccess => NetworkPolicy::Allowed,
            SandboxPolicy::ReadOnly { network } => network.clone(),
            SandboxPolicy::WorkspaceWrite(w) => w.network.clone(),
        }
    }

    /// True when the command should be run without any OS sandbox wrapper.
    pub fn is_full_access(&self) -> bool {
        matches!(self, SandboxPolicy::DangerFullAccess)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let w = WorkspaceWrite::new(vec!["/ws".into()]);
        assert_eq!(w.writable_roots, vec![PathBuf::from("/ws")]);
        assert!(w.read_only_subpaths.is_empty());
        assert!(!w.exclude_tmp);
        assert_eq!(w.network, NetworkPolicy::Blocked);
    }

    #[test]
    fn builder_setters_chain() {
        let w = WorkspaceWrite::new(vec!["/ws".into()])
            .read_only("/ws/secrets")
            .exclude_tmp(true)
            .network(NetworkPolicy::Allowed);
        assert_eq!(w.read_only_subpaths, vec![PathBuf::from("/ws/secrets")]);
        assert!(w.exclude_tmp);
        assert_eq!(w.network, NetworkPolicy::Allowed);
    }

    #[test]
    fn network_helper_maps_each_variant() {
        assert_eq!(
            SandboxPolicy::DangerFullAccess.network(),
            NetworkPolicy::Allowed
        );
        assert_eq!(
            SandboxPolicy::ReadOnly {
                network: NetworkPolicy::Blocked
            }
            .network(),
            NetworkPolicy::Blocked
        );
        let w = SandboxPolicy::WorkspaceWrite(
            WorkspaceWrite::new(vec!["/ws".into()]).network(NetworkPolicy::Allowed),
        );
        assert_eq!(w.network(), NetworkPolicy::Allowed);
    }

    #[test]
    fn is_full_access_only_for_danger() {
        assert!(SandboxPolicy::DangerFullAccess.is_full_access());
        assert!(!SandboxPolicy::ReadOnly {
            network: NetworkPolicy::Blocked
        }
        .is_full_access());
    }
}
