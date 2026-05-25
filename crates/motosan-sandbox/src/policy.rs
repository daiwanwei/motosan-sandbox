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
    /// Egress only to allowlisted hosts, via a local proxy. Hard on macOS
    /// (Seatbelt restricts egress to the proxy endpoint); `Error::Unsupported`
    /// on Linux until Phase 3 (netns + loopback bridge).
    Proxied { allowlist: Vec<HostPattern> },
}

/// An allowlist entry. Matching itself lives in the proxy crate; here we model
/// the policy API and render to the canonical string the proxy parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// Exactly this host (`example.com` matches only `example.com`).
    Exact(String),
    /// Subdomains only (`*.example.com` matches `a.example.com`, NOT the apex).
    SubdomainsOnly(String),
    /// Apex + subdomains (`**.example.com` matches `example.com` and `a.example.com`).
    ApexAndSubdomains(String),
    /// Any host. Allowlist-only (meaningless/forbidden as a denial).
    Any,
}

impl HostPattern {
    /// Parse `"example.com"` / `"*.example.com"` / `"**.example.com"` / `"*"`.
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        if s == "*" {
            HostPattern::Any
        } else if let Some(rest) = s.strip_prefix("**.") {
            HostPattern::ApexAndSubdomains(rest.to_ascii_lowercase())
        } else if let Some(rest) = s.strip_prefix("*.") {
            HostPattern::SubdomainsOnly(rest.to_ascii_lowercase())
        } else {
            HostPattern::Exact(s.to_ascii_lowercase())
        }
    }

    /// Canonical string form (round-trips with [`HostPattern::parse`]). This is
    /// what `run()` passes to the proxy crate, which does the actual matching.
    pub fn to_pattern_string(&self) -> String {
        match self {
            HostPattern::Exact(h) => h.clone(),
            HostPattern::SubdomainsOnly(h) => format!("*.{h}"),
            HostPattern::ApexAndSubdomains(h) => format!("**.{h}"),
            HostPattern::Any => "*".to_string(),
        }
    }
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

#[cfg(test)]
mod host_pattern_tests {
    use super::*;

    #[test]
    fn parses_each_shape() {
        assert_eq!(
            HostPattern::parse("example.com"),
            HostPattern::Exact("example.com".into())
        );
        assert_eq!(
            HostPattern::parse("*.example.com"),
            HostPattern::SubdomainsOnly("example.com".into())
        );
        assert_eq!(
            HostPattern::parse("**.example.com"),
            HostPattern::ApexAndSubdomains("example.com".into())
        );
        assert_eq!(HostPattern::parse("*"), HostPattern::Any);
    }

    #[test]
    fn round_trips_to_string() {
        for s in ["example.com", "*.example.com", "**.example.com", "*"] {
            assert_eq!(HostPattern::parse(s).to_pattern_string(), s);
        }
    }

    #[test]
    fn lowercases_host() {
        assert_eq!(
            HostPattern::parse("Example.COM"),
            HostPattern::Exact("example.com".into())
        );
    }

    #[test]
    fn proxied_carries_allowlist() {
        let n = NetworkPolicy::Proxied {
            allowlist: vec![HostPattern::parse("*.example.com")],
        };
        let NetworkPolicy::Proxied { allowlist } = &n else {
            panic!("expected Proxied")
        };
        assert_eq!(allowlist.len(), 1);
    }
}
