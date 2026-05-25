//! Allowlist matching. Mirrors Codex's semantics:
//! exact / `*.` subdomains-only (excludes apex) / `**.` apex+subdomains / `*` any.

enum Pattern {
    Exact(String),
    SubdomainsOnly(String),
    ApexAndSubdomains(String),
    Any,
}

impl Pattern {
    fn parse(s: &str) -> Self {
        let s = s.trim().to_ascii_lowercase();
        if s == "*" {
            Pattern::Any
        } else if let Some(r) = s.strip_prefix("**.") {
            Pattern::ApexAndSubdomains(r.to_string())
        } else if let Some(r) = s.strip_prefix("*.") {
            Pattern::SubdomainsOnly(r.to_string())
        } else {
            Pattern::Exact(s)
        }
    }
    fn matches(&self, host: &str) -> bool {
        match self {
            Pattern::Any => true,
            Pattern::Exact(h) => host == h,
            Pattern::ApexAndSubdomains(h) => host == h || host.ends_with(&format!(".{h}")),
            // `*.{h}` matches strictly the subdomains, NOT the apex.
            Pattern::SubdomainsOnly(h) => host.ends_with(&format!(".{h}")),
        }
    }
}

pub struct Allowlist(Vec<Pattern>);

impl Allowlist {
    pub fn parse(patterns: &[String]) -> Self {
        Allowlist(patterns.iter().map(|p| Pattern::parse(p)).collect())
    }
    /// Block-by-default: host is allowed only if some pattern matches.
    pub fn allows(&self, host: &str) -> bool {
        let host = normalize(host);
        self.0.iter().any(|p| p.matches(&host))
    }
}

/// Strip a trailing `:port`, surrounding brackets, lowercase.
///
/// NOTE: bracketless IPv6 literals (`::1`) get mangled by the `:port` split —
/// acceptable because it's **fail-closed** (a mangled IPv6 literal won't match a
/// hostname allowlist → denied). Hostnames are the real case here; tighten IPv6
/// parsing only if literal-IPv6 allowlisting is ever needed.
fn normalize(host: &str) -> String {
    let h = host.trim().trim_start_matches('[');
    let h = h.split(']').next().unwrap_or(h); // [::1]:443 → ::1
    let h = h.rsplit_once(':').map(|(a, _)| a).unwrap_or(h); // host:443 → host (IPv4/name)
    h.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn al(p: &[&str]) -> Allowlist {
        Allowlist::parse(&p.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn exact_only_matches_host() {
        let a = al(&["example.com"]);
        assert!(a.allows("example.com"));
        assert!(!a.allows("a.example.com"));
        assert!(!a.allows("evil.com"));
    }

    #[test]
    fn subdomains_only_excludes_apex() {
        let a = al(&["*.example.com"]);
        assert!(a.allows("a.example.com"));
        assert!(a.allows("b.a.example.com"));
        assert!(!a.allows("example.com"));
    }

    #[test]
    fn apex_and_subdomains_includes_apex() {
        let a = al(&["**.example.com"]);
        assert!(a.allows("example.com"));
        assert!(a.allows("a.example.com"));
        assert!(!a.allows("notexample.com"));
    }

    #[test]
    fn any_allows_all() {
        assert!(al(&["*"]).allows("whatever.com"));
    }

    #[test]
    fn block_by_default_empty() {
        assert!(!al(&[]).allows("example.com"));
    }

    #[test]
    fn strips_port_and_lowercases() {
        assert!(al(&["example.com"]).allows("Example.com:443"));
    }

    #[test]
    fn substring_attack_blocked() {
        // "evilexample.com" must NOT match "*.example.com" or "**.example.com"
        // (the leading `.` in the suffix prevents the substring attack).
        assert!(!al(&["*.example.com"]).allows("evilexample.com"));
        assert!(!al(&["**.example.com"]).allows("evilexample.com"));
    }
}
