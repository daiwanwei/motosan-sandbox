//! Allowlist matching (stub — real implementation lands in Task 4).

pub struct Allowlist;

impl Allowlist {
    pub fn parse(_: &[String]) -> Self {
        Allowlist
    }
    pub fn allows(&self, _host: &str) -> bool {
        false
    }
}
