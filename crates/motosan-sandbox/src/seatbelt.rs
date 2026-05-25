//! macOS Seatbelt backend — filled out in Tasks 7–8.

use crate::error::Error;
use crate::policy::SandboxPolicy;
use crate::types::{SandboxCommand, SandboxKind, SpawnRequest};

pub(crate) fn transform_seatbelt(
    _cmd: &SandboxCommand,
    _policy: &SandboxPolicy,
) -> Result<SpawnRequest, Error> {
    Err(Error::Unsupported(SandboxKind::MacosSeatbelt))
}
