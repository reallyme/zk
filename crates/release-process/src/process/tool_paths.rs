// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::Path;

use crate::{ReleaseProcessError, ReleaseTool};

use super::tool_identity::{require_tool_digest, validate_executable};

/// Caller-reviewed executable identities for one release run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseToolDigests {
    nargo: [u8; 32],
    barretenberg: [u8; 32],
}

impl ReleaseToolDigests {
    /// Creates exact SHA-256 identities for the two release executables.
    #[must_use]
    pub const fn new(nargo: [u8; 32], barretenberg: [u8; 32]) -> Self {
        Self {
            nargo,
            barretenberg,
        }
    }

    pub(crate) const fn for_tool(self, tool: ReleaseTool) -> [u8; 32] {
        match tool {
            ReleaseTool::Nargo => self.nargo,
            ReleaseTool::Barretenberg => self.barretenberg,
        }
    }
}

/// Paths to explicit release tools; neither tool is discovered from `PATH`.
///
/// This type intentionally omits `Debug` because local executable paths can
/// contain account information.
pub struct ReleaseToolPaths<'a> {
    pub(crate) nargo: &'a Path,
    pub(crate) barretenberg: &'a Path,
    pub(crate) digests: ReleaseToolDigests,
}

impl<'a> ReleaseToolPaths<'a> {
    /// Validates explicit absolute, regular, non-symlinked executables.
    pub fn try_new(
        nargo: &'a Path,
        barretenberg: &'a Path,
        digests: ReleaseToolDigests,
    ) -> Result<Self, ReleaseProcessError> {
        validate_executable(nargo)?;
        validate_executable(barretenberg)?;
        require_tool_digest(nargo, digests.nargo, ReleaseTool::Nargo)?;
        require_tool_digest(
            barretenberg,
            digests.barretenberg,
            ReleaseTool::Barretenberg,
        )?;
        Ok(Self {
            nargo,
            barretenberg,
            digests,
        })
    }
}
