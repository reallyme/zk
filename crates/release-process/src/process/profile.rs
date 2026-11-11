// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{ReleaseProcessError, ReleaseProcessErrorReason, ReleaseTool};
use reallyme_zk_artifacts::ArtifactToolchain;

/// Exact Nargo version approved for the v1 circuit ABI.
pub const PINNED_NARGO_VERSION: &str = "1.0.0";
/// Exact Barretenberg version approved for artifact generation.
pub const PINNED_BARRETENBERG_VERSION: &str = "6.0.0";
/// Exact reviewed upstream Noirc commit used by the typed witness bindings.
pub const PINNED_NOIRC_GIT_COMMIT: &str = "275d3ab1a5c916c6ea73e8d6b943f685f574500c";
/// Exact Nargo version selected by the explicit toolchain profile.
pub const MODERN_CANDIDATE_NARGO_VERSION: &str = "1.0.0";
/// Exact Barretenberg version selected by the explicit toolchain profile.
pub const MODERN_CANDIDATE_BARRETENBERG_VERSION: &str = "6.0.0";
/// Exact upstream Noirc commit selected by the explicit toolchain profile.
pub const MODERN_CANDIDATE_NOIRC_GIT_COMMIT: &str = "275d3ab1a5c916c6ea73e8d6b943f685f574500c";

pub(crate) const PINNED_NARGO_VERSION_LINE: &[u8] = b"nargo version = 1.0.0";
pub(crate) const PINNED_NOIRC_VERSION_LINE: &[u8] =
    b"noirc version = 1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c";
pub(crate) const PINNED_BARRETENBERG_VERSION_LINE: &[u8] = b"6.0.0";
pub(crate) const MODERN_CANDIDATE_NARGO_VERSION_LINE: &[u8] = b"nargo version = 1.0.0";
pub(crate) const MODERN_CANDIDATE_NOIRC_VERSION_LINE: &[u8] =
    b"noirc version = 1.0.0+275d3ab1a5c916c6ea73e8d6b943f685f574500c";
pub(crate) const MODERN_CANDIDATE_BARRETENBERG_VERSION_LINE: &[u8] = b"6.0.0";

/// Explicit release-toolchain lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseToolchainProfile {
    /// Deprecated selector retained for older callers; uses the current pinned
    /// production toolchain and command shape.
    LegacyProduction,
    /// Explicit selector for the reviewed Noir/Barretenberg pair.
    ModernCandidate,
}

impl ReleaseToolchainProfile {
    pub(crate) fn toolchain(self) -> Result<ArtifactToolchain, ReleaseProcessError> {
        let (nargo, barretenberg) = match self {
            Self::LegacyProduction => (PINNED_NARGO_VERSION, PINNED_BARRETENBERG_VERSION),
            Self::ModernCandidate => (
                MODERN_CANDIDATE_NARGO_VERSION,
                MODERN_CANDIDATE_BARRETENBERG_VERSION,
            ),
        };
        ArtifactToolchain::try_from_versions(nargo, barretenberg).map_err(|_| {
            ReleaseProcessError::new(ReleaseProcessErrorReason::VersionMismatch(
                ReleaseTool::Nargo,
            ))
        })
    }

    pub(crate) const fn nargo_version_line(self) -> &'static [u8] {
        match self {
            Self::LegacyProduction => PINNED_NARGO_VERSION_LINE,
            Self::ModernCandidate => MODERN_CANDIDATE_NARGO_VERSION_LINE,
        }
    }

    pub(crate) const fn noirc_version_line(self) -> &'static [u8] {
        match self {
            Self::LegacyProduction => PINNED_NOIRC_VERSION_LINE,
            Self::ModernCandidate => MODERN_CANDIDATE_NOIRC_VERSION_LINE,
        }
    }

    pub(crate) const fn barretenberg_version_line(self) -> &'static [u8] {
        match self {
            Self::LegacyProduction => PINNED_BARRETENBERG_VERSION_LINE,
            Self::ModernCandidate => MODERN_CANDIDATE_BARRETENBERG_VERSION_LINE,
        }
    }
}
