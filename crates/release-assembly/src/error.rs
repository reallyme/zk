// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Privacy-safe release-assembly errors.

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifact_package::{ArtifactPackageError, ArtifactPackageErrorReason};
use reallyme_zk_release_process::{ReleaseProcessError, ReleaseProcessErrorReason};
use thiserror::Error;

/// Stable reason for release-assembly failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseAssemblyErrorReason {
    /// CLI or typed path arguments were missing or malformed.
    InvalidArguments,
    /// A root, circuit, retained output, or source path violated policy.
    InvalidPath,
    /// A filesystem operation failed without retaining its path.
    Filesystem(std::io::ErrorKind),
    /// Exact ZK-domain validation failed.
    Domain(ZkErrorReason),
    /// Pinned witness or proof processing failed.
    ReleaseProcess(ReleaseProcessErrorReason),
    /// Artifact package construction or persistence failed.
    ArtifactPackage(ArtifactPackageErrorReason),
    /// A bounded count, size, or offset calculation overflowed.
    LengthOverflow,
}

/// Typed, path-free release-assembly error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ReallyMe ZK release assembly failed")]
pub struct ReleaseAssemblyError {
    reason: ReleaseAssemblyErrorReason,
}

impl ReleaseAssemblyError {
    /// Creates an error from one stable reason.
    #[must_use]
    pub const fn new(reason: ReleaseAssemblyErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable reason without paths or sensitive bytes.
    #[must_use]
    pub const fn reason(&self) -> ReleaseAssemblyErrorReason {
        self.reason
    }
}

impl From<std::io::Error> for ReleaseAssemblyError {
    fn from(error: std::io::Error) -> Self {
        Self::new(ReleaseAssemblyErrorReason::Filesystem(error.kind()))
    }
}

impl From<ZkError> for ReleaseAssemblyError {
    fn from(error: ZkError) -> Self {
        Self::new(ReleaseAssemblyErrorReason::Domain(error.reason()))
    }
}

impl From<ReleaseProcessError> for ReleaseAssemblyError {
    fn from(error: ReleaseProcessError) -> Self {
        Self::new(ReleaseAssemblyErrorReason::ReleaseProcess(error.reason()))
    }
}

impl From<ArtifactPackageError> for ReleaseAssemblyError {
    fn from(error: ArtifactPackageError) -> Self {
        Self::new(ReleaseAssemblyErrorReason::ArtifactPackage(error.reason()))
    }
}
