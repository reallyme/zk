// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Privacy-safe errors for deterministic artifact packaging.

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use thiserror::Error;

/// Stable reason for a release artifact package failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactPackageErrorReason {
    /// A release-tool invocation omitted, duplicated, or malformed arguments.
    InvalidArguments,
    /// A package-relative path was empty, absolute, non-UTF-8, or traversing.
    InvalidRelativePath,
    /// Caller-supplied files were not in strict canonical lexical order.
    NonCanonicalFileOrder,
    /// A file set or individual file exceeded its explicit bound.
    InputTooLarge,
    /// An input required for package identity was empty.
    EmptyInput,
    /// A checked length calculation or conversion overflowed.
    LengthOverflow,
    /// Domain manifest validation or sealing failed.
    Domain(ZkErrorReason),
    /// The destination package already exists and will not be overwritten.
    PackageAlreadyExists,
    /// A required package path does not exist.
    PackageMissing,
    /// Persisted package bytes differ from the canonical expected package.
    PackageMismatch,
    /// Recovery was refused because the release already has its commit marker.
    ReleaseAlreadyCommitted,
    /// Recovery was refused because preserved evidence already occupies the slot.
    RecoveryDestinationAlreadyExists,
    /// A release commit marker appeared while recovery was moving the directory.
    ReleaseChangedDuringRecovery,
    /// A filesystem operation failed without retaining a sensitive path.
    Filesystem(std::io::ErrorKind),
}

/// Typed, privacy-safe artifact package error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ReallyMe ZK artifact package operation failed")]
pub struct ArtifactPackageError {
    reason: ArtifactPackageErrorReason,
}

impl ArtifactPackageError {
    /// Creates an error from a stable reason.
    #[must_use]
    pub const fn new(reason: ArtifactPackageErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable reason without path or artifact contents.
    #[must_use]
    pub const fn reason(&self) -> ArtifactPackageErrorReason {
        self.reason
    }
}

impl From<ZkError> for ArtifactPackageError {
    fn from(error: ZkError) -> Self {
        Self::new(ArtifactPackageErrorReason::Domain(error.reason()))
    }
}

impl From<std::io::Error> for ArtifactPackageError {
    fn from(error: std::io::Error) -> Self {
        Self::new(ArtifactPackageErrorReason::Filesystem(error.kind()))
    }
}
