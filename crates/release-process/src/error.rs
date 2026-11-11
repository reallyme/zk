// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Privacy-safe release-process errors.

use thiserror::Error;

use crate::{ReleaseTool, ReleaseToolOperation};

/// Closed class of verified release output files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutputKind {
    /// Serialized witness stack emitted by the pinned Noir executor.
    Witness,
    /// Pinned Nargo compiled-program JSON.
    CompiledProgram,
    /// Barretenberg verification key.
    VerificationKey,
    /// Barretenberg proof bytes.
    Proof,
    /// Flattened Barretenberg public field elements.
    PublicInputs,
}

/// Stable reason for a release-process failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseProcessErrorReason {
    /// The executable adapter received the wrong number of opaque path inputs.
    InvalidArguments,
    /// A configured executable or working path violated the path policy.
    InvalidPath,
    /// A filesystem operation failed without retaining its path.
    Filesystem(std::io::ErrorKind),
    /// A generated witness could not be overwritten and removed.
    SensitiveFileCleanup(std::io::ErrorKind),
    /// The operating system could not start or wait for a pinned tool.
    ProcessIo {
        /// Tool whose process operation failed.
        tool: ReleaseTool,
        /// Operation being performed.
        operation: ReleaseToolOperation,
        /// Stable operating-system error class.
        kind: std::io::ErrorKind,
    },
    /// A pinned tool returned a non-success status.
    ProcessFailed {
        /// Tool that failed.
        tool: ReleaseTool,
        /// Operation that failed.
        operation: ReleaseToolOperation,
    },
    /// A pinned tool exceeded the fixed release-process deadline.
    ProcessTimedOut {
        /// Tool that exceeded the deadline.
        tool: ReleaseTool,
        /// Operation that exceeded the deadline.
        operation: ReleaseToolOperation,
    },
    /// Version output exceeded the explicit bound.
    VersionOutputTooLarge(ReleaseTool),
    /// Version output did not match the exact approved release.
    VersionMismatch(ReleaseTool),
    /// Executable bytes did not match the caller-supplied SHA-256 identity.
    ToolDigestMismatch(ReleaseTool),
    /// The modern Barretenberg CRS is missing or differs from the pinned full-prover identity.
    CrsIdentityMismatch,
    /// The requested proof suite is not implemented by the pinned toolchain.
    UnsupportedProofSuite,
    /// A compiled Noir program artifact was empty, oversized, or malformed.
    MalformedCompiledArtifact,
    /// A compiled artifact did not record the pinned Noirc build.
    CompiledArtifactToolchainMismatch,
    /// Two artifacts differed in execution-relevant ABI or bytecode.
    CompiledArtifactExecutionMismatch,
    /// A verified release output was empty, oversized, malformed, or changed
    /// while it was being admitted into a bounded owner.
    InvalidReleaseOutput(ReleaseOutputKind),
}

/// Typed, path-free release-process error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ReallyMe ZK release process failed")]
pub struct ReleaseProcessError {
    reason: ReleaseProcessErrorReason,
}

impl ReleaseProcessError {
    /// Creates an error from one stable reason.
    #[must_use]
    pub const fn new(reason: ReleaseProcessErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable reason without command output or filesystem paths.
    #[must_use]
    pub const fn reason(&self) -> ReleaseProcessErrorReason {
        self.reason
    }
}

impl From<std::io::Error> for ReleaseProcessError {
    fn from(error: std::io::Error) -> Self {
        Self::new(ReleaseProcessErrorReason::Filesystem(error.kind()))
    }
}
