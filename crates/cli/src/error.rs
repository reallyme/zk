// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io;

use thiserror::Error;

/// Stable process status for CLI execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliExit {
    /// Command completed successfully.
    Success,
    /// Command failed because input or repository state was invalid.
    Failure,
    /// Command-line syntax was invalid.
    Usage,
}

impl CliExit {
    /// Converts the stable status to a process exit code.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
        }
    }
}

/// Domain-specific CLI failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliErrorReason {
    /// The requested command is not supported.
    UnknownCommand,
    /// The command received more arguments than its typed contract accepts.
    UnexpectedArgument,
    /// A write to stdout or stderr failed.
    OutputUnavailable,
    /// The compiled repository registry or lock file failed a self-check.
    RepositoryPolicyMismatch,
    /// Required input was absent or malformed.
    InvalidInput,
    /// File-system I/O failed without exposing host path details.
    IoUnavailable,
    /// An input exceeded the command's bounded admission policy.
    InputTooLarge,
    /// The requested output path already exists.
    OutputAlreadyExists,
    /// Witness generation failed before proving.
    WitnessFailed,
    /// Canonical artifact or proof validation failed.
    ArtifactValidationFailed,
    /// This build has no linked proving or verification backend.
    BackendUnavailable,
    /// The linked proving backend is unavailable or rejected the request.
    BackendFailed,
    /// The proof failed verification.
    VerificationFailed,
}

/// Typed CLI error with no caller-provided strings.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("{reason}")]
pub struct CliError {
    reason: CliErrorReason,
}

impl CliError {
    /// Creates a typed CLI error.
    #[must_use]
    pub const fn new(reason: CliErrorReason) -> Self {
        Self { reason }
    }

    /// Returns the stable reason.
    #[must_use]
    pub const fn reason(self) -> CliErrorReason {
        self.reason
    }
}

impl core::fmt::Display for CliErrorReason {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl CliErrorReason {
    /// Stable kebab-case reason code for human CLI output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCommand => "unknown-command",
            Self::UnexpectedArgument => "unexpected-argument",
            Self::OutputUnavailable => "output-unavailable",
            Self::RepositoryPolicyMismatch => "repository-policy-mismatch",
            Self::InvalidInput => "invalid-input",
            Self::IoUnavailable => "io-unavailable",
            Self::InputTooLarge => "input-too-large",
            Self::OutputAlreadyExists => "output-already-exists",
            Self::WitnessFailed => "witness-failed",
            Self::ArtifactValidationFailed => "artifact-validation-failed",
            Self::BackendUnavailable => "backend-unavailable",
            Self::BackendFailed => "backend-failed",
            Self::VerificationFailed => "verification-failed",
        }
    }
}

impl From<io::Error> for CliError {
    fn from(_error: io::Error) -> Self {
        Self::new(CliErrorReason::OutputUnavailable)
    }
}
