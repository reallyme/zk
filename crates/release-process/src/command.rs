// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed command construction for the pinned release toolchain.

use std::{ffi::OsString, path::PathBuf};

/// External release tool whose version and flags are pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTool {
    /// Noir compiler and witness generator.
    Nargo,
    /// Barretenberg artifact and proof generator.
    Barretenberg,
}

/// Closed set of external operations allowed by release tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseToolOperation {
    /// Query the exact tool version.
    Version,
    /// Compile a Noir circuit with constraint checks enabled.
    Compile,
    /// Execute a Noir circuit to produce a witness.
    Execute,
    /// Generate an UltraHonk verification key.
    WriteVerificationKey,
    /// Generate a zero-knowledge UltraHonk proof.
    Prove,
    /// Verify a zero-knowledge UltraHonk proof.
    Verify,
}

/// One fully specified process request.
///
/// This type intentionally omits `Debug`; executable and working-directory
/// paths can contain local account information.
pub struct ReleaseCommand {
    pub(crate) tool: ReleaseTool,
    pub(crate) operation: ReleaseToolOperation,
    pub(crate) executable: PathBuf,
    pub(crate) current_directory: Option<PathBuf>,
    pub(crate) arguments: Vec<OsString>,
    pub(crate) capture_stdout: bool,
}

impl ReleaseCommand {
    /// Tool selected for this command.
    #[must_use]
    pub const fn tool(&self) -> ReleaseTool {
        self.tool
    }

    /// Closed operation selected for this command.
    #[must_use]
    pub const fn operation(&self) -> ReleaseToolOperation {
        self.operation
    }

    /// Exact ordered argument vector, exposed for audit and test runners.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}
