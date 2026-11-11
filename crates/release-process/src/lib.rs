// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pinned, typed external-tool boundary for deterministic release generation.

mod artifact_compatibility;
mod command;
mod error;
mod generation;
mod process;
mod proof_cycle;
mod proof_material;
mod runner;

pub use artifact_compatibility::{
    ensure_compiled_program_execution_compatible, normalize_compiled_program_artifact,
    normalize_modern_compiled_program_artifact, validate_compiled_program_artifact,
    MAX_COMPILED_PROGRAM_ARTIFACT_BYTES,
};
pub use command::{ReleaseCommand, ReleaseTool, ReleaseToolOperation};
pub use error::{ReleaseOutputKind, ReleaseProcessError, ReleaseProcessErrorReason};
pub use generation::{ReleaseGenerationPaths, ReleaseWitnessMaterialPaths};
pub(crate) use process::{validate_directory, validate_regular_file};
pub use process::{
    PinnedReleaseProcess, ReleaseToolDigests, ReleaseToolPaths, ReleaseToolchainProfile,
    MODERN_CANDIDATE_BARRETENBERG_VERSION, MODERN_CANDIDATE_NARGO_VERSION,
    MODERN_CANDIDATE_NOIRC_GIT_COMMIT, PINNED_BARRETENBERG_VERSION, PINNED_NARGO_VERSION,
    PINNED_NOIRC_GIT_COMMIT,
};
pub use proof_cycle::{
    CompletedReleaseProofCycle, ExistingReleaseProofPaths, ReleaseProofCyclePaths,
};
pub use proof_material::{CompletedReleaseProofMaterial, CompletedReleaseProvingMaterial};
pub use runner::{
    ReleaseProcessOutput, ReleaseProcessRunner, SystemReleaseProcessRunner,
    MAX_RELEASE_TOOL_VERSION_OUTPUT_BYTES,
};
