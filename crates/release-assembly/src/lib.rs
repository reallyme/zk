// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resumable assembly of real ZK proving vectors and stage artifact packages.

mod assembly;
mod error;
mod source_attestation;
mod source_tree;
#[cfg(test)]
mod tests;

pub use assembly::{
    assemble_production_packages, ProductionAssemblyPaths, ProductionAssemblySummary,
};
pub use error::{ReleaseAssemblyError, ReleaseAssemblyErrorReason};
pub use source_attestation::validate_release_source_attestation;
