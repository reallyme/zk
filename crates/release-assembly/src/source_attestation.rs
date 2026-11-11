// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Source-tree attestation checks for sealed release candidates.

use std::path::Path;

use crate::assembly::circuit_directory;
use crate::source_tree::{validate_directory, SourceTree};
use crate::ReleaseAssemblyError;
use reallyme_zk_artifact_package::{
    noir_source_tree_sha256, ArtifactPackageError, ArtifactPackageErrorReason,
    SealedArtifactPackage, SealedRelease,
};
use reallyme_zk_artifacts::{ArtifactVersion, ProductionArtifactManifest};

/// Recomputes the normalized Noir source identity for every sealed artifact.
///
/// The release index and artifact manifests can be internally consistent even
/// when they were assembled from older circuit sources. Attestation uses this
/// release-SHA checkout check to bind the signed index back to the source tree
/// that reviewers see.
pub fn validate_release_source_attestation(
    workspace_root: &Path,
    release_root: &Path,
    release_version: ArtifactVersion,
) -> Result<(), ReleaseAssemblyError> {
    validate_directory(workspace_root)?;
    validate_directory(release_root)?;
    let release = SealedRelease::load_candidate_and_check(release_root, release_version)?;
    for pin in release.index().artifact_manifests() {
        let package = SealedArtifactPackage::load_and_check(release_root, *pin)?;
        validate_manifest_source_digest(workspace_root, package.manifest())?;
    }
    Ok(())
}

pub(super) fn validate_manifest_source_digest(
    workspace_root: &Path,
    manifest: &ProductionArtifactManifest,
) -> Result<(), ReleaseAssemblyError> {
    let circuit_ref = manifest.circuit_ref();
    let circuit_directory = circuit_directory(
        workspace_root,
        manifest.bundle_kind(),
        circuit_ref.credential_hash_algorithm,
        manifest.stage(),
    );
    let source_tree = SourceTree::load(workspace_root, &circuit_directory)?;
    let source_files = source_tree.borrowed_files()?;
    let current_source_sha256 = noir_source_tree_sha256(&source_files)?;
    if manifest.digests().noir_source_sha256 != current_source_sha256 {
        return Err(ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
