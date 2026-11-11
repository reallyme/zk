// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Create-new promotion from a checked staging tree into an artifact root.

use std::{ffi::OsStr, fs, path::Path};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::{
    ArtifactKind, ArtifactVersion, CommonCredentialRootArtifactLayout, Digest32,
    PersonaCredentialEvidenceArtifactLayout,
};
use reallyme_zk_proto_codec::{
    release::MAX_ZK_RELEASE_INDEX_BYTES, verification_vector::MAX_ZK_VERIFICATION_VECTOR_SET_BYTES,
};

use crate::{
    package::{
        compare_file, copy_bounded_file_new, copy_sealed_package_new, ensure_directory_chain,
        read_bounded_file, sync_directory,
    },
    release_layout::RELEASE_INDEX_FILE_NAME,
    ArtifactPackageError, ArtifactPackageErrorReason, ReleasePackageLayout, SealedRelease,
};

/// Counts and canonical index identity for one successful promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleasePromotionSummary {
    /// Newly created immutable stage packages.
    pub created_package_count: u32,
    /// Existing content-identical immutable packages reused without writes.
    pub reused_package_count: u32,
    /// Newly created proof-bearing verification-vector files.
    pub vector_set_count: u32,
    /// SHA-256 of the promoted canonical release index.
    pub release_index_sha256: Digest32,
}

/// Checks a complete source release, copies immutable packages without
/// overwrite, and commits the new release by writing `index.pb` last.
///
/// A failed promotion may leave content-addressed packages, immutable
/// common-credential-root files, or a release directory without `index.pb`. None is a
/// readable release. Cleanup and retry are deliberately separate reviewed
/// operations.
pub fn promote_sealed_release_new(
    staging_root: &Path,
    artifact_root: &Path,
    release_version: ArtifactVersion,
    expected_index_sha256: Digest32,
) -> Result<ReleasePromotionSummary, ArtifactPackageError> {
    validate_distinct_canonical_roots(staging_root, artifact_root)?;
    let source_release = SealedRelease::load_candidate_and_check(staging_root, release_version)?;
    if source_release.index_sha256() != expected_index_sha256 {
        return package_mismatch();
    }
    let source_layout = ReleasePackageLayout::try_new(staging_root, release_version)?;
    let destination_layout = ReleasePackageLayout::try_new(artifact_root, release_version)?;
    if destination_layout.directory().try_exists()? {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageAlreadyExists,
        ));
    }

    let mut created_package_count = 0_usize;
    let mut reused_package_count = 0_usize;
    for pin in source_release.index().artifact_manifests() {
        if copy_sealed_package_new(staging_root, artifact_root, *pin)? {
            created_package_count =
                created_package_count
                    .checked_add(1)
                    .ok_or(ArtifactPackageError::new(
                        ArtifactPackageErrorReason::LengthOverflow,
                    ))?;
        } else {
            reused_package_count =
                reused_package_count
                    .checked_add(1)
                    .ok_or(ArtifactPackageError::new(
                        ArtifactPackageErrorReason::LengthOverflow,
                    ))?;
        }
    }

    let destination_parent =
        destination_layout
            .directory()
            .parent()
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
    ensure_directory_chain(artifact_root, destination_parent)?;
    fs::create_dir(destination_layout.directory()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ArtifactPackageError::new(ArtifactPackageErrorReason::PackageAlreadyExists)
        } else {
            ArtifactPackageError::from(error)
        }
    })?;
    let promotion_result = (|| {
        // The index is the commit marker. Copy every pinned common-credential-root input
        // before it so a readable release cannot refer to absent programs.
        copy_common_credential_root_artifacts(&source_release, staging_root, artifact_root)?;
        copy_persona_credential_evidence_artifacts(&source_release, staging_root, artifact_root)?;
        fs::create_dir(destination_layout.vectors())?;

        let mut vector_set_count = 0_usize;
        for pin in source_release.index().verification_vectors() {
            let source = source_layout
                .verification_vector(pin.credential_hash_algorithm(), pin.bundle_kind());
            let destination = destination_layout
                .verification_vector(pin.credential_hash_algorithm(), pin.bundle_kind());
            let directory = destination.parent().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            ensure_directory_chain(&destination_layout.vectors(), directory)?;
            let file_name = destination.file_name().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            copy_bounded_file_new(
                destination_parent,
                &source,
                directory,
                file_name,
                MAX_ZK_VERIFICATION_VECTOR_SET_BYTES,
            )?;
            vector_set_count = vector_set_count
                .checked_add(1)
                .ok_or(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::LengthOverflow,
                ))?;
        }
        sync_directory(&destination_layout.vectors())?;
        copy_bounded_file_new(
            destination_parent,
            &source_layout.index(),
            destination_layout.directory(),
            OsStr::new(RELEASE_INDEX_FILE_NAME),
            MAX_ZK_RELEASE_INDEX_BYTES,
        )?;
        sync_directory(destination_layout.directory())?;

        let promoted = SealedRelease::load_and_check(artifact_root, release_version)?;
        if promoted.index_sha256() != source_release.index_sha256() {
            return package_mismatch();
        }
        Ok((vector_set_count, promoted.index_sha256()))
    })();
    let (vector_set_count, release_index_sha256) = match promotion_result {
        Ok(summary) => summary,
        Err(error) => {
            fs::remove_dir_all(destination_layout.directory())?;
            return Err(error);
        }
    };
    Ok(ReleasePromotionSummary {
        created_package_count: u32::try_from(created_package_count)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
        reused_package_count: u32::try_from(reused_package_count)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
        vector_set_count: u32::try_from(vector_set_count)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?,
        release_index_sha256,
    })
}

const MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES: usize = 64 * 1024;

fn copy_common_credential_root_artifacts(
    source_release: &SealedRelease,
    staging_root: &Path,
    artifact_root: &Path,
) -> Result<(), ArtifactPackageError> {
    for (position, pin) in source_release
        .index()
        .common_credential_root_artifacts()
        .iter()
        .enumerate()
    {
        let source = CommonCredentialRootArtifactLayout::try_new(staging_root, pin.circuit_ref())?;
        let destination =
            CommonCredentialRootArtifactLayout::try_new(artifact_root, pin.circuit_ref())?;
        if position == 0 {
            copy_or_verify_bounded_file(
                artifact_root,
                &source.source_lock(),
                &destination.source_lock(),
                MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES,
            )?;
        }
        copy_or_verify_bounded_file(
            artifact_root,
            &source.program(),
            &destination.program(),
            ArtifactKind::AcirBytecode.max_bytes(),
        )?;
        copy_or_verify_bounded_file(
            artifact_root,
            &source.verification_key(),
            &destination.verification_key(),
            ArtifactKind::VerificationKey.max_bytes(),
        )?;
    }
    Ok(())
}

fn copy_persona_credential_evidence_artifacts(
    source_release: &SealedRelease,
    staging_root: &Path,
    artifact_root: &Path,
) -> Result<(), ArtifactPackageError> {
    for (position, pin) in source_release
        .index()
        .persona_credential_evidence_artifacts()
        .iter()
        .enumerate()
    {
        let source =
            PersonaCredentialEvidenceArtifactLayout::try_new(staging_root, pin.circuit_ref())?;
        let destination =
            PersonaCredentialEvidenceArtifactLayout::try_new(artifact_root, pin.circuit_ref())?;
        if position == 0 {
            copy_or_verify_bounded_file(
                artifact_root,
                &source.source_lock(),
                &destination.source_lock(),
                MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES,
            )?;
        }
        copy_or_verify_bounded_file(
            artifact_root,
            &source.program(),
            &destination.program(),
            ArtifactKind::AcirBytecode.max_bytes(),
        )?;
        copy_or_verify_bounded_file(
            artifact_root,
            &source.verification_key(),
            &destination.verification_key(),
            ArtifactKind::VerificationKey.max_bytes(),
        )?;
    }
    Ok(())
}

fn copy_or_verify_bounded_file(
    artifact_root: &Path,
    source: &Path,
    destination: &Path,
    maximum: usize,
) -> Result<(), ArtifactPackageError> {
    let directory = destination.parent().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidRelativePath,
    ))?;
    let file_name = destination.file_name().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidRelativePath,
    ))?;
    ensure_directory_chain(artifact_root, directory)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => {
            // Immutable files may be shared by successive releases only when
            // the bytes agree exactly; a path collision never replaces them.
            let source_bytes = read_bounded_file(source, maximum)?;
            compare_file(destination, &source_bytes, maximum)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            copy_bounded_file_new(artifact_root, source, directory, file_name, maximum)
        }
        Err(error) => Err(ArtifactPackageError::from(error)),
    }
}

fn validate_distinct_canonical_roots(
    staging_root: &Path,
    artifact_root: &Path,
) -> Result<(), ArtifactPackageError> {
    let source = canonical_directory(staging_root)?;
    let destination = canonical_directory(artifact_root)?;
    if source == destination {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidArguments,
        ));
    }
    Ok(())
}

pub(crate) fn canonical_directory(path: &Path) -> Result<std::path::PathBuf, ArtifactPackageError> {
    if !path.is_absolute() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return package_mismatch();
    }
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return package_mismatch();
    }
    Ok(canonical)
}

fn package_mismatch<T>() -> Result<T, ArtifactPackageError> {
    Err(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMismatch,
    ))
}

#[cfg(test)]
mod tests;
