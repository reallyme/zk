// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Admission of one complete sealed release from an untrusted staging tree.

use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::{
    common_credential_root_source_closure_from_lock, ArtifactKind, ArtifactPackageLayout,
    ArtifactVersion, CommonCredentialRootArtifactLayout, Digest32,
    PersonaCredentialEvidenceArtifactLayout,
};
use reallyme_zk_proto_codec::{
    release::{decode_release_index, ReleaseIndex, MAX_ZK_RELEASE_INDEX_BYTES},
    verification_vector::{decode_verification_vector_set, MAX_ZK_VERIFICATION_VECTOR_SET_BYTES},
};

use crate::{
    package::{collect_vector_paths, read_bounded_file},
    release::validate_release_entries,
    ArtifactPackageError, ArtifactPackageErrorReason, ReleasePackageLayout, SealedArtifactPackage,
};

const ARTIFACTS_PER_VECTOR_SET: usize = 4;
const MAX_SEALED_RELEASE_TREE_ENTRIES: usize = 4_096;
const MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES: usize = 64 * 1024;

/// Complete manifest, artifact, and post-manifest-vector release admitted from
/// persistent storage.
///
/// Host paths and proof-bearing vector bytes are deliberately not retained.
pub struct SealedRelease {
    index: ReleaseIndex,
    index_sha256: Digest32,
}

impl SealedRelease {
    /// Loads and checks one complete release beneath an explicit absolute
    /// staging root.
    pub fn load_and_check(
        staging_root: &Path,
        release_version: ArtifactVersion,
    ) -> Result<Self, ArtifactPackageError> {
        validate_absolute_directory(staging_root)?;
        let layout = ReleasePackageLayout::try_new(staging_root, release_version)?;
        validate_derived_directories(staging_root, layout.directory())?;
        validate_release_entries(&layout)?;

        let index_bytes = read_bounded_file(&layout.index(), MAX_ZK_RELEASE_INDEX_BYTES)?;
        let index_sha256 = Digest32::sha256(&index_bytes);
        let index = decode_release_index(&index_bytes)?;
        if index.release_version() != release_version {
            return package_mismatch();
        }

        for pin in index.artifact_manifests() {
            let package = SealedArtifactPackage::load_and_check(staging_root, *pin)?;
            let manifest = package.manifest();
            if manifest.toolchain() != index.toolchain()
                || manifest.proof_suite() != index.proof_suite()
                || manifest.digests().capability_registry_sha256
                    != index.capability_registry_sha256()
            {
                return package_mismatch();
            }
        }

        for pin in index.common_credential_root_artifacts() {
            let artifact_layout =
                CommonCredentialRootArtifactLayout::try_new(staging_root, pin.circuit_ref())?;
            validate_derived_directories(staging_root, artifact_layout.directory())?;
            let source_lock = read_bounded_file(
                &artifact_layout.source_lock(),
                MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES,
            )?;
            let bytecode = read_bounded_file(
                &artifact_layout.program(),
                ArtifactKind::AcirBytecode.max_bytes(),
            )?;
            let verification_key = read_bounded_file(
                &artifact_layout.verification_key(),
                ArtifactKind::VerificationKey.max_bytes(),
            )?;
            if !pin.source_lock_sha256().matches_sha256(&source_lock)
                || common_credential_root_source_closure_from_lock(&source_lock, pin.circuit_ref())?
                    != pin.source_closure_sha256()
                || !pin.bytecode_sha256().matches_sha256(&bytecode)
                || !pin
                    .verification_key_sha256()
                    .matches_sha256(&verification_key)
            {
                return package_mismatch();
            }
        }

        for pin in index.persona_credential_evidence_artifacts() {
            let artifact_layout =
                PersonaCredentialEvidenceArtifactLayout::try_new(staging_root, pin.circuit_ref())?;
            validate_derived_directories(staging_root, artifact_layout.directory())?;
            let source_lock = read_bounded_file(
                &artifact_layout.source_lock(),
                MAX_COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_BYTES,
            )?;
            let bytecode = read_bounded_file(
                &artifact_layout.program(),
                ArtifactKind::AcirBytecode.max_bytes(),
            )?;
            let verification_key = read_bounded_file(
                &artifact_layout.verification_key(),
                ArtifactKind::VerificationKey.max_bytes(),
            )?;
            if !pin.source_lock_sha256().matches_sha256(&source_lock)
                || common_credential_root_source_closure_from_lock(&source_lock, pin.circuit_ref())?
                    != pin.source_closure_sha256()
                || !pin.bytecode_sha256().matches_sha256(&bytecode)
                || !pin
                    .verification_key_sha256()
                    .matches_sha256(&verification_key)
            {
                return package_mismatch();
            }
        }

        for (position, pin) in index.verification_vectors().iter().enumerate() {
            let path =
                layout.verification_vector(pin.credential_hash_algorithm(), pin.bundle_kind());
            let bytes = read_bounded_file(&path, MAX_ZK_VERIFICATION_VECTOR_SET_BYTES)?;
            if !pin.vector_set_sha256().matches_sha256(&bytes) {
                return package_mismatch();
            }
            let vector_set = decode_verification_vector_set(&bytes)?;
            let vector_count = u32::try_from(vector_set.vectors().len())
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
            if vector_set.bundle_kind() != pin.bundle_kind()
                || vector_set.credential_hash_algorithm() != pin.credential_hash_algorithm()
                || vector_set.proof_suite() != pin.proof_suite()
                || vector_count != pin.vector_count()
            {
                return package_mismatch();
            }
            let artifact_start = position
                .checked_mul(ARTIFACTS_PER_VECTOR_SET)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            let artifact_end = artifact_start
                .checked_add(ARTIFACTS_PER_VECTOR_SET)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
            let expected_artifacts = index
                .artifact_manifests()
                .get(artifact_start..artifact_end)
                .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
            if vector_set.artifact_manifests() != expected_artifacts {
                return package_mismatch();
            }
        }

        Ok(Self {
            index,
            index_sha256,
        })
    }

    /// Loads one candidate release from a dedicated staging root and rejects
    /// every file or directory outside the exact referenced release graph.
    ///
    /// Artifact repositories may legitimately contain several releases, so
    /// ordinary runtime admission is graph-scoped. Promotion uses this stricter
    /// entry point because its staging root is required to contain exactly one
    /// reviewed candidate and no unreviewed sibling payloads.
    pub fn load_candidate_and_check(
        staging_root: &Path,
        release_version: ArtifactVersion,
    ) -> Result<Self, ArtifactPackageError> {
        let candidate_index = load_candidate_index_for_exact_tree(staging_root, release_version)?;
        validate_candidate_root_entries(staging_root, release_version, &candidate_index)?;
        let release = Self::load_and_check(staging_root, release_version)?;
        validate_exact_candidate_tree(staging_root, release_version, &release.index)?;
        Ok(release)
    }

    /// Validated canonical release index.
    #[must_use]
    pub const fn index(&self) -> &ReleaseIndex {
        &self.index
    }

    /// SHA-256 of the exact canonical index bytes admitted from storage.
    #[must_use]
    pub const fn index_sha256(&self) -> Digest32 {
        self.index_sha256
    }
}

fn load_candidate_index_for_exact_tree(
    staging_root: &Path,
    release_version: ArtifactVersion,
) -> Result<ReleaseIndex, ArtifactPackageError> {
    validate_absolute_directory(staging_root)?;
    let layout = ReleasePackageLayout::try_new(staging_root, release_version)?;
    validate_derived_directories(staging_root, layout.directory())?;
    let index_bytes = read_bounded_file(&layout.index(), MAX_ZK_RELEASE_INDEX_BYTES)?;
    let index = decode_release_index(&index_bytes)?;
    if index.release_version() != release_version {
        return package_mismatch();
    }
    Ok(index)
}

fn validate_exact_candidate_tree(
    root: &Path,
    release_version: ArtifactVersion,
    index: &ReleaseIndex,
) -> Result<(), ArtifactPackageError> {
    let release_layout = ReleasePackageLayout::try_new(root, release_version)?;
    let mut expected_files = BTreeSet::new();
    add_expected_file(root, &release_layout.index(), &mut expected_files)?;
    for pin in index.verification_vectors() {
        add_expected_file(
            root,
            &release_layout.verification_vector(pin.credential_hash_algorithm(), pin.bundle_kind()),
            &mut expected_files,
        )?;
    }

    for pin in index.artifact_manifests() {
        let circuit_ref = pin.circuit_ref();
        let package_layout = ArtifactPackageLayout::try_new(
            root,
            circuit_ref.credential_hash_algorithm,
            pin.bundle_kind(),
            pin.stage(),
            pin.manifest_sha256(),
        )?;
        add_expected_file(root, &package_layout.manifest(), &mut expected_files)?;
        add_expected_file(root, &package_layout.program(), &mut expected_files)?;
        add_expected_file(
            root,
            &package_layout.verification_key(),
            &mut expected_files,
        )?;

        let mut vector_paths = Vec::new();
        collect_vector_paths(
            &package_layout.vectors(),
            &package_layout.vectors(),
            &mut vector_paths,
        )?;
        for relative_path in vector_paths {
            add_expected_file(
                root,
                &package_layout.vectors().join(relative_path),
                &mut expected_files,
            )?;
        }
    }

    for (position, pin) in index.common_credential_root_artifacts().iter().enumerate() {
        let layout = CommonCredentialRootArtifactLayout::try_new(root, pin.circuit_ref())?;
        add_expected_file(root, &layout.program(), &mut expected_files)?;
        add_expected_file(root, &layout.verification_key(), &mut expected_files)?;
        if position == 0 {
            add_expected_file(root, &layout.source_lock(), &mut expected_files)?;
        }
    }
    for (position, pin) in index
        .persona_credential_evidence_artifacts()
        .iter()
        .enumerate()
    {
        let layout = PersonaCredentialEvidenceArtifactLayout::try_new(root, pin.circuit_ref())?;
        add_expected_file(root, &layout.program(), &mut expected_files)?;
        add_expected_file(root, &layout.verification_key(), &mut expected_files)?;
        if position == 0 {
            add_expected_file(root, &layout.source_lock(), &mut expected_files)?;
        }
    }

    let expected_directories = expected_directories(root, &expected_files)?;
    let mut observed_entry_count = 0_usize;
    validate_candidate_directory(
        root,
        root,
        &expected_files,
        &expected_directories,
        &mut observed_entry_count,
    )?;
    Ok(())
}

fn validate_candidate_root_entries(
    root: &Path,
    release_version: ArtifactVersion,
    index: &ReleaseIndex,
) -> Result<(), ArtifactPackageError> {
    let mut expected = BTreeSet::new();
    let release_layout = ReleasePackageLayout::try_new(root, release_version)?;
    add_first_relative_component(root, release_layout.directory(), &mut expected)?;
    for pin in index.artifact_manifests() {
        let package_layout = ArtifactPackageLayout::try_new(
            root,
            pin.circuit_ref().credential_hash_algorithm,
            pin.bundle_kind(),
            pin.stage(),
            pin.manifest_sha256(),
        )?;
        add_first_relative_component(root, package_layout.directory(), &mut expected)?;
    }
    if let Some(pin) = index.common_credential_root_artifacts().first() {
        let layout = CommonCredentialRootArtifactLayout::try_new(root, pin.circuit_ref())?;
        add_first_relative_component(root, layout.directory(), &mut expected)?;
    }
    if let Some(pin) = index.persona_credential_evidence_artifacts().first() {
        let layout = PersonaCredentialEvidenceArtifactLayout::try_new(root, pin.circuit_ref())?;
        add_first_relative_component(root, layout.directory(), &mut expected)?;
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_dir() || file_type.is_symlink() || !expected.contains(&entry.file_name()) {
            return package_mismatch();
        }
    }
    Ok(())
}

fn add_first_relative_component(
    root: &Path,
    path: &Path,
    expected: &mut BTreeSet<std::ffi::OsString>,
) -> Result<(), ArtifactPackageError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch))?;
    let Some(component) = relative.components().next() else {
        return package_mismatch();
    };
    let Component::Normal(name) = component else {
        return package_mismatch();
    };
    if expected.len() >= MAX_SEALED_RELEASE_TREE_ENTRIES {
        return package_mismatch();
    }
    expected.insert(name.to_os_string());
    Ok(())
}

fn add_expected_file(
    root: &Path,
    path: &Path,
    expected: &mut BTreeSet<PathBuf>,
) -> Result<(), ArtifactPackageError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch))?;
    if relative.as_os_str().is_empty() || expected.len() >= MAX_SEALED_RELEASE_TREE_ENTRIES {
        return package_mismatch();
    }
    if !expected.insert(relative.to_path_buf()) {
        return package_mismatch();
    }
    Ok(())
}

fn expected_directories(
    root: &Path,
    files: &BTreeSet<PathBuf>,
) -> Result<BTreeSet<PathBuf>, ArtifactPackageError> {
    let mut directories = BTreeSet::new();
    for file in files {
        let mut parent = file.parent();
        while let Some(relative) = parent {
            if relative.as_os_str().is_empty() {
                break;
            }
            if directories.len() >= MAX_SEALED_RELEASE_TREE_ENTRIES {
                return package_mismatch();
            }
            directories.insert(relative.to_path_buf());
            parent = relative.parent();
        }
    }
    if root.as_os_str().is_empty() {
        return package_mismatch();
    }
    Ok(directories)
}

fn validate_candidate_directory(
    root: &Path,
    directory: &Path,
    expected_files: &BTreeSet<PathBuf>,
    expected_directories: &BTreeSet<PathBuf>,
    observed_entry_count: &mut usize,
) -> Result<(), ArtifactPackageError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        *observed_entry_count =
            observed_entry_count
                .checked_add(1)
                .ok_or(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::LengthOverflow,
                ))?;
        if *observed_entry_count > MAX_SEALED_RELEASE_TREE_ENTRIES {
            return package_mismatch();
        }
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch))?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return package_mismatch();
        }
        if file_type.is_dir() {
            if !expected_directories.contains(relative) {
                return package_mismatch();
            }
            validate_candidate_directory(
                root,
                &path,
                expected_files,
                expected_directories,
                observed_entry_count,
            )?;
        } else if !file_type.is_file() || !expected_files.contains(relative) {
            return package_mismatch();
        }
    }
    Ok(())
}

fn validate_derived_directories(root: &Path, directory: &Path) -> Result<(), ArtifactPackageError> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return package_mismatch();
        };
        current.push(component);
        validate_directory(&current)?;
    }
    Ok(())
}

fn validate_absolute_directory(path: &Path) -> Result<(), ArtifactPackageError> {
    if !path.is_absolute() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ));
    }
    validate_directory(path)
}

fn validate_directory(path: &Path) -> Result<(), ArtifactPackageError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMissing)
        } else {
            ArtifactPackageError::from(error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return package_mismatch();
    }
    Ok(())
}

fn package_mismatch<T>() -> Result<T, ArtifactPackageError> {
    Err(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMismatch,
    ))
}

#[cfg(test)]
mod tests;
