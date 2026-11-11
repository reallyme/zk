// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Closed filesystem layouts for full release candidates and public runtime packs.

use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

use reallyme_zk_artifacts::{
    ArtifactPackageLayout, ArtifactVersion, CommonCredentialRootArtifactLayout,
    PersonaCredentialEvidenceArtifactLayout,
};
use reallyme_zk_proto_codec::release::ReleaseIndex;

use super::{RuntimeContents, MAX_MOBILE_RUNTIME_TREE_ENTRIES};
use crate::{
    candidate_util::package_mismatch, package::collect_vector_paths, ArtifactPackageError,
    ArtifactPackageErrorReason, ReleasePackageLayout,
};

pub(super) fn validate_mobile_runtime_root_entries(
    root: &Path,
    release_version: ArtifactVersion,
    index: &ReleaseIndex,
) -> Result<(), ArtifactPackageError> {
    let mut expected = BTreeSet::new();
    let release_layout = ReleasePackageLayout::try_new(root, release_version)?;
    add_first_relative_component(root, release_layout.directory(), &mut expected)?;
    if let Some(pin) = index.artifact_manifests().first() {
        let circuit_ref = pin.circuit_ref();
        let layout = ArtifactPackageLayout::try_new(
            root,
            circuit_ref.credential_hash_algorithm,
            pin.bundle_kind(),
            pin.stage(),
            pin.manifest_sha256(),
        )?;
        add_first_relative_component(root, layout.directory(), &mut expected)?;
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

pub(super) fn validate_mobile_runtime_exact_tree(
    root: &Path,
    release_version: ArtifactVersion,
    index: &ReleaseIndex,
    contents: RuntimeContents,
) -> Result<(), ArtifactPackageError> {
    let release_layout = ReleasePackageLayout::try_new(root, release_version)?;
    let mut expected_files = BTreeSet::new();
    add_expected_file(root, &release_layout.index(), &mut expected_files)?;
    if matches!(contents, RuntimeContents::CompleteRelease) {
        for pin in index.verification_vectors() {
            add_expected_file(
                root,
                &release_layout
                    .verification_vector(pin.credential_hash_algorithm(), pin.bundle_kind()),
                &mut expected_files,
            )?;
        }
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

        if matches!(contents, RuntimeContents::CompleteRelease) {
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
    let expected_directories = expected_directories(&expected_files)?;
    let mut observed_entry_count = 0_usize;
    validate_mobile_runtime_directory(
        root,
        root,
        &expected_files,
        &expected_directories,
        &mut observed_entry_count,
    )
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
    if expected.len() >= MAX_MOBILE_RUNTIME_TREE_ENTRIES {
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
    if relative.as_os_str().is_empty() || expected.len() >= MAX_MOBILE_RUNTIME_TREE_ENTRIES {
        return package_mismatch();
    }
    if !expected.insert(relative.to_path_buf()) {
        return package_mismatch();
    }
    Ok(())
}

fn expected_directories(
    files: &BTreeSet<PathBuf>,
) -> Result<BTreeSet<PathBuf>, ArtifactPackageError> {
    let mut directories = BTreeSet::new();
    for file in files {
        let mut parent = file.parent();
        while let Some(relative) = parent {
            if relative.as_os_str().is_empty() {
                break;
            }
            if directories.len() >= MAX_MOBILE_RUNTIME_TREE_ENTRIES {
                return package_mismatch();
            }
            directories.insert(relative.to_path_buf());
            parent = relative.parent();
        }
    }
    Ok(directories)
}

fn validate_mobile_runtime_directory(
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
        if *observed_entry_count > MAX_MOBILE_RUNTIME_TREE_ENTRIES {
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
            validate_mobile_runtime_directory(
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
