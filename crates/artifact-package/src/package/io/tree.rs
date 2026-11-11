// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fs,
    path::{Path, PathBuf},
};

use reallyme_zk_artifacts::{
    ArtifactPackageLayout, ARTIFACT_MANIFEST_FILE_NAME, ARTIFACT_PROGRAM_FILE_NAME,
    ARTIFACT_VECTORS_DIRECTORY_NAME, ARTIFACT_VERIFICATION_KEY_FILE_NAME, MAX_VECTOR_SET_DIGESTS,
};

use crate::{hash::validate_relative_path, ArtifactPackageError, ArtifactPackageErrorReason};

use super::super::OwnedVectorFile;
use super::{compare_file, MAX_VECTOR_FILE_BYTES};

/// Maximum directory nesting accepted below a package `vectors/` root.
///
/// Reviewed vector trees nest at most two directories below the root. The
/// bound keeps the recursive walk's stack use independent of untrusted
/// on-disk layout.
pub(crate) const MAX_VECTOR_DIRECTORY_DEPTH: usize = 8;

pub(crate) fn validate_top_level_entries(
    layout: &ArtifactPackageLayout,
) -> Result<(), ArtifactPackageError> {
    let mut manifest = false;
    let mut program = false;
    let mut verification_key = false;
    let mut vectors = false;
    for entry in fs::read_dir(layout.directory())? {
        let entry = entry?;
        let name = entry.file_name();
        let file_type = entry.file_type()?;
        if name == ARTIFACT_MANIFEST_FILE_NAME {
            require_file_entry(file_type)?;
            manifest = true;
        } else if name == ARTIFACT_PROGRAM_FILE_NAME {
            require_file_entry(file_type)?;
            program = true;
        } else if name == ARTIFACT_VERIFICATION_KEY_FILE_NAME {
            require_file_entry(file_type)?;
            verification_key = true;
        } else if name == ARTIFACT_VECTORS_DIRECTORY_NAME {
            require_directory_entry(file_type)?;
            vectors = true;
        } else {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMismatch,
            ));
        }
    }
    if !(manifest && program && verification_key && vectors) {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMissing,
        ));
    }
    Ok(())
}

fn require_file_entry(file_type: fs::FileType) -> Result<(), ArtifactPackageError> {
    if !file_type.is_file() || file_type.is_symlink() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    Ok(())
}

fn require_directory_entry(file_type: fs::FileType) -> Result<(), ArtifactPackageError> {
    if !file_type.is_dir() || file_type.is_symlink() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    Ok(())
}

pub(crate) fn validate_vector_tree(
    root: &Path,
    expected: &[OwnedVectorFile],
) -> Result<(), ArtifactPackageError> {
    let mut persisted_paths = Vec::new();
    persisted_paths
        .try_reserve_exact(expected.len())
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InputTooLarge))?;
    collect_vector_paths(root, root, &mut persisted_paths)?;
    persisted_paths.sort();
    if persisted_paths.len() != expected.len() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMismatch,
        ));
    }
    for (path, vector) in persisted_paths.iter().zip(expected) {
        if path != &vector.relative_path {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMismatch,
            ));
        }
        compare_file(&root.join(path), &vector.contents, MAX_VECTOR_FILE_BYTES)?;
    }
    Ok(())
}

pub(crate) fn collect_vector_paths(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<(), ArtifactPackageError> {
    collect_vector_paths_at_depth(root, directory, 0, paths)
}

fn collect_vector_paths_at_depth(
    root: &Path,
    directory: &Path,
    depth: usize,
    paths: &mut Vec<PathBuf>,
) -> Result<(), ArtifactPackageError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMismatch,
            ));
        }
        if file_type.is_dir() {
            let child_depth = depth.checked_add(1).ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))?;
            if child_depth > MAX_VECTOR_DIRECTORY_DEPTH {
                return Err(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::PackageMismatch,
                ));
            }
            let previous_count = paths.len();
            collect_vector_paths_at_depth(root, &entry.path(), child_depth, paths)?;
            if paths.len() == previous_count {
                return Err(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::PackageMismatch,
                ));
            }
            continue;
        }
        if !file_type.is_file() || paths.len() >= MAX_VECTOR_SET_DIGESTS {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMismatch,
            ));
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMismatch))?
            .to_path_buf();
        validate_relative_path(&relative)?;
        paths.push(relative);
    }
    Ok(())
}
