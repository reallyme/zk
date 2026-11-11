// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical path-bound hashing for source trees and vector files.

use std::{
    cmp::Ordering,
    path::{Component, Path},
};

use reallyme_zk_artifacts::Digest32;
use sha2::{Digest, Sha256};

use crate::{ArtifactPackageError, ArtifactPackageErrorReason};

const MAX_CANONICAL_RELATIVE_PATH_BYTES: usize = 512;

pub(crate) trait NamedFile {
    fn relative_path(&self) -> &Path;
    fn contents(&self) -> &[u8];
}

pub(crate) fn hash_named_files<T: NamedFile>(
    domain_separator: &[u8],
    files: &[T],
) -> Result<Digest32, ArtifactPackageError> {
    let file_count = u32::try_from(files.len())
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::LengthOverflow))?;
    let mut hasher = Sha256::new();
    hasher.update(domain_separator);
    hasher.update(file_count.to_be_bytes());

    let mut previous_path: Option<&Path> = None;
    for file in files {
        validate_order(previous_path, file.relative_path())?;
        let path_length = canonical_path_length(file.relative_path())?;
        let path_length = u32::try_from(path_length)
            .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::LengthOverflow))?;
        let content_length = u64::try_from(file.contents().len())
            .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::LengthOverflow))?;

        hasher.update(path_length.to_be_bytes());
        hash_canonical_path(&mut hasher, file.relative_path())?;
        hasher.update(content_length.to_be_bytes());
        hasher.update(file.contents());
        previous_path = Some(file.relative_path());
    }

    let bytes = hasher.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(bytes.as_slice());
    Ok(Digest32::from_bytes(digest))
}

fn validate_order(previous_path: Option<&Path>, path: &Path) -> Result<(), ArtifactPackageError> {
    validate_relative_path(path)?;
    if let Some(previous) = previous_path {
        if canonical_path_cmp(previous, path)? != Ordering::Less {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::NonCanonicalFileOrder,
            ));
        }
    }
    Ok(())
}

fn canonical_path_cmp(left: &Path, right: &Path) -> Result<Ordering, ArtifactPackageError> {
    let mut left_components = left.components();
    let mut right_components = right.components();
    loop {
        match (left_components.next(), right_components.next()) {
            (Some(Component::Normal(left_value)), Some(Component::Normal(right_value))) => {
                let left_text = left_value.to_str().ok_or(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::InvalidRelativePath,
                ))?;
                let right_text = right_value.to_str().ok_or(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::InvalidRelativePath,
                ))?;
                match left_text.cmp(right_text) {
                    Ordering::Equal => {}
                    ordering => return Ok(ordering),
                }
            }
            (None, None) => return Ok(Ordering::Equal),
            (None, Some(_)) => return Ok(Ordering::Less),
            (Some(_), None) => return Ok(Ordering::Greater),
            _ => {
                return Err(ArtifactPackageError::new(
                    ArtifactPackageErrorReason::InvalidRelativePath,
                ));
            }
        }
    }
}

pub(crate) fn validate_relative_path(path: &Path) -> Result<(), ArtifactPackageError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ));
    }
    let _ = canonical_path_length(path)?;
    Ok(())
}

fn canonical_path_length(path: &Path) -> Result<usize, ArtifactPackageError> {
    let mut length = 0_usize;
    let mut component_count = 0_usize;
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ));
        };
        let value = component.to_str().ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?;
        if value.is_empty() || value.as_bytes().contains(&b'\\') {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ));
        }
        if component_count > 0 {
            length = length.checked_add(1).ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))?;
        }
        length = length
            .checked_add(value.len())
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))?;
        component_count = component_count
            .checked_add(1)
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::LengthOverflow,
            ))?;
    }
    if component_count == 0 || length > MAX_CANONICAL_RELATIVE_PATH_BYTES {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ));
    }
    Ok(length)
}

fn hash_canonical_path(hasher: &mut Sha256, path: &Path) -> Result<(), ArtifactPackageError> {
    for (index, component) in path.components().enumerate() {
        let Component::Normal(component) = component else {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ));
        };
        let value = component.to_str().ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?;
        if index > 0 {
            hasher.update(b"/");
        }
        hasher.update(value.as_bytes());
    }
    Ok(())
}
