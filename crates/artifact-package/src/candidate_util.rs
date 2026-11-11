// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared fail-closed operations for assembling local release candidates.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use reallyme_zk_artifacts::ArtifactVersion;

use crate::{
    package::sync_directory, ArtifactPackageError, ArtifactPackageErrorReason, ReleasePackageLayout,
};

const INDEX_PENDING_FILE: &str = ".index.pb.pending";

pub(crate) fn replace_index(
    root: &Path,
    version: ArtifactVersion,
    bytes: &[u8],
) -> Result<(), ArtifactPackageError> {
    let layout = ReleasePackageLayout::try_new(root, version)?;
    let pending = layout.directory().join(INDEX_PENDING_FILE);
    let final_path = layout.index();
    let metadata = fs::symlink_metadata(&final_path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return package_mismatch();
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    let result = (|| -> Result<(), ArtifactPackageError> {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&pending, &final_path)?;
        sync_directory(layout.directory())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

pub(crate) fn package_mismatch<T>() -> Result<T, ArtifactPackageError> {
    Err(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMismatch,
    ))
}
