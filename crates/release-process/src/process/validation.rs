// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{ffi::OsString, fs, path::Path};

use crate::{ReleaseProcessError, ReleaseProcessErrorReason};
use reallyme_zk_artifacts::ArtifactVersion;

pub(crate) fn validate_regular_file(path: &Path) -> Result<(), ReleaseProcessError> {
    if !path.is_absolute() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    Ok(())
}

pub(crate) fn validate_directory(path: &Path) -> Result<(), ReleaseProcessError> {
    if !path.is_absolute() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    Ok(())
}

pub(crate) fn validate_new_output(path: &Path) -> Result<(), ReleaseProcessError> {
    if !path.is_absolute() {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    if path.try_exists()? {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    let parent = path.parent().ok_or(ReleaseProcessError::new(
        ReleaseProcessErrorReason::InvalidPath,
    ))?;
    validate_directory(parent)
}

pub(crate) fn path_component(version: ArtifactVersion) -> Result<OsString, ReleaseProcessError> {
    if matches!(version.as_bytes(), b"." | b"..") {
        return Err(ReleaseProcessError::new(
            ReleaseProcessErrorReason::InvalidPath,
        ));
    }
    let value = core::str::from_utf8(version.as_bytes())
        .map_err(|_| ReleaseProcessError::new(ReleaseProcessErrorReason::InvalidPath))?;
    Ok(OsString::from(value))
}
