// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use reallyme_zk_artifact_package::{
    ArtifactPackageError, ArtifactPackageErrorReason, SealedRelease,
};
use reallyme_zk_artifacts::ArtifactVersion;

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temporary_root() -> Result<PathBuf, ArtifactPackageError> {
    let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "reallyme-zk-sealed-release-test-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(directory)
}

#[test]
fn sealed_release_requires_absolute_root() -> Result<(), ArtifactPackageError> {
    let version = ArtifactVersion::try_from_token("0.1.0")?;
    let reason = SealedRelease::load_and_check(Path::new("artifacts"), version)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::InvalidRelativePath)
    );
    Ok(())
}

#[test]
fn sealed_release_requires_complete_release_directory() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let version = ArtifactVersion::try_from_token("0.1.0")?;
    let reason = SealedRelease::load_and_check(&root, version)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ArtifactPackageErrorReason::PackageMissing));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn sealed_release_rejects_symlinked_root() -> Result<(), ArtifactPackageError> {
    use std::os::unix::fs::symlink;

    let container = temporary_root()?;
    let target = container.join("target");
    let root = container.join("root");
    fs::create_dir(&target)?;
    symlink(&target, &root)?;
    let version = ArtifactVersion::try_from_token("0.1.0")?;
    let reason = SealedRelease::load_and_check(&root, version)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ArtifactPackageErrorReason::PackageMismatch));
    fs::remove_dir_all(container)?;
    Ok(())
}
