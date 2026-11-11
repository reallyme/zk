// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(missing_docs)]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use reallyme_zk_artifact_package::{
    quarantine_incomplete_release, ArtifactPackageError, ArtifactPackageErrorReason,
    ReleasePackageLayout, INCOMPLETE_RELEASE_QUARANTINE_DIRECTORY, RELEASE_PACKAGE_FORMAT,
};
use reallyme_zk_artifacts::ArtifactVersion;

static TEMPORARY_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn temporary_root() -> Result<PathBuf, ArtifactPackageError> {
    let sequence = TEMPORARY_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "reallyme-zk-release-recovery-test-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)?;
    Ok(fs::canonicalize(directory)?)
}

fn version() -> Result<ArtifactVersion, ArtifactPackageError> {
    Ok(ArtifactVersion::try_from_token("0.1.0")?)
}

fn quarantine_release(root: &std::path::Path) -> PathBuf {
    root.join(INCOMPLETE_RELEASE_QUARANTINE_DIRECTORY)
        .join(RELEASE_PACKAGE_FORMAT)
        .join("0.1.0")
        .join("release")
}

#[test]
fn incomplete_release_is_preserved_outside_readable_namespace() -> Result<(), ArtifactPackageError>
{
    let root = temporary_root()?;
    let release_version = version()?;
    let layout = ReleasePackageLayout::try_new(&root, release_version)?;
    fs::create_dir_all(layout.vectors())?;
    fs::write(layout.directory().join("partial.pb"), [1_u8, 2, 3])?;

    let summary = quarantine_incomplete_release(&root, release_version)?;

    assert_eq!(summary.release_version, release_version);
    assert_eq!(summary.preserved_entry_count, 2);
    assert!(!layout.directory().try_exists()?);
    let quarantined = quarantine_release(&root);
    assert!(quarantined.is_dir());
    assert_eq!(fs::read(quarantined.join("partial.pb"))?, [1_u8, 2, 3]);
    assert!(!quarantined.join("index.pb").try_exists()?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn committed_release_is_never_moved() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let release_version = version()?;
    let layout = ReleasePackageLayout::try_new(&root, release_version)?;
    fs::create_dir_all(layout.directory())?;
    fs::write(layout.index(), [1_u8])?;

    let reason = quarantine_incomplete_release(&root, release_version)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::ReleaseAlreadyCommitted)
    );
    assert!(layout.directory().is_dir());
    assert!(!quarantine_release(&root).try_exists()?);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn existing_quarantine_evidence_is_never_overwritten() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let release_version = version()?;
    let layout = ReleasePackageLayout::try_new(&root, release_version)?;
    fs::create_dir_all(layout.directory())?;
    let quarantine_slot = quarantine_release(&root)
        .parent()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?
        .to_path_buf();
    fs::create_dir_all(&quarantine_slot)?;
    fs::write(quarantine_slot.join("evidence"), [9_u8])?;

    let reason = quarantine_incomplete_release(&root, release_version)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::RecoveryDestinationAlreadyExists)
    );
    assert!(layout.directory().is_dir());
    assert_eq!(fs::read(quarantine_slot.join("evidence"))?, [9_u8]);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn missing_release_returns_stable_reason() -> Result<(), ArtifactPackageError> {
    let root = temporary_root()?;
    let reason = quarantine_incomplete_release(&root, version()?)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ArtifactPackageErrorReason::PackageMissing));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_release_directory_is_rejected() -> Result<(), ArtifactPackageError> {
    use std::os::unix::fs::symlink;

    let root = temporary_root()?;
    let release_version = version()?;
    let layout = ReleasePackageLayout::try_new(&root, release_version)?;
    let parent = layout
        .directory()
        .parent()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?;
    fs::create_dir_all(parent)?;
    let target = root.join("untrusted-target");
    fs::create_dir(&target)?;
    symlink(&target, layout.directory())?;

    let reason = quarantine_incomplete_release(&root, release_version)
        .err()
        .map(|error| error.reason());

    assert_eq!(reason, Some(ArtifactPackageErrorReason::PackageMismatch));
    assert!(target.is_dir());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn broken_index_symlink_is_treated_as_a_commit_marker() -> Result<(), ArtifactPackageError> {
    use std::os::unix::fs::symlink;

    let root = temporary_root()?;
    let release_version = version()?;
    let layout = ReleasePackageLayout::try_new(&root, release_version)?;
    fs::create_dir_all(layout.directory())?;
    symlink("missing-index", layout.index())?;

    let reason = quarantine_incomplete_release(&root, release_version)
        .err()
        .map(|error| error.reason());

    assert_eq!(
        reason,
        Some(ArtifactPackageErrorReason::ReleaseAlreadyCommitted)
    );
    assert!(layout.directory().is_dir());
    fs::remove_dir_all(root)?;
    Ok(())
}
