// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Recoverable quarantine for an incomplete release promotion.

use std::{fs, path::Path};

use reallyme_zk_artifacts::ArtifactVersion;
use reallyme_zk_artifacts::{ArtifactPackageLayout, ARTIFACT_MANIFEST_FILE_NAME};
use reallyme_zk_proto_codec::release::ReleaseArtifactPin;

use crate::{
    package::{ensure_directory_chain, sync_directory},
    promotion::canonical_directory,
    release_layout::RELEASE_INDEX_FILE_NAME,
    ArtifactPackageError, ArtifactPackageErrorReason, ReleasePackageLayout, RELEASE_PACKAGE_FORMAT,
};

/// Root directory for incomplete releases removed from the readable namespace.
pub const INCOMPLETE_RELEASE_QUARANTINE_DIRECTORY: &str = ".incomplete-releases";

/// Root directory for incomplete content-addressed artifact packages.
pub const INCOMPLETE_ARTIFACT_PACKAGE_QUARANTINE_DIRECTORY: &str = ".incomplete-artifact-packages";

const QUARANTINED_RELEASE_DIRECTORY_NAME: &str = "release";
const QUARANTINED_ARTIFACT_PACKAGE_DIRECTORY_NAME: &str = "package";

/// Stable result for one release directory moved out of the readable namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncompleteReleaseQuarantineSummary {
    /// Exact version token of the quarantined incomplete release.
    pub release_version: ArtifactVersion,
    /// Number of immediate entries preserved with the incomplete release.
    pub preserved_entry_count: u32,
}

/// Stable result for one package directory moved out of the readable namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncompleteArtifactPackageQuarantineSummary {
    /// Exact release-index pin whose incomplete package was preserved.
    pub pin: ReleaseArtifactPin,
    /// Number of immediate entries preserved with the incomplete package.
    pub preserved_entry_count: u32,
}

/// Moves a manifest-less artifact package into a create-new evidence slot.
///
/// `manifest.pb` is the package commit marker. Any entry at that path blocks
/// recovery, including a symlink or non-regular file. The operation never
/// deletes or overwrites partial bytes; after it succeeds, promotion can retry
/// the same content-addressed package path safely.
pub fn quarantine_incomplete_artifact_package(
    artifact_root: &Path,
    pin: ReleaseArtifactPin,
) -> Result<IncompleteArtifactPackageQuarantineSummary, ArtifactPackageError> {
    let canonical_root = canonical_directory(artifact_root)?;
    let circuit_ref = pin.circuit_ref();
    let layout = ArtifactPackageLayout::try_new(
        &canonical_root,
        circuit_ref.credential_hash_algorithm,
        pin.bundle_kind(),
        pin.stage(),
        pin.manifest_sha256(),
    )?;
    validate_incomplete_release_directory(layout.directory())?;
    require_missing_commit_marker(&layout.manifest())?;

    let preserved_entry_count = immediate_entry_count(layout.directory())?;
    sync_directory(layout.directory())?;
    let relative_package = layout
        .directory()
        .strip_prefix(&canonical_root)
        .map_err(|_| ArtifactPackageError::new(ArtifactPackageErrorReason::InvalidRelativePath))?;
    let quarantine_slot = canonical_root
        .join(INCOMPLETE_ARTIFACT_PACKAGE_QUARANTINE_DIRECTORY)
        .join(relative_package);
    let quarantine_parent = quarantine_slot.parent().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidRelativePath,
    ))?;
    ensure_directory_chain(&canonical_root, quarantine_parent)?;
    create_quarantine_slot(&quarantine_slot)?;
    sync_directory(quarantine_parent)?;

    let quarantined_package = quarantine_slot.join(QUARANTINED_ARTIFACT_PACKAGE_DIRECTORY_NAME);
    if let Err(error) = fs::rename(layout.directory(), &quarantined_package) {
        let _cleanup_result = fs::remove_dir(&quarantine_slot);
        return Err(ArtifactPackageError::from(error));
    }

    let package_parent = layout
        .directory()
        .parent()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?;
    sync_directory(package_parent)?;
    sync_directory(&quarantine_slot)?;
    sync_directory(quarantine_parent)?;

    if commit_marker_exists(&quarantined_package.join(ARTIFACT_MANIFEST_FILE_NAME))? {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::ReleaseChangedDuringRecovery,
        ));
    }

    Ok(IncompleteArtifactPackageQuarantineSummary {
        pin,
        preserved_entry_count,
    })
}

/// Moves an incomplete release into a create-new quarantine slot.
///
/// The caller must first stop the failed promotion process. A directory with
/// any `index.pb` entry is treated as committed and is never moved. Quarantine
/// preserves all partial bytes for review and never removes or overwrites an
/// existing evidence slot.
pub fn quarantine_incomplete_release(
    artifact_root: &Path,
    release_version: ArtifactVersion,
) -> Result<IncompleteReleaseQuarantineSummary, ArtifactPackageError> {
    let canonical_root = canonical_directory(artifact_root)?;
    let release_layout = ReleasePackageLayout::try_new(&canonical_root, release_version)?;
    let release_directory = release_layout.directory();
    validate_incomplete_release_directory(release_directory)?;
    require_missing_commit_marker(&release_layout.index())?;

    let preserved_entry_count = immediate_entry_count(release_directory)?;
    sync_directory(release_directory)?;
    let quarantine_parent = canonical_root
        .join(INCOMPLETE_RELEASE_QUARANTINE_DIRECTORY)
        .join(RELEASE_PACKAGE_FORMAT);
    ensure_directory_chain(&canonical_root, &quarantine_parent)?;
    let version_component = release_directory
        .file_name()
        .ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::InvalidRelativePath,
        ))?;
    let quarantine_slot = quarantine_parent.join(version_component);
    create_quarantine_slot(&quarantine_slot)?;
    sync_directory(&quarantine_parent)?;

    let quarantined_release = quarantine_slot.join(QUARANTINED_RELEASE_DIRECTORY_NAME);
    if let Err(error) = fs::rename(release_directory, &quarantined_release) {
        // The reservation is known to have been created empty by this call.
        // `remove_dir` cannot remove data if another actor populated it.
        let _cleanup_result = fs::remove_dir(&quarantine_slot);
        return Err(ArtifactPackageError::from(error));
    }

    let release_parent = release_directory.parent().ok_or(ArtifactPackageError::new(
        ArtifactPackageErrorReason::InvalidRelativePath,
    ))?;
    sync_directory(release_parent)?;
    sync_directory(&quarantine_slot)?;
    sync_directory(&quarantine_parent)?;

    if commit_marker_exists(&quarantined_release.join(RELEASE_INDEX_FILE_NAME))? {
        // The bytes remain quarantined and therefore unreadable as a release.
        // This reason identifies a concurrent writer without risking restore
        // over a newly created path.
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::ReleaseChangedDuringRecovery,
        ));
    }

    Ok(IncompleteReleaseQuarantineSummary {
        release_version,
        preserved_entry_count,
    })
}

fn validate_incomplete_release_directory(path: &Path) -> Result<(), ArtifactPackageError> {
    match canonical_directory(path) {
        Ok(_) => Ok(()),
        Err(error)
            if error.reason()
                == ArtifactPackageErrorReason::Filesystem(std::io::ErrorKind::NotFound) =>
        {
            Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMissing,
            ))
        }
        Err(error) => Err(error),
    }
}

fn require_missing_commit_marker(path: &Path) -> Result<(), ArtifactPackageError> {
    if commit_marker_exists(path)? {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::ReleaseAlreadyCommitted,
        ));
    }
    Ok(())
}

fn commit_marker_exists(path: &Path) -> Result<bool, ArtifactPackageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ArtifactPackageError::from(error)),
    }
}

fn immediate_entry_count(directory: &Path) -> Result<u32, ArtifactPackageError> {
    let mut count = 0_u32;
    for entry in fs::read_dir(directory)? {
        let _entry = entry?;
        count = count.checked_add(1).ok_or(ArtifactPackageError::new(
            ArtifactPackageErrorReason::LengthOverflow,
        ))?;
    }
    Ok(count)
}

fn create_quarantine_slot(path: &Path) -> Result<(), ArtifactPackageError> {
    fs::create_dir(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ArtifactPackageError::new(ArtifactPackageErrorReason::RecoveryDestinationAlreadyExists)
        } else {
            ArtifactPackageError::from(error)
        }
    })
}
