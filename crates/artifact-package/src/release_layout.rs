// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed repository-relative layout for one sealed release.

use std::path::{Path, PathBuf};

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::ZkClaimProofBundleKind,
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::ArtifactVersion;

use crate::ArtifactPackageError;

/// Versioned root directory for sealed releases.
pub const RELEASE_PACKAGE_FORMAT: &str = "v1";

pub(crate) const RELEASE_INDEX_FILE_NAME: &str = "index.pb";
pub(crate) const RELEASE_VECTORS_DIRECTORY_NAME: &str = "verification-vectors";

/// Exact paths for one release index and its post-manifest vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasePackageLayout {
    directory: PathBuf,
}

impl ReleasePackageLayout {
    /// Derives a release directory from a validated, path-safe version token.
    pub fn try_new(
        release_root: &Path,
        release_version: ArtifactVersion,
    ) -> Result<Self, ArtifactPackageError> {
        validate_release_version(release_version)?;
        let version_bytes = release_version.as_bytes();
        let version = core::str::from_utf8(version_bytes)
            .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        Ok(Self {
            directory: release_root.join(RELEASE_PACKAGE_FORMAT).join(version),
        })
    }

    /// Directory whose `index.pb` file is the atomic readiness marker.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Canonical release-index protobuf path.
    #[must_use]
    pub fn index(&self) -> PathBuf {
        self.directory.join(RELEASE_INDEX_FILE_NAME)
    }

    /// Directory containing proof-bearing post-manifest vectors.
    #[must_use]
    pub fn vectors(&self) -> PathBuf {
        self.directory.join(RELEASE_VECTORS_DIRECTORY_NAME)
    }

    /// Canonical vector path derived only from closed protocol enums.
    #[must_use]
    pub fn verification_vector(
        &self,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        bundle_kind: ZkClaimProofBundleKind,
    ) -> PathBuf {
        self.vectors()
            .join(credential_hash_algorithm.as_str())
            .join(bundle_kind.as_str())
            .with_extension("pb")
    }
}

pub(crate) fn validate_release_version(
    release_version: ArtifactVersion,
) -> Result<(), ArtifactPackageError> {
    let version_bytes = release_version.as_bytes();
    if matches!(version_bytes, b"." | b"..")
        || ZkCredentialHashAlgorithm::ALL
            .iter()
            .any(|credential_hash_algorithm| {
                version_bytes == credential_hash_algorithm.as_str().as_bytes()
            })
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch).into());
    }
    Ok(())
}
