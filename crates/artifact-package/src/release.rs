// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-object validation and canonical release-index assembly.

use std::{
    ffi::OsStr,
    fs::{self},
    path::Path,
};

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use reallyme_zk_artifacts::{ArtifactVersion, Digest32, ProductionArtifactManifest};
use reallyme_zk_proto_codec::{
    artifact::decode_artifact_manifest,
    release::MAX_ZK_RELEASE_INDEX_BYTES,
    release::{
        encode_release_index, ReleaseArtifactPin, ReleaseIndex, ReleaseVerificationVectorPin,
        RELEASE_ARTIFACT_MANIFEST_COUNT, RELEASE_VERIFICATION_VECTOR_SET_COUNT,
    },
    verification_vector::{
        decode_verification_vector_set, VerificationVectorSet, MAX_ZK_VERIFICATION_VECTOR_SET_BYTES,
    },
};
use zeroize::Zeroizing;

use crate::{
    package::{
        compare_file, ensure_directory_chain, map_create_directory_error, sync_directory,
        write_atomic_file,
    },
    release_layout::{
        validate_release_version, RELEASE_INDEX_FILE_NAME, RELEASE_VECTORS_DIRECTORY_NAME,
    },
    ArtifactPackageError, ArtifactPackageErrorReason, ReleasePackageLayout,
};

const ARTIFACTS_PER_VECTOR_SET: usize = 4;

/// Canonical manifest bytes paired with their validated domain identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseArtifactManifestFile {
    sha256: Digest32,
    manifest: ProductionArtifactManifest,
}

impl ReleaseArtifactManifestFile {
    /// Decodes canonical manifest bytes and retains only their public digest.
    pub fn try_new(bytes: &[u8]) -> Result<Self, ArtifactPackageError> {
        Ok(Self {
            sha256: Digest32::sha256(bytes),
            manifest: decode_artifact_manifest(bytes)?,
        })
    }
}

/// Canonical post-manifest proof-vector bytes and validated zeroizing owner.
///
/// This type intentionally implements neither `Debug` nor `Clone` because the
/// decoded set retains concrete proof encodings.
pub struct ReleaseVerificationVectorFile {
    sha256: Digest32,
    vector_set: VerificationVectorSet,
    canonical_bytes: Zeroizing<Vec<u8>>,
}

impl ReleaseVerificationVectorFile {
    /// Decodes canonical proof-bearing vector bytes at construction.
    pub fn try_new(bytes: &[u8]) -> Result<Self, ArtifactPackageError> {
        let vector_set = decode_verification_vector_set(bytes)?;
        let mut canonical_bytes = Zeroizing::new(Vec::new());
        canonical_bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        canonical_bytes.extend_from_slice(bytes);
        Ok(Self {
            sha256: Digest32::sha256(bytes),
            vector_set,
            canonical_bytes,
        })
    }
}

/// Canonical index bytes plus the validated index and external SHA-256 pin.
pub struct AssembledReleaseIndex {
    index: ReleaseIndex,
    canonical_bytes: Vec<u8>,
    sha256: Digest32,
    vector_files: Vec<ReleaseVerificationVectorFile>,
}

impl AssembledReleaseIndex {
    /// Validated release-index domain owner.
    #[must_use]
    pub const fn index(&self) -> &ReleaseIndex {
        &self.index
    }

    /// Deterministic protobuf bytes persisted and signed by release tooling.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// External SHA-256 identity of the canonical index bytes.
    #[must_use]
    pub const fn sha256(&self) -> Digest32 {
        self.sha256
    }

    /// Derives the strict release location beneath a release root.
    pub fn layout(
        &self,
        release_root: &Path,
    ) -> Result<ReleasePackageLayout, ArtifactPackageError> {
        ReleasePackageLayout::try_new(release_root, self.index.release_version())
    }

    /// Persists a new release without overwriting an existing directory.
    ///
    /// Vector payloads are synced before `index.pb`; consumers therefore treat
    /// the index as the atomic readiness marker for the complete release.
    pub fn write_new(&self, release_root: &Path) -> Result<(), ArtifactPackageError> {
        let layout = self.layout(release_root)?;
        if layout.directory().try_exists()? {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageAlreadyExists,
            ));
        }
        let parent = layout
            .directory()
            .parent()
            .ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
        ensure_directory_chain(release_root, parent)?;
        fs::create_dir(layout.directory()).map_err(map_create_directory_error)?;
        fs::create_dir(layout.vectors())?;

        for file in &self.vector_files {
            let destination = layout.verification_vector(
                file.vector_set.credential_hash_algorithm(),
                file.vector_set.bundle_kind(),
            );
            let directory = destination.parent().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            ensure_directory_chain(&layout.vectors(), directory)?;
            let file_name = destination.file_name().ok_or(ArtifactPackageError::new(
                ArtifactPackageErrorReason::InvalidRelativePath,
            ))?;
            write_atomic_file(parent, directory, file_name, &file.canonical_bytes)?;
        }
        sync_directory(&layout.vectors())?;
        write_atomic_file(
            parent,
            layout.directory(),
            OsStr::new(RELEASE_INDEX_FILE_NAME),
            &self.canonical_bytes,
        )?;
        sync_directory(layout.directory())?;
        Ok(())
    }

    /// Verifies the persisted release tree against the assembled package.
    pub fn check(&self, release_root: &Path) -> Result<(), ArtifactPackageError> {
        let layout = self.layout(release_root)?;
        if !layout.directory().try_exists()? {
            return Err(ArtifactPackageError::new(
                ArtifactPackageErrorReason::PackageMissing,
            ));
        }
        validate_release_entries(&layout)?;
        compare_file(
            &layout.index(),
            &self.canonical_bytes,
            MAX_ZK_RELEASE_INDEX_BYTES,
        )?;
        for file in &self.vector_files {
            compare_file(
                &layout.verification_vector(
                    file.vector_set.credential_hash_algorithm(),
                    file.vector_set.bundle_kind(),
                ),
                &file.canonical_bytes,
                MAX_ZK_VERIFICATION_VECTOR_SET_BYTES,
            )?;
        }
        Ok(())
    }
}

/// Validates the complete cross-object release graph and emits its index.
pub fn assemble_release_index(
    release_version: &str,
    artifact_files: Vec<ReleaseArtifactManifestFile>,
    vector_files: Vec<ReleaseVerificationVectorFile>,
) -> Result<AssembledReleaseIndex, ArtifactPackageError> {
    // `ArtifactVersion` is also used for non-path toolchain tokens. Release
    // versions need this additional invariant before they may name a directory.
    let release_version = ArtifactVersion::try_from_token(release_version)?;
    validate_release_version(release_version)?;
    if artifact_files.len() != RELEASE_ARTIFACT_MANIFEST_COUNT
        || vector_files.len() != RELEASE_VERIFICATION_VECTOR_SET_COUNT
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch).into());
    }
    let first_manifest = artifact_files
        .first()
        .map(|file| &file.manifest)
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let toolchain = first_manifest.toolchain();
    let proof_suite = first_manifest.proof_suite();
    proof_suite.require_production()?;
    let capability_registry_sha256 = first_manifest.digests().capability_registry_sha256;

    let mut artifact_pins = Vec::new();
    artifact_pins
        .try_reserve_exact(artifact_files.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for file in artifact_files {
        validate_manifest_release_identity(
            &file,
            toolchain,
            proof_suite,
            capability_registry_sha256,
        )?;
        artifact_pins.push(ReleaseArtifactPin::try_new(
            file.manifest.bundle_kind(),
            file.manifest.stage(),
            file.manifest.circuit_ref(),
            file.manifest.manifest_sha256(),
        )?);
    }

    let mut vector_pins = Vec::new();
    vector_pins
        .try_reserve_exact(vector_files.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    let mut retained_vectors = Vec::new();
    retained_vectors
        .try_reserve_exact(vector_files.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for (index, file) in vector_files.into_iter().enumerate() {
        if file.vector_set.proof_suite() != proof_suite {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite).into());
        }
        let artifact_start = index
            .checked_mul(ARTIFACTS_PER_VECTOR_SET)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let artifact_end = artifact_start
            .checked_add(ARTIFACTS_PER_VECTOR_SET)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let expected_artifacts = artifact_pins
            .get(artifact_start..artifact_end)
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        if file.vector_set.artifact_manifests() != expected_artifacts {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch).into());
        }
        let vector_count = u32::try_from(file.vector_set.vectors().len())
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        vector_pins.push(ReleaseVerificationVectorPin::try_new(
            file.vector_set.bundle_kind(),
            file.vector_set.credential_hash_algorithm(),
            file.vector_set.proof_suite(),
            file.sha256,
            vector_count,
        )?);
        retained_vectors.push(file);
    }

    let index = ReleaseIndex::try_new(
        release_version,
        toolchain,
        proof_suite,
        capability_registry_sha256,
        artifact_pins,
        vector_pins,
    )?;
    let canonical_bytes = encode_release_index(&index)?;
    let sha256 = Digest32::sha256(&canonical_bytes);
    Ok(AssembledReleaseIndex {
        index,
        canonical_bytes,
        sha256,
        vector_files: retained_vectors,
    })
}

pub(crate) fn validate_release_entries(
    layout: &ReleasePackageLayout,
) -> Result<(), ArtifactPackageError> {
    let release_metadata = fs::symlink_metadata(layout.directory()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMissing)
        } else {
            ArtifactPackageError::from(error)
        }
    })?;
    if release_metadata.file_type().is_symlink() || !release_metadata.is_dir() {
        return package_mismatch();
    }
    let mut index_found = false;
    let mut vectors_found = false;
    for entry in fs::read_dir(layout.directory())? {
        let entry = entry?;
        let name = entry.file_name();
        let file_type = entry.file_type()?;
        if name == RELEASE_INDEX_FILE_NAME {
            if !file_type.is_file() || file_type.is_symlink() {
                return package_mismatch();
            }
            index_found = true;
        } else if name == RELEASE_VECTORS_DIRECTORY_NAME {
            if !file_type.is_dir() || file_type.is_symlink() {
                return package_mismatch();
            }
            vectors_found = true;
        } else {
            return package_mismatch();
        }
    }
    if !(index_found && vectors_found) {
        return Err(ArtifactPackageError::new(
            ArtifactPackageErrorReason::PackageMissing,
        ));
    }

    let mut hash_directories = 0_usize;
    for entry in fs::read_dir(layout.vectors())? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return package_mismatch();
        }
        let name = entry.file_name();
        if !reallyme_zk_api::circuits::ZkCredentialHashAlgorithm::ALL
            .iter()
            .any(|hash| name == hash.as_str())
        {
            return package_mismatch();
        }
        hash_directories = hash_directories
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    if hash_directories != reallyme_zk_api::circuits::ZkCredentialHashAlgorithm::ALL.len() {
        return package_mismatch();
    }

    let mut expected_files = 0_usize;
    for hash in reallyme_zk_api::circuits::ZkCredentialHashAlgorithm::ALL {
        let hash_directory = layout.vectors().join(hash.as_str());
        let metadata = fs::symlink_metadata(&hash_directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ArtifactPackageError::new(ArtifactPackageErrorReason::PackageMissing)
            } else {
                ArtifactPackageError::from(error)
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return package_mismatch();
        }
        for entry in fs::read_dir(&hash_directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() || !file_type.is_file() {
                return package_mismatch();
            }
            let name = entry.file_name();
            let known = reallyme_zk_api::claim_bundle::ZkClaimProofBundleKind::ALL
                .iter()
                .any(|bundle_kind| {
                    let mut expected = OsStr::new(bundle_kind.as_str()).to_os_string();
                    expected.push(".pb");
                    name == expected
                });
            if !known {
                return package_mismatch();
            }
            expected_files = expected_files
                .checked_add(1)
                .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        }
    }
    if expected_files != RELEASE_VERIFICATION_VECTOR_SET_COUNT {
        return package_mismatch();
    }
    Ok(())
}

fn package_mismatch() -> Result<(), ArtifactPackageError> {
    Err(ArtifactPackageError::new(
        ArtifactPackageErrorReason::PackageMismatch,
    ))
}

fn validate_manifest_release_identity(
    file: &ReleaseArtifactManifestFile,
    expected_toolchain: reallyme_zk_artifacts::ArtifactToolchain,
    expected_suite: ZkProofSuite,
    expected_capability_registry: Digest32,
) -> Result<(), ArtifactPackageError> {
    let expected_manifest_digest = ZkArtifactManifestDigest::from_bytes(*file.sha256.as_bytes());
    if file.manifest.manifest_sha256() != expected_manifest_digest
        || file.manifest.toolchain() != expected_toolchain
        || file.manifest.proof_suite() != expected_suite
        || file.manifest.digests().capability_registry_sha256 != expected_capability_registry
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch).into());
    }
    Ok(())
}
