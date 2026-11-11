// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical runtime and release-tool layout for one stage artifact package.

use std::path::{Path, PathBuf};

use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
};

const LOWER_HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const SHA256_HEX_BYTES: usize = 64;

/// Versioned root directory for the current artifact package layout.
pub const ARTIFACT_PACKAGE_VERSION: &str = "v1";
/// Canonical protobuf manifest file name.
pub const ARTIFACT_MANIFEST_FILE_NAME: &str = "manifest.pb";
/// Compiled ACIR program file name.
pub const ARTIFACT_PROGRAM_FILE_NAME: &str = "program.json";
/// Verification-key file name.
pub const ARTIFACT_VERIFICATION_KEY_FILE_NAME: &str = "verification-key.bin";
/// Directory containing stage-local canonical vector files.
pub const ARTIFACT_VECTORS_DIRECTORY_NAME: &str = "vectors";
/// Release directory containing exact common-credential-root v1 programs.
pub const COMMON_CREDENTIAL_ROOT_ARTIFACT_DIRECTORY_NAME: &str = "common-credential-root-v1";
/// Release directory containing exact persona-credential-evidence v1 programs.
pub const PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_DIRECTORY_NAME: &str =
    "persona-credential-evidence-v1";
/// Canonical source closure lock distributed with exact programs.
pub const COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_FILE_NAME: &str = "modern-circuit-source-lock.tsv";

/// Closed, path-safe layout for one common-credential-root source program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonCredentialRootArtifactLayout {
    root: PathBuf,
    directory: PathBuf,
}

/// Closed, path-safe layout for one persona-credential-evidence source program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonaCredentialEvidenceArtifactLayout {
    root: PathBuf,
    directory: PathBuf,
}

impl PersonaCredentialEvidenceArtifactLayout {
    /// Derives paths only from a registered persona-credential-evidence v1 source ref.
    pub fn try_new(artifact_root: &Path, circuit_ref: ZkCircuitRef) -> Result<Self, ZkError> {
        if circuit_ref.family != ZkCircuitFamily::PersonaCredentialEvidenceV1
            || circuit_ref.revision != ZkCircuitRef::CURRENT_REVISION
            || !matches!(
                circuit_ref.stage,
                ZkCircuitStage::EvidenceIssuerEnvelope
                    | ZkCircuitStage::EvidenceClaimRoot
                    | ZkCircuitStage::EvidenceSignedValidity
                    | ZkCircuitStage::EvidencePublicClaim
                    | ZkCircuitStage::EvidencePrivateClaim
                    | ZkCircuitStage::EvidenceCurrentState
            )
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        let root = artifact_root.join(PERSONA_CREDENTIAL_EVIDENCE_ARTIFACT_DIRECTORY_NAME);
        let directory = root
            .join(circuit_ref.credential_hash_algorithm.source_dir())
            .join(circuit_ref.stage.source_dir());
        Ok(Self { root, directory })
    }

    /// Exact package directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// Source closure lock shared by all prepared programs in this release.
    #[must_use]
    pub fn source_lock(&self) -> PathBuf {
        self.root.join(COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_FILE_NAME)
    }
    /// Compiled ACIR program bytes.
    #[must_use]
    pub fn program(&self) -> PathBuf {
        self.directory.join(ARTIFACT_PROGRAM_FILE_NAME)
    }
    /// Verification-key bytes.
    #[must_use]
    pub fn verification_key(&self) -> PathBuf {
        self.directory.join(ARTIFACT_VERIFICATION_KEY_FILE_NAME)
    }
}

impl CommonCredentialRootArtifactLayout {
    /// Derives paths only from a validated common-credential-root v1 source reference.
    pub fn try_new(artifact_root: &Path, circuit_ref: ZkCircuitRef) -> Result<Self, ZkError> {
        if circuit_ref.family != ZkCircuitFamily::CommonCredentialRootV1
            || circuit_ref.revision != ZkCircuitRef::CURRENT_REVISION
            || !matches!(
                circuit_ref.stage,
                ZkCircuitStage::RootAttestation
                    | ZkCircuitStage::RootStatus
                    | ZkCircuitStage::Lineage
                    | ZkCircuitStage::IssuerCredentialStatus
                    | ZkCircuitStage::PrivatePersonaClaim
                    | ZkCircuitStage::PublicPersonaClaim
                    | ZkCircuitStage::PublicSession
            )
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedCircuit));
        }
        let root = artifact_root.join(COMMON_CREDENTIAL_ROOT_ARTIFACT_DIRECTORY_NAME);
        let directory = root
            .join(circuit_ref.credential_hash_algorithm.source_dir())
            .join(circuit_ref.stage.source_dir());
        Ok(Self { root, directory })
    }

    /// Exact package directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    /// The source closure lock shared by all fourteen packages.
    #[must_use]
    pub fn source_lock(&self) -> PathBuf {
        self.root.join(COMMON_CREDENTIAL_ROOT_SOURCE_LOCK_FILE_NAME)
    }
    /// Compiled ACIR program bytes.
    #[must_use]
    pub fn program(&self) -> PathBuf {
        self.directory.join(ARTIFACT_PROGRAM_FILE_NAME)
    }
    /// Verification key bytes.
    #[must_use]
    pub fn verification_key(&self) -> PathBuf {
        self.directory.join(ARTIFACT_VERIFICATION_KEY_FILE_NAME)
    }
}

/// Exact package paths derived only from closed protocol coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPackageLayout {
    directory: PathBuf,
}

impl ArtifactPackageLayout {
    /// Derives one package directory beneath an explicit artifact root.
    pub fn try_new(
        artifact_root: &Path,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        bundle_kind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        manifest_sha256: ZkArtifactManifestDigest,
    ) -> Result<Self, ZkError> {
        let manifest_component = manifest_digest_component(manifest_sha256)?;
        let manifest_component = core::str::from_utf8(&manifest_component)
            .map_err(|_| ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let directory = artifact_root
            .join(ARTIFACT_PACKAGE_VERSION)
            .join(credential_hash_algorithm.as_str())
            .join(bundle_kind.as_str())
            .join(stage.as_str())
            .join(manifest_component);
        Ok(Self { directory })
    }

    /// Complete stage-package directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Canonical deterministic protobuf manifest path.
    #[must_use]
    pub fn manifest(&self) -> PathBuf {
        self.directory.join(ARTIFACT_MANIFEST_FILE_NAME)
    }

    /// Compiled ACIR program path.
    #[must_use]
    pub fn program(&self) -> PathBuf {
        self.directory.join(ARTIFACT_PROGRAM_FILE_NAME)
    }

    /// Verification-key path.
    #[must_use]
    pub fn verification_key(&self) -> PathBuf {
        self.directory.join(ARTIFACT_VERIFICATION_KEY_FILE_NAME)
    }

    /// Directory containing canonical stage-local vectors.
    #[must_use]
    pub fn vectors(&self) -> PathBuf {
        self.directory.join(ARTIFACT_VECTORS_DIRECTORY_NAME)
    }
}

fn manifest_digest_component(
    digest: ZkArtifactManifestDigest,
) -> Result<[u8; SHA256_HEX_BYTES], ZkError> {
    let mut encoded = [0_u8; SHA256_HEX_BYTES];
    for (index, byte) in digest.as_bytes().iter().copied().enumerate() {
        let offset = index
            .checked_mul(2)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let high = LOWER_HEX_DIGITS
            .get(usize::from(byte >> 4))
            .copied()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let low = LOWER_HEX_DIGITS
            .get(usize::from(byte & 0x0f))
            .copied()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        *encoded
            .get_mut(offset)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))? = high;
        let low_offset = offset
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        *encoded
            .get_mut(low_offset)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))? = low;
    }
    Ok(encoded)
}

#[cfg(test)]
#[path = "layout/tests.rs"]
mod tests;
