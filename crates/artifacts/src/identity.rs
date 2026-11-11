// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    artifacts::ZkArtifactSetIdentity,
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};
use sha2::{Digest, Sha256};

/// Maximum byte length of one canonical artifact toolchain version token.
pub const MAX_ARTIFACT_VERSION_BYTES: usize = 64;

/// Maximum number of vector-set digests retained by one stage manifest.
pub const MAX_VECTOR_SET_DIGESTS: usize = 64;

/// Bounded ASCII toolchain version retained without heap-backed strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactVersion {
    bytes: [u8; MAX_ARTIFACT_VERSION_BYTES],
    len: u8,
}

impl ArtifactVersion {
    /// Validates and stores a non-empty release/version token.
    pub fn try_from_token(value: &str) -> Result<Self, ZkError> {
        if value.is_empty() || value.len() > MAX_ARTIFACT_VERSION_BYTES {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        if !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        let len =
            u8::try_from(value.len()).map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        let mut bytes = [0_u8; MAX_ARTIFACT_VERSION_BYTES];
        let target = bytes
            .get_mut(..value.len())
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        target.copy_from_slice(value.as_bytes());
        Ok(Self { bytes, len })
    }

    /// Returns the validated ASCII version bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self.bytes.get(..usize::from(self.len)) {
            Some(bytes) => bytes,
            None => &[],
        }
    }
}

/// Exact compiler and proving-system versions used for an artifact set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactToolchain {
    nargo_version: ArtifactVersion,
    barretenberg_version: ArtifactVersion,
}

impl ArtifactToolchain {
    /// Validates and stores both toolchain version tokens atomically.
    pub fn try_from_versions(
        nargo_version: &str,
        barretenberg_version: &str,
    ) -> Result<Self, ZkError> {
        Ok(Self {
            nargo_version: ArtifactVersion::try_from_token(nargo_version)?,
            barretenberg_version: ArtifactVersion::try_from_token(barretenberg_version)?,
        })
    }

    /// Exact Nargo version bytes.
    #[must_use]
    pub const fn nargo_version(&self) -> ArtifactVersion {
        self.nargo_version
    }

    /// Exact linked Barretenberg version bytes.
    #[must_use]
    pub const fn barretenberg_version(&self) -> ArtifactVersion {
        self.barretenberg_version
    }
}

/// Fixed-size SHA-256 digest used for artifact pinning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Creates a digest from exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Computes the SHA-256 digest for artifact bytes.
    #[must_use]
    pub fn sha256(bytes: &[u8]) -> Self {
        let hash = Sha256::digest(bytes);
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&hash);
        Self(digest)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns true for the all-zero sentinel, which is not an artifact hash.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    /// Returns true when `bytes` hash to this digest.
    #[must_use]
    pub fn matches_sha256(&self, bytes: &[u8]) -> bool {
        *self == Self::sha256(bytes)
    }
}

const EXACT_SOURCE_ARTIFACT_IDENTITY_DOMAIN: &[u8] = b"reallyme-zk-linked-all30-v1\n";

/// Derives the proof-facing identity of an exact compiled source artifact.
///
/// Retaining this legacy domain preserves already generated proof identities;
/// all five inputs are also checked against the signed release index.
pub fn exact_source_artifact_identity(
    circuit_ref: ZkCircuitRef,
    source_closure_sha256: Digest32,
    bytecode_sha256: Digest32,
    verification_key_sha256: Digest32,
) -> Result<ZkArtifactSetIdentity, ZkError> {
    let circuit_name = [
        circuit_ref.credential_hash_algorithm.source_dir(),
        "families",
        circuit_ref.family.source_dir(),
        circuit_ref.stage.source_dir(),
    ]
    .join("/");
    let capacity = EXACT_SOURCE_ARTIFACT_IDENTITY_DOMAIN
        .len()
        .checked_add(circuit_name.len())
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(ZkProofSuite::PRODUCTION.as_str().len()))
        .and_then(|len| len.checked_add(1))
        .and_then(|len| len.checked_add(96))
        .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    let mut material = Vec::new();
    material
        .try_reserve_exact(capacity)
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    material.extend_from_slice(EXACT_SOURCE_ARTIFACT_IDENTITY_DOMAIN);
    material.extend_from_slice(circuit_name.as_bytes());
    material.extend_from_slice(b"\n");
    material.extend_from_slice(ZkProofSuite::PRODUCTION.as_str().as_bytes());
    material.extend_from_slice(b"\n");
    material.extend_from_slice(source_closure_sha256.as_bytes());
    material.extend_from_slice(bytecode_sha256.as_bytes());
    material.extend_from_slice(verification_key_sha256.as_bytes());
    Ok(ZkArtifactSetIdentity::from_bytes(
        *Digest32::sha256(material.as_slice()).as_bytes(),
    ))
}
