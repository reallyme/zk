// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded ownership and digest verification for backend artifact bytes.

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};

use crate::Digest32;

/// Maximum accepted ACIR bytecode size: 64 MiB.
///
/// This is deliberately larger than the imported v1 circuits while still
/// placing a deterministic ceiling on packaged, cached, and remotely loaded
/// artifacts. Raising it is a release-policy decision, not an adapter detail.
pub const MAX_ACIR_BYTECODE_BYTES: usize = 67_108_864;

/// Maximum accepted verification-key size: 16 MiB.
///
/// Verification keys have a separate limit because they are independently
/// loaded and retained beside bytecode in every stage provider.
pub const MAX_VERIFICATION_KEY_BYTES: usize = 16_777_216;

/// Artifact payload class with its independently reviewed size policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    /// Compiled ACIR bytecode consumed by the proving backend.
    AcirBytecode,
    /// Verification key consumed during proof verification.
    VerificationKey,
}

impl ArtifactKind {
    /// Maximum bytes accepted for this artifact class.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::AcirBytecode => MAX_ACIR_BYTECODE_BYTES,
            Self::VerificationKey => MAX_VERIFICATION_KEY_BYTES,
        }
    }

    /// Validates a declared content length before an adapter allocates or
    /// reads the payload.
    pub const fn validate_length(self, length: usize) -> Result<(), ZkError> {
        if length == 0 {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }
        if length > self.max_bytes() {
            return Err(ZkError::new(ZkErrorReason::ArtifactTooLarge));
        }
        Ok(())
    }
}

/// Bounded but not yet hash-verified artifact bytes.
///
/// Stores and platform resource adapters return this type so an unconstrained
/// raw vector cannot cross into the manifest-backed resolver. Adapters reading
/// from a stream must enforce `ArtifactKind::max_bytes()` while reading; the
/// constructors repeat that check at the ownership boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactBytes {
    kind: ArtifactKind,
    bytes: Vec<u8>,
}

impl ArtifactBytes {
    /// Validates an already-owned artifact buffer without copying it.
    pub fn try_from_bytes(kind: ArtifactKind, bytes: Vec<u8>) -> Result<Self, ZkError> {
        kind.validate_length(bytes.len())?;
        Ok(Self { kind, bytes })
    }

    /// Checks a borrowed buffer before allocating its owned representation.
    pub fn try_copy_from_slice(kind: ArtifactKind, bytes: &[u8]) -> Result<Self, ZkError> {
        kind.validate_length(bytes.len())?;

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        Ok(Self { kind, bytes: owned })
    }

    /// Artifact class associated with this buffer's enforced limit.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Borrows the bounded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Consumes the bounded owner without copying its allocation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl core::fmt::Debug for ArtifactBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ArtifactBytes")
            .field("kind", &self.kind)
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Artifact bytes checked against their pinned SHA-256 digest.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedArtifactBytes {
    digest: Digest32,
    bytes: ArtifactBytes,
}

impl VerifiedArtifactBytes {
    /// Hashes and validates bounded artifact bytes before backend use.
    pub fn try_from_bounded(
        bytes: ArtifactBytes,
        expected_digest: Digest32,
    ) -> Result<Self, ZkError> {
        if !expected_digest.matches_sha256(bytes.as_bytes()) {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }

        Ok(Self {
            digest: expected_digest,
            bytes,
        })
    }

    /// Checks length before copying and then validates the pinned digest.
    pub fn try_copy_from_slice(
        kind: ArtifactKind,
        bytes: &[u8],
        expected_digest: Digest32,
    ) -> Result<Self, ZkError> {
        let bounded = ArtifactBytes::try_copy_from_slice(kind, bytes)?;
        Self::try_from_bounded(bounded, expected_digest)
    }

    /// Validates an already-owned buffer and its pinned digest.
    pub fn try_from_bytes(
        kind: ArtifactKind,
        bytes: Vec<u8>,
        expected_digest: Digest32,
    ) -> Result<Self, ZkError> {
        let bounded = ArtifactBytes::try_from_bytes(kind, bytes)?;
        Self::try_from_bounded(bounded, expected_digest)
    }

    /// Artifact class associated with this buffer's enforced limit.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        self.bytes.kind()
    }

    /// Pinned digest that was validated for these bytes.
    #[must_use]
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Borrows the validated artifact bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }

    /// Consumes this wrapper and returns the artifact bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes.into_bytes()
    }
}

impl core::fmt::Debug for VerifiedArtifactBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedArtifactBytes")
            .field("kind", &self.kind())
            .field("digest", &self.digest)
            .field("len", &self.as_bytes().len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}
