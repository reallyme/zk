// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Artifact-manifest identity retained by proofs and provider boundaries.

/// SHA-256 identity of the canonical binary protobuf artifact manifest.
///
/// The digest is public integrity metadata, not secret material. A dedicated
/// type prevents confusing the manifest identity with verification-key,
/// bytecode, circuit-source, or vector-set digests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkArtifactManifestDigest([u8; 32]);

impl ZkArtifactManifestDigest {
    /// Creates an identity from one exact SHA-256 value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns true for the all-zero sentinel, which is never a reviewed
    /// manifest identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Domain-separated identity of an exact source, bytecode and verification-key set.
/// It is deliberately distinct from the digest of a serialized manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkArtifactSetIdentity([u8; 32]);

impl ZkArtifactSetIdentity {
    /// Construct an identity from exact digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the public identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this is the reserved all-zero identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Explicit proof-facing artifact identity construction.
/// Matching bytes of different variants never establish the same artifact identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZkArtifactIdentity {
    /// SHA-256 of a canonical binary protobuf manifest.
    Manifest(ZkArtifactManifestDigest),
    /// Domain-separated digest of an exact artifact set.
    ArtifactSet(ZkArtifactSetIdentity),
}

impl From<ZkArtifactManifestDigest> for ZkArtifactIdentity {
    fn from(value: ZkArtifactManifestDigest) -> Self {
        Self::Manifest(value)
    }
}

impl From<ZkArtifactSetIdentity> for ZkArtifactIdentity {
    fn from(value: ZkArtifactSetIdentity) -> Self {
        Self::ArtifactSet(value)
    }
}

impl ZkArtifactIdentity {
    /// Whether the digest is the reserved all-zero identity.
    #[must_use]
    pub fn is_zero(self) -> bool {
        match self {
            Self::Manifest(value) => value.is_zero(),
            Self::ArtifactSet(value) => value.is_zero(),
        }
    }

    /// Require the manifest construction at a manifest-only boundary.
    pub fn require_manifest(self) -> Result<ZkArtifactManifestDigest, crate::errors::ZkError> {
        match self {
            Self::Manifest(value) => Ok(value),
            Self::ArtifactSet(_) => Err(crate::errors::ZkError::new(
                crate::errors::ZkErrorReason::ArtifactMismatch,
            )),
        }
    }

    /// Require the derived artifact-set construction at an exact-source boundary.
    pub fn require_artifact_set(self) -> Result<ZkArtifactSetIdentity, crate::errors::ZkError> {
        match self {
            Self::ArtifactSet(value) => Ok(value),
            Self::Manifest(_) => Err(crate::errors::ZkError::new(
                crate::errors::ZkErrorReason::ArtifactMismatch,
            )),
        }
    }
}

#[cfg(test)]
mod tests;
