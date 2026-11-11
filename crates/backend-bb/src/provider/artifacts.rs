// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verification-only artifact ownership.

use reallyme_zk_api::errors::{ZkError, ZkErrorReason};
use reallyme_zk_artifacts::{ArtifactKind, ProductionArtifactManifest, VerifiedArtifactBytes};

/// Hash-verified verification material for one production stage.
///
/// Verification deliberately excludes ACIR bytecode: a verifier needs only
/// the reviewed manifest coordinates and verification key. Keeping a distinct
/// owner prevents proof-flood traffic from forcing unnecessary bytecode I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BbStageVerificationArtifacts {
    pub(super) manifest: ProductionArtifactManifest,
    pub(super) verification_key: VerifiedArtifactBytes,
}

impl BbStageVerificationArtifacts {
    /// Validates verification-key bytes against the manifest digest and kind.
    pub fn try_new(
        manifest: ProductionArtifactManifest,
        verification_key: VerifiedArtifactBytes,
    ) -> Result<Self, ZkError> {
        if verification_key.digest() != manifest.digests().verification_key_sha256
            || verification_key.kind() != ArtifactKind::VerificationKey
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        Ok(Self {
            manifest,
            verification_key,
        })
    }

    /// Manifest pinned to this verification key.
    #[must_use]
    pub const fn manifest(&self) -> &ProductionArtifactManifest {
        &self.manifest
    }

    /// Hash-verified verification-key bytes.
    #[must_use]
    pub const fn verification_key(&self) -> &VerifiedArtifactBytes {
        &self.verification_key
    }
}
