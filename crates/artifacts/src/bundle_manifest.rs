// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Atomic manifest for complete ReallyMe ZK proof bundles.

use crate::{ArtifactToolchain, ProductionArtifactManifest};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkProofSuite,
};

/// Hash-pinned manifest for the complete production proof bundle.
///
/// Providers must treat this as the atomic release unit: Noir source, ACIR,
/// verification keys, vector sets, and semantic guarantees are valid only when
/// every required production stage is present for the same bundle_kind and hash
/// lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionBundleManifest {
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    toolchain: ArtifactToolchain,
    stage_manifests: Vec<ProductionArtifactManifest>,
}

impl ProductionBundleManifest {
    /// Validates that a full production bundle_kind bundle is complete and
    /// internally consistent.
    pub fn try_from_stage_manifests(
        bundle_kind: ZkClaimProofBundleKind,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        stage_manifests: Vec<ProductionArtifactManifest>,
    ) -> Result<Self, ZkError> {
        if stage_manifests.len() != ZkClaimProofBundleStage::ALL.len() {
            return Err(ZkError::new(ZkErrorReason::MissingStage));
        }

        let proof_suite = first_proof_suite(stage_manifests.as_slice())?;
        let toolchain = first_toolchain(stage_manifests.as_slice())?;
        let mut seen = 0_u8;

        for manifest in &stage_manifests {
            if manifest.bundle_kind() != bundle_kind {
                return Err(ZkError::new(ZkErrorReason::StageMismatch));
            }
            if manifest.circuit_ref().credential_hash_algorithm != credential_hash_algorithm {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            if manifest.proof_suite() != proof_suite {
                return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
            }
            if manifest.toolchain() != toolchain {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            let bit = stage_bit(manifest.stage());
            if seen & bit != 0 {
                return Err(ZkError::new(ZkErrorReason::DuplicateStage));
            }
            seen |= bit;
        }

        if seen != required_stage_mask() {
            return Err(ZkError::new(ZkErrorReason::MissingStage));
        }

        Ok(Self {
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            toolchain,
            stage_manifests,
        })
    }

    /// Production bundle_kind covered by this atomic manifest.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Hash lane covered by this atomic manifest.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    /// Exact proof suite shared by every stage manifest.
    #[must_use]
    pub const fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    /// Exact toolchain shared by every stage manifest.
    #[must_use]
    pub const fn toolchain(&self) -> ArtifactToolchain {
        self.toolchain
    }

    /// Stage manifests in provider-supplied order.
    #[must_use]
    pub fn stage_manifests(&self) -> &[ProductionArtifactManifest] {
        self.stage_manifests.as_slice()
    }

    /// Finds the manifest for one production stage.
    pub fn stage_manifest(
        &self,
        stage: ZkClaimProofBundleStage,
    ) -> Result<&ProductionArtifactManifest, ZkError> {
        self.stage_manifests
            .iter()
            .find(|manifest| manifest.stage() == stage)
            .ok_or(ZkError::new(ZkErrorReason::MissingStage))
    }

    /// Consumes this wrapper and returns the owned stage manifests.
    #[must_use]
    pub fn into_stage_manifests(self) -> Vec<ProductionArtifactManifest> {
        self.stage_manifests
    }
}

fn first_proof_suite(manifests: &[ProductionArtifactManifest]) -> Result<ZkProofSuite, ZkError> {
    manifests
        .first()
        .map(ProductionArtifactManifest::proof_suite)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))
}

fn first_toolchain(manifests: &[ProductionArtifactManifest]) -> Result<ArtifactToolchain, ZkError> {
    manifests
        .first()
        .map(ProductionArtifactManifest::toolchain)
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))
}

fn required_stage_mask() -> u8 {
    ZkClaimProofBundleStage::ALL
        .iter()
        .fold(0_u8, |mask, stage| mask | stage_bit(*stage))
}

const fn stage_bit(stage: ZkClaimProofBundleStage) -> u8 {
    match stage {
        ZkClaimProofBundleStage::Session => 0b0000_0001,
        ZkClaimProofBundleStage::CredentialEnvelope => 0b0000_0010,
        ZkClaimProofBundleStage::CredentialRoot => 0b0000_0100,
        ZkClaimProofBundleStage::Claim => 0b0000_1000,
        _ => 0,
    }
}
