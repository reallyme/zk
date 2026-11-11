// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared fail-closed validation for bundle proving and verification.

use reallyme_zk_api::{
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleStage, MAX_PRESENTATION_LIFETIME_SECONDS,
    },
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::ProductionArtifactManifest;

use super::BbStageArtifacts;

pub(crate) fn validate_presentation_expiry(
    expiry_unix: u64,
    verification_time_unix: u64,
) -> Result<(), ZkError> {
    if verification_time_unix == 0 {
        return Err(ZkError::new(ZkErrorReason::PresentationExpired));
    }
    let remaining_lifetime = expiry_unix
        .checked_sub(verification_time_unix)
        .ok_or(ZkError::new(ZkErrorReason::PresentationExpired))?;
    if remaining_lifetime == 0 {
        return Err(ZkError::new(ZkErrorReason::PresentationExpired));
    }
    if remaining_lifetime > MAX_PRESENTATION_LIFETIME_SECONDS {
        return Err(ZkError::new(ZkErrorReason::PresentationExpiryTooFar));
    }
    Ok(())
}

pub(super) fn validate_stage_ref(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
) -> Result<(), ZkError> {
    if circuit_ref != bundle_kind.source_ref(circuit_ref.credential_hash_algorithm, stage) {
        return Err(ZkError::new(ZkErrorReason::StageMismatch));
    }

    Ok(())
}

pub(crate) fn validate_resolved_artifacts(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
    artifacts: &BbStageArtifacts,
) -> Result<(), ZkError> {
    validate_resolved_manifest(bundle_kind, stage, circuit_ref, artifacts.manifest())
}

pub(super) fn validate_resolved_manifest(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    circuit_ref: ZkCircuitRef,
    manifest: &ProductionArtifactManifest,
) -> Result<(), ZkError> {
    if manifest.bundle_kind() != bundle_kind
        || manifest.stage() != stage
        || manifest.circuit_ref() != circuit_ref
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }

    Ok(())
}

pub(super) fn validate_hash_lane(
    credential_hash_algorithm: &mut Option<ZkCredentialHashAlgorithm>,
    circuit_ref: ZkCircuitRef,
) -> Result<(), ZkError> {
    if let Some(existing) = credential_hash_algorithm {
        if *existing != circuit_ref.credential_hash_algorithm {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
    } else {
        *credential_hash_algorithm = Some(circuit_ref.credential_hash_algorithm);
    }

    Ok(())
}
