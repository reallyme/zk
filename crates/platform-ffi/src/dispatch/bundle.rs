// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::ZkClaimProofBundle,
    errors::{ZkError, ZkErrorReason},
};

pub(super) fn bundle_credential_hash_algorithm(
    bundle: &ZkClaimProofBundle,
) -> Result<ZkCredentialHashAlgorithm, ZkError> {
    let mut credential_hash_algorithm = None;
    for stage_proof in bundle.stage_proofs() {
        let stage_credential_hash_algorithm =
            stage_proof.proof().circuit_ref().credential_hash_algorithm;
        if let Some(expected_credential_hash_algorithm) = credential_hash_algorithm {
            if expected_credential_hash_algorithm != stage_credential_hash_algorithm {
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
        } else {
            credential_hash_algorithm = Some(stage_credential_hash_algorithm);
        }
    }
    credential_hash_algorithm.ok_or(ZkError::new(ZkErrorReason::MissingStage))
}
