// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    admit_claim_proof_bundle, claim_proof_bundle, proof_package, session_binding, stage_package,
    EnumValue, MessageField, ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkError,
    ZkErrorReason,
};

#[test]
fn claim_proof_bundle_converts_to_domain_bundle() -> Result<(), ZkError> {
    let bundle = admit_claim_proof_bundle(claim_proof_bundle()?)?;

    assert_eq!(bundle.stage_proofs().len(), 4);
    assert_eq!(bundle.session_binding().nonce_hash, [1_u8; 32]);
    for stage in bundle.stage_proofs() {
        assert_eq!(
            stage
                .proof()
                .artifact_identity()
                .require_manifest()?
                .as_bytes(),
            &[7_u8; 32]
        );
    }
    Ok(())
}

#[test]
fn claim_proof_bundle_rejects_bad_nonce_hash_length() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    let mut session_binding = session_binding();
    session_binding.nonce_hash = vec![1_u8; 31];
    bundle.session_binding = MessageField::some(session_binding);

    let err = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn claim_proof_bundle_rejects_transaction_binding_mismatch() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    let mut binding = session_binding();
    binding.transaction_data_hash = vec![3_u8; 32];
    bundle.session_binding = MessageField::some(binding);

    let err = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn claim_proof_bundle_rejects_missing_public_inputs() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    let mut stage = stage_package(ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM)?;
    let mut proof = proof_package(ZkClaimProofBundleStage::ZK_CLAIM_PROOF_BUNDLE_STAGE_CLAIM)?;
    proof.public_inputs = MessageField::none();
    stage.proof = MessageField::some(proof);
    let last = bundle
        .stages
        .last_mut()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    *last = stage;

    let err = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::EmptyInput);
    Ok(())
}

#[test]
fn claim_proof_bundle_rejects_stage_profile_mismatch() -> Result<(), ZkError> {
    let mut bundle = claim_proof_bundle()?;
    let first = bundle
        .stages
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    first.bundle_kind = EnumValue::from(
        ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
    );

    let err = admit_claim_proof_bundle(bundle)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}
