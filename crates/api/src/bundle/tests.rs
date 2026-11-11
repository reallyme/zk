// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest,
    ZkClaimProofBundleStage, ZkClaimProofBundleStageProof, ZkClaimProofBundleWitness,
};
use crate::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
        ZkSessionBinding, ZkWitness,
    },
};

fn manifest_digest() -> ZkArtifactManifestDigest {
    ZkArtifactManifestDigest::from_bytes([7_u8; 32])
}

fn binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: None,
    }
}

fn claim_proof_bundle_witness(
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
) -> Result<ZkClaimProofBundleWitness, ZkError> {
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    for stage in ZkClaimProofBundleStage::ALL {
        witnesses.push(ZkWitness::try_from_noir_witness_stack_v1(
            bundle_kind.source_ref(credential_hash_algorithm, *stage),
            vec![stage.index().saturating_add(1)],
        )?);
    }
    ZkClaimProofBundleWitness::try_from_stage_witnesses(
        bundle_kind,
        credential_hash_algorithm,
        witnesses,
    )
}

fn proof_for(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
) -> Result<ZkClaimProofBundleStageProof, ZkError> {
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let public_inputs = public_inputs_for_binding(circuit_ref, binding())?;
    let proof = ZkProof::try_from_exact_parts(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        public_inputs,
    )?;
    ZkClaimProofBundleStageProof::try_from_parts(bundle_kind, stage, proof)
}

fn public_inputs_for_binding(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::Challenge,
        &binding.nonce_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::AudienceHash,
        &binding.audience_hash,
    )?;
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::TransactionDataHash)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::TransactionDataHash,
            &binding.transaction_data_public_input(),
        )?;
    }
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::ExpiryUnix,
        &42_u64.to_be_bytes(),
    )?;
    for (name, value) in [
        (ZkPublicInputName::SessionBinding, [10_u8; 32]),
        (ZkPublicInputName::EnvelopeBinding, [11_u8; 32]),
        (ZkPublicInputName::CredentialBinding, [12_u8; 32]),
    ] {
        if descriptor.fields().iter().any(|field| field.name == name) {
            write_public_input(bytes.as_mut_slice(), descriptor, name, &value)?;
        }
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::ValueLength)
    {
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::ValueLength,
            &1_u32.to_be_bytes(),
        )?;
    }
    if descriptor
        .fields()
        .iter()
        .any(|field| field.name == ZkPublicInputName::Value)
    {
        let mut claim_value = [0_u8; 64];
        claim_value[0] = 5;
        write_public_input(
            bytes.as_mut_slice(),
            descriptor,
            ZkPublicInputName::Value,
            &claim_value,
        )?;
    }
    ZkPublicInputs::try_from_bytes(bytes)
}

fn proof_with_replaced_public_input(
    bundle_kind: ZkClaimProofBundleKind,
    stage: ZkClaimProofBundleStage,
    name: ZkPublicInputName,
    value: &[u8],
) -> Result<ZkClaimProofBundleStageProof, ZkError> {
    let circuit_ref = bundle_kind.source_ref(ZkCredentialHashAlgorithm::Sha256, stage);
    let public_inputs = public_inputs_for_binding(circuit_ref, binding())?;
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = public_inputs.into_bytes();
    write_public_input(bytes.as_mut_slice(), descriptor, name, value)?;
    let proof = ZkProof::try_from_exact_parts(
        bundle_kind.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        ZkPublicInputs::try_from_bytes(bytes)?,
    )?;
    ZkClaimProofBundleStageProof::try_from_parts(bundle_kind, stage, proof)
}

fn replace_stage(
    stages: &mut [ZkClaimProofBundleStageProof],
    replacement: ZkClaimProofBundleStageProof,
) -> Result<(), ZkError> {
    let target = stages
        .iter_mut()
        .find(|stage| stage.stage() == replacement.stage())
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    *target = replacement;
    Ok(())
}

fn write_public_input(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) -> Result<(), ZkError> {
    let target = bytes
        .get_mut(descriptor.field_range(name)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(value);
    Ok(())
}

fn complete_bundle_stages(
    bundle_kind: ZkClaimProofBundleKind,
) -> Result<Vec<ZkClaimProofBundleStageProof>, ZkError> {
    let mut stages = Vec::new();
    for stage in ZkClaimProofBundleStage::ALL {
        stages.push(proof_for(bundle_kind, *stage)?);
    }
    Ok(stages)
}

#[test]
fn bundle_kind_maps_to_source_family_and_policy_id() {
    assert_eq!(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1
            .family()
            .as_str(),
        "private_persona_claim_v1"
    );
    assert_eq!(
        ZkClaimProofBundleKind::PrivatePersonaClaimV1
            .source_ref(
                ZkCredentialHashAlgorithm::Poseidon2,
                ZkClaimProofBundleStage::Claim
            )
            .stage
            .as_str(),
        "claim"
    );
}

#[test]
fn production_stage_indexes_are_stable() {
    assert_eq!(ZkClaimProofBundleStage::Session.index(), 0);
    assert_eq!(ZkClaimProofBundleStage::CredentialEnvelope.index(), 1);
    assert_eq!(ZkClaimProofBundleStage::CredentialRoot.index(), 2);
    assert_eq!(ZkClaimProofBundleStage::Claim.index(), 3);
}

#[test]
fn claim_proof_bundle_prove_request_carries_exact_stage_witnesses() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Poseidon2;
    let witnesses = claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?;
    let request = ZkClaimProofBundleProveRequest::try_new(
        bundle_kind,
        credential_hash_algorithm,
        ZkProofSuite::PRODUCTION,
        &witnesses,
        binding(),
    )?;

    assert_eq!(request.bundle_kind(), bundle_kind);
    assert_eq!(
        request.credential_hash_algorithm(),
        credential_hash_algorithm
    );
    assert_eq!(
        request
            .witness_bundle()
            .stage_witness(ZkClaimProofBundleStage::CredentialRoot)?
            .circuit_ref(),
        bundle_kind.source_ref(
            credential_hash_algorithm,
            ZkClaimProofBundleStage::CredentialRoot
        )
    );
    Ok(())
}

#[test]
fn claim_proof_bundle_witness_rejects_missing_and_cross_lane_stacks() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let credential_hash_algorithm = ZkCredentialHashAlgorithm::Sha256;
    let missing = vec![ZkWitness::try_from_noir_witness_stack_v1(
        bundle_kind.source_ref(credential_hash_algorithm, ZkClaimProofBundleStage::Session),
        vec![1],
    )?];
    let mut wrong_lane =
        claim_proof_bundle_witness(bundle_kind, credential_hash_algorithm)?.into_stage_witnesses();
    wrong_lane[0] = ZkWitness::try_from_noir_witness_stack_v1(
        bundle_kind.source_ref(
            ZkCredentialHashAlgorithm::Poseidon2,
            ZkClaimProofBundleStage::Session,
        ),
        vec![1],
    )?;

    assert_eq!(
        ZkClaimProofBundleWitness::try_from_stage_witnesses(
            bundle_kind,
            credential_hash_algorithm,
            missing
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::MissingStage)
    );
    assert_eq!(
        ZkClaimProofBundleWitness::try_from_stage_witnesses(
            bundle_kind,
            credential_hash_algorithm,
            wrong_lane
        )
        .err()
        .map(|error| error.reason()),
        Some(ZkErrorReason::StageMismatch)
    );
    Ok(())
}

#[test]
fn complete_production_bundle_validates() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stages = complete_bundle_stages(bundle_kind)?;
    let bundle = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)?;

    assert_eq!(bundle.bundle_kind(), bundle_kind);
    assert_eq!(bundle.proof_suite(), ZkProofSuite::PRODUCTION);
    assert_eq!(
        bundle.stage_proofs().len(),
        ZkClaimProofBundleStage::ALL.len()
    );
    Ok(())
}

#[test]
fn bundle_rejects_complete_stages_out_of_canonical_order() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let mut stages = complete_bundle_stages(bundle_kind)?;
    stages.swap(0, 1);

    let error = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn standalone_credential_envelope_cannot_grant_claim_admission() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let stages = vec![proof_for(
        bundle_kind,
        ZkClaimProofBundleStage::CredentialEnvelope,
    )?];
    let error = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::MissingStage);
    Ok(())
}

#[test]
fn bundle_rejects_missing_stage() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let stages = vec![proof_for(bundle_kind, ZkClaimProofBundleStage::Session)?];
    let err = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::MissingStage);
    Ok(())
}

#[test]
fn bundle_rejects_duplicate_stage() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stages = vec![
        proof_for(bundle_kind, ZkClaimProofBundleStage::Session)?,
        proof_for(bundle_kind, ZkClaimProofBundleStage::Session)?,
        proof_for(bundle_kind, ZkClaimProofBundleStage::CredentialRoot)?,
        proof_for(bundle_kind, ZkClaimProofBundleStage::Claim)?,
    ];
    let err = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::DuplicateStage);
    Ok(())
}

#[test]
fn overcomplete_bundle_reports_duplicate_stage() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let mut stages = complete_bundle_stages(bundle_kind)?;
    stages.push(proof_for(bundle_kind, ZkClaimProofBundleStage::Session)?);
    let err = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::DuplicateStage);
    Ok(())
}

#[test]
fn stage_proof_rejects_wrong_source_stage() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let wrong_ref = bundle_kind.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Claim,
    );
    let public_inputs = public_inputs_for_binding(wrong_ref, binding())?;
    let proof = ZkProof::try_from_exact_parts(
        bundle_kind.circuit_id(),
        wrong_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        public_inputs,
    )?;
    let err = ZkClaimProofBundleStageProof::try_from_parts(
        bundle_kind,
        ZkClaimProofBundleStage::Session,
        proof,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn bundle_rejects_supplied_absence_sentinel_as_transaction_data() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let stages = complete_bundle_stages(bundle_kind)?;
    let binding = ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: Some(crate::proofs::ABSENT_TRANSACTION_DATA_HASH),
    };
    let err = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding, stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn bundle_rejects_stage_public_input_binding_mismatch() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let mut stages = complete_bundle_stages(bundle_kind)?;
    let mismatched = proof_for(bundle_kind, ZkClaimProofBundleStage::Session)?;
    let (_, _, proof_suite, manifest_digest, proof_bytes, _) =
        mismatched.into_proof().into_exact_parts();
    let wrong_binding = ZkSessionBinding {
        nonce_hash: [9_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: None,
    };
    let public_inputs = public_inputs_for_binding(
        bundle_kind.source_ref(
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::Session,
        ),
        wrong_binding,
    )?;
    let proof = ZkProof::try_from_exact_parts(
        bundle_kind.circuit_id(),
        bundle_kind.source_ref(
            ZkCredentialHashAlgorithm::Sha256,
            ZkClaimProofBundleStage::Session,
        ),
        proof_suite,
        manifest_digest,
        proof_bytes,
        public_inputs,
    )?;
    let replacement = ZkClaimProofBundleStageProof::try_from_parts(
        bundle_kind,
        ZkClaimProofBundleStage::Session,
        proof,
    )?;
    let first = stages
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::MissingStage))?;
    *first = replacement;

    let err = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn bundle_rejects_cross_stage_session_commitment_mismatch() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let mut stages = complete_bundle_stages(bundle_kind)?;
    let replacement = proof_with_replaced_public_input(
        bundle_kind,
        ZkClaimProofBundleStage::Claim,
        ZkPublicInputName::SessionBinding,
        &[99_u8; 32],
    )?;
    replace_stage(stages.as_mut_slice(), replacement)?;

    let error = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn bundle_rejects_diagnostic_envelope_root_chain_mismatch() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let mut stages = complete_bundle_stages(bundle_kind)?;
    let diagnostic_envelope = proof_with_replaced_public_input(
        bundle_kind,
        ZkClaimProofBundleStage::CredentialEnvelope,
        ZkPublicInputName::EnvelopeBinding,
        &[99_u8; 32],
    )?;
    replace_stage(stages.as_mut_slice(), diagnostic_envelope)?;

    let error = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn bundle_rejects_cross_stage_expiry_mismatch() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::PrivatePersonaClaimV1;
    let mut stages = complete_bundle_stages(bundle_kind)?;
    let replacement = proof_with_replaced_public_input(
        bundle_kind,
        ZkClaimProofBundleStage::CredentialRoot,
        ZkPublicInputName::ExpiryUnix,
        &43_u64.to_be_bytes(),
    )?;
    replace_stage(stages.as_mut_slice(), replacement)?;

    let error = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn bundle_constructor_rejects_cross_stage_issuer_mismatch() -> Result<(), ZkError> {
    let bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    let mut stages = complete_bundle_stages(bundle_kind)?;
    let replacement = proof_with_replaced_public_input(
        bundle_kind,
        ZkClaimProofBundleStage::Claim,
        ZkPublicInputName::IssuerPublicKeyX,
        &[99_u8; 32],
    )?;
    replace_stage(stages.as_mut_slice(), replacement)?;

    let error = ZkClaimProofBundle::try_from_stage_proofs(bundle_kind, binding(), stages)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn stage_proof_rejects_mismatched_exact_circuit_ref() -> Result<(), ZkError> {
    let circuit_ref = ZkClaimProofBundleKind::PrivatePersonaClaimV1.source_ref(
        ZkCredentialHashAlgorithm::Sha256,
        ZkClaimProofBundleStage::Session,
    );
    let public_inputs = public_inputs_for_binding(circuit_ref, binding())?;
    let proof = ZkProof::try_from_exact_parts(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        public_inputs,
    )?;
    let err = ZkClaimProofBundleStageProof::try_from_parts(
        ZkClaimProofBundleKind::CredentialSubjectClaimV1,
        ZkClaimProofBundleStage::Session,
        proof,
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}
