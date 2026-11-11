// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    ZkProof, ZkProofBytes, ZkProveRequest, ZkVerifyRequest, ZkWitness, ZkWitnessEncoding,
    MAX_PROOF_BYTES, MAX_WITNESS_BYTES,
};
use crate::{
    artifacts::ZkArtifactManifestDigest,
    circuits::{
        ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm,
    },
    claim_bundle::ZkCompatibilitySuiteAcknowledgement,
    errors::ZkErrorReason,
    proofs::{
        ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs, ZkSessionBinding,
    },
};
use core::ops::Range;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[test]
fn proof_bytes_erase_on_drop_and_transfer_explicitly() -> Result<(), crate::errors::ZkError> {
    fn requires_erasure<T: ZeroizeOnDrop>() {}
    requires_erasure::<ZkProofBytes>();

    let owned = ZkProofBytes::try_copy_from_slice(&[0x5a, 0xa5])?;
    let transferred = owned.into_bytes();
    assert_eq!(transferred, [0x5a, 0xa5]);
    let _transferred_owner = Zeroizing::new(transferred);
    Ok(())
}

#[allow(dead_code)]
trait WitnessMustNotImplementClone {}

impl WitnessMustNotImplementClone for ZkWitness {}

impl<T: Clone> WitnessMustNotImplementClone for T {}

fn manifest_digest() -> ZkArtifactManifestDigest {
    ZkArtifactManifestDigest::from_bytes([7_u8; 32])
}

const fn circuit_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    )
}

fn exact_public_inputs(
    circuit_ref: ZkCircuitRef,
) -> Result<ZkPublicInputs, crate::errors::ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    ZkPublicInputs::try_from_bytes(vec![0_u8; descriptor.encoded_len()?])
}

const fn zero_binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [0; 32],
        audience_hash: [0; 32],
        transaction_data_hash: None,
    }
}

const fn prove_binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [1; 32],
        audience_hash: [2; 32],
        transaction_data_hash: None,
    }
}

fn exact_public_inputs_for_binding(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
) -> Result<ZkPublicInputs, crate::errors::ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::Challenge)?,
        &binding.nonce_hash,
    )?;
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::AudienceHash)?,
        &binding.audience_hash,
    )?;
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::TransactionDataHash)?,
        &binding.transaction_data_public_input(),
    )?;
    write_field(
        &mut bytes,
        descriptor.field_range(ZkPublicInputName::ExpiryUnix)?,
        &42_u64.to_be_bytes(),
    )?;
    ZkPublicInputs::try_from_bytes(bytes)
}

fn write_field(
    bytes: &mut [u8],
    range: Range<usize>,
    value: &[u8],
) -> Result<(), crate::errors::ZkError> {
    let target = bytes.get_mut(range).ok_or(crate::errors::ZkError::new(
        ZkErrorReason::InvalidProofEncoding,
    ))?;
    if target.len() != value.len() {
        return Err(crate::errors::ZkError::new(
            ZkErrorReason::InvalidProofEncoding,
        ));
    }
    target.copy_from_slice(value);
    Ok(())
}

#[test]
fn proof_rejects_empty_bytes() -> Result<(), crate::errors::ZkError> {
    let exact_ref = circuit_ref();
    let public_inputs = exact_public_inputs(exact_ref)?;
    let err = ZkProof::try_from_exact_parts(
        exact_ref.circuit_id(),
        exact_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        Vec::new(),
        public_inputs,
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::EmptyInput);
    Ok(())
}

#[test]
fn proof_rejects_oversized_bytes() -> Result<(), crate::errors::ZkError> {
    let exact_ref = circuit_ref();
    let public_inputs = exact_public_inputs(exact_ref)?;
    let proof_bytes = vec![0_u8; MAX_PROOF_BYTES + 1];
    let err = ZkProof::try_from_exact_parts(
        exact_ref.circuit_id(),
        exact_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        proof_bytes,
        public_inputs,
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(err.reason(), ZkErrorReason::ProofTooLarge);
    Ok(())
}

#[test]
fn bounded_proof_bytes_copy_borrowed_input_and_redact_debug() -> Result<(), crate::errors::ZkError>
{
    let source = [171_u8, 205_u8];
    let proof_bytes = ZkProofBytes::try_copy_from_slice(&source)?;
    let debug = format!("{proof_bytes:?}");

    assert_eq!(proof_bytes.as_bytes(), source.as_slice());
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("171"));
    assert!(!debug.contains("205"));
    Ok(())
}

#[test]
fn bounded_proof_bytes_reject_invalid_reported_lengths() {
    let empty = ZkProofBytes::validate_length(0)
        .err()
        .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));
    let oversized = ZkProofBytes::validate_length(MAX_PROOF_BYTES.saturating_add(1))
        .err()
        .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(empty.reason(), ZkErrorReason::EmptyInput);
    assert_eq!(oversized.reason(), ZkErrorReason::ProofTooLarge);
}

#[test]
fn witness_exposes_bytes_without_debug_trait() -> Result<(), crate::errors::ZkError> {
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref(), vec![7, 8, 9])?;

    assert_eq!(witness.encoding(), ZkWitnessEncoding::NoirWitnessStackV1);
    assert_eq!(witness.expose_bytes(), &[7, 8, 9]);
    Ok(())
}

#[test]
fn witness_admits_existing_zeroizing_owner_without_copy() -> Result<(), crate::errors::ZkError> {
    let witness = ZkWitness::try_from_noir_witness_stack_v1_zeroizing(
        circuit_ref(),
        Zeroizing::new(vec![7, 8, 9]),
    )?;

    assert_eq!(witness.circuit_ref(), circuit_ref());
    assert_eq!(witness.expose_bytes(), &[7, 8, 9]);
    Ok(())
}

#[test]
fn witness_rejects_empty_bytes() {
    let error = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref(), Vec::new())
        .err()
        .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(error.reason(), ZkErrorReason::EmptyInput);
}

#[test]
fn witness_rejects_oversized_bytes() {
    let bytes = vec![0_u8; MAX_WITNESS_BYTES.saturating_add(1)];
    let error = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref(), bytes)
        .err()
        .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(error.reason(), ZkErrorReason::WitnessTooLarge);
}

#[test]
fn witness_rejects_unsupported_circuit_revision() {
    let mut unsupported = circuit_ref();
    unsupported.revision = ZkCircuitRef::CURRENT_REVISION.saturating_add(1);
    let error = ZkWitness::try_from_noir_witness_stack_v1(unsupported, vec![1])
        .err()
        .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedCircuit);
}

#[test]
fn v1_circuit_rejects_supplied_absence_sentinel_transaction_data() {
    let binding = ZkSessionBinding {
        nonce_hash: [1; 32],
        audience_hash: [2; 32],
        transaction_data_hash: Some(crate::proofs::ABSENT_TRANSACTION_DATA_HASH),
    };
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Claim,
    );

    let error = binding
        .validate_for_circuit(circuit_ref)
        .err()
        .unwrap_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure));

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
}

#[test]
fn v1_circuit_accepts_binding_without_transaction_data() -> Result<(), crate::errors::ZkError> {
    let binding = ZkSessionBinding {
        nonce_hash: [1; 32],
        audience_hash: [2; 32],
        transaction_data_hash: None,
    };
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::PrivatePersonaClaimV1,
        ZkCircuitStage::Session,
    );

    binding.validate_for_circuit(circuit_ref)
}

#[test]
fn proof_can_carry_exact_circuit_ref() -> Result<(), crate::errors::ZkError> {
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Claim,
    );
    let public_inputs = exact_public_inputs(circuit_ref)?;
    let proof = ZkProof::try_from_exact_parts(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        public_inputs,
    )?;

    assert_eq!(proof.circuit_ref(), circuit_ref);
    Ok(())
}

#[test]
fn exact_proof_rejects_mismatched_policy_circuit_id() -> Result<(), crate::errors::ZkError> {
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    );
    let error = ZkProof::try_from_exact_parts(
        ZkCircuitId::PrivatePersonaClaimV1,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        exact_public_inputs(circuit_ref)?,
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn exact_proof_rejects_malformed_public_input_abi() -> Result<(), crate::errors::ZkError> {
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Poseidon2,
        ZkCircuitFamily::PrivatePersonaClaimV1,
        ZkCircuitStage::Claim,
    );
    let public_inputs = ZkPublicInputs::try_from_bytes(vec![0_u8; 1])?;
    let error = ZkProof::try_from_exact_parts(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        public_inputs,
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn stage_prove_request_accepts_exact_production_boundary() -> Result<(), crate::errors::ZkError> {
    let circuit_ref = circuit_ref();
    let binding = prove_binding();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![7, 8, 9])?;
    let public_inputs = exact_public_inputs_for_binding(circuit_ref, binding)?;
    let request = ZkProveRequest::try_new(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )?;

    assert_eq!(request.circuit_ref(), circuit_ref);
    assert_eq!(request.proof_suite(), ZkProofSuite::PRODUCTION);
    assert_eq!(request.public_inputs().as_bytes(), public_inputs.as_bytes());
    Ok(())
}

#[test]
fn stage_prove_request_rejects_mismatched_witness_ref() -> Result<(), crate::errors::ZkError> {
    let circuit_ref = circuit_ref();
    let wrong_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Claim,
    );
    let witness = ZkWitness::try_from_noir_witness_stack_v1(wrong_ref, vec![7, 8, 9])?;
    let binding = prove_binding();
    let public_inputs = exact_public_inputs_for_binding(circuit_ref, binding)?;
    let error = ZkProveRequest::try_new(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn stage_prove_request_rejects_mismatched_policy_circuit_id() -> Result<(), crate::errors::ZkError>
{
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![7, 8, 9])?;
    let binding = prove_binding();
    let public_inputs = exact_public_inputs_for_binding(circuit_ref, binding)?;
    let error = ZkProveRequest::try_new(
        ZkCircuitId::PrivatePersonaClaimV1,
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        binding,
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn stage_prove_request_rejects_malformed_public_input_abi() -> Result<(), crate::errors::ZkError> {
    let circuit_ref = circuit_ref();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![7, 8, 9])?;
    let public_inputs = ZkPublicInputs::try_from_bytes(vec![0_u8; 1])?;
    let error = ZkProveRequest::try_new(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        &witness,
        &public_inputs,
        zero_binding(),
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn stage_prove_request_rejects_unacknowledged_compatibility_suite(
) -> Result<(), crate::errors::ZkError> {
    let circuit_ref = circuit_ref();
    let binding = prove_binding();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![7, 8, 9])?;
    let public_inputs = exact_public_inputs_for_binding(circuit_ref, binding)?;
    let error = ZkProveRequest::try_new(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
        &witness,
        &public_inputs,
        binding,
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedProofSuite);
    Ok(())
}

#[test]
fn stage_prove_request_accepts_acknowledged_compatibility_suite(
) -> Result<(), crate::errors::ZkError> {
    let circuit_ref = circuit_ref();
    let binding = prove_binding();
    let witness = ZkWitness::try_from_noir_witness_stack_v1(circuit_ref, vec![7, 8, 9])?;
    let public_inputs = exact_public_inputs_for_binding(circuit_ref, binding)?;
    let request = ZkProveRequest::try_new_compatibility(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
        &witness,
        &public_inputs,
        binding,
        ZkCompatibilitySuiteAcknowledgement::acknowledge_non_production_risk(),
    )?;

    assert_eq!(
        request.proof_suite(),
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa
    );
    Ok(())
}

#[test]
fn stage_verification_request_rejects_suite_downgrade() -> Result<(), crate::errors::ZkError> {
    let circuit_ref = circuit_ref();
    let proof = ZkProof::try_from_exact_parts(
        circuit_ref.circuit_id(),
        circuit_ref,
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![2],
        exact_public_inputs(circuit_ref)?,
    )?;
    let error = ZkVerifyRequest::try_new(
        &proof,
        ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa,
        ZkSessionBinding {
            nonce_hash: [0; 32],
            audience_hash: [0; 32],
            transaction_data_hash: None,
        },
    )
    .err()
    .ok_or(crate::errors::ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::UnsupportedProofSuite);
    Ok(())
}
