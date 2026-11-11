// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::BbStageProveResponse;
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    errors::{ZkError, ZkErrorReason},
    proofs::ZkPublicInputDescriptor,
};

fn circuit_ref() -> ZkCircuitRef {
    ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        ZkCircuitFamily::CredentialSubjectClaimV1,
        ZkCircuitStage::Session,
    )
}

fn exact_public_inputs() -> Result<Vec<u8>, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref())?;
    Ok(vec![171_u8; descriptor.encoded_len()?])
}

#[test]
fn borrowed_platform_result_is_bounded_and_abi_checked() -> Result<(), ZkError> {
    let proof = [205_u8, 239_u8];
    let public_inputs = exact_public_inputs()?;
    let response =
        BbStageProveResponse::try_copy_from_compact_slices(circuit_ref(), &proof, &public_inputs)?;

    assert_eq!(response.proof_bytes().as_bytes(), proof.as_slice());
    assert_eq!(
        response.public_inputs().as_bytes(),
        public_inputs.as_slice()
    );
    Ok(())
}

#[test]
fn platform_result_rejects_malformed_public_input_abi() -> Result<(), ZkError> {
    let error = BbStageProveResponse::try_copy_from_compact_slices(circuit_ref(), &[1_u8], &[2_u8])
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProofEncoding);
    Ok(())
}

#[test]
fn platform_result_rejects_empty_buffers_before_copying() -> Result<(), ZkError> {
    let public_inputs = exact_public_inputs()?;
    let error = BbStageProveResponse::try_copy_from_compact_slices(
        circuit_ref(),
        &[],
        public_inputs.as_slice(),
    )
    .err()
    .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::EmptyInput);
    Ok(())
}

#[test]
fn platform_result_rejects_missing_normalized_public_inputs() -> Result<(), ZkError> {
    let error = BbStageProveResponse::try_copy_from_compact_slices(circuit_ref(), &[1_u8], &[])
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::EmptyInput);
    Ok(())
}

#[test]
fn platform_result_debug_redacts_both_buffers() -> Result<(), ZkError> {
    let response = BbStageProveResponse::try_from_compact_bytes(
        circuit_ref(),
        vec![205_u8, 239_u8],
        exact_public_inputs()?,
    )?;
    let debug = format!("{response:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("171"));
    assert!(!debug.contains("205"));
    assert!(!debug.contains("239"));
    Ok(())
}
