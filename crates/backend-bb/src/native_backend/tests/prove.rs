// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::atomic::{AtomicUsize, Ordering};

use reallyme_zk_api::{
    claim_bundle::ZkClaimProofBundleKind,
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProofSuite, ZkSessionBinding},
};

use super::{
    binding, bundle_kind, circuit_ref, lock_process_state_test, public_inputs_for_binding, stage,
    stage_artifacts, witness, BarretenbergBbapiResponse, BarretenbergBbapiTransport,
    BarretenbergProcessCrsIdentity, BarretenbergProverCrsIdentity, BbapiProcessCrsState,
    ErrorTransport, NativeBarretenbergBackend, StaticTransport, SRS_INIT_CALL_COUNT,
    SUCCESS_RESPONSE,
};
use crate::{
    public_input_codec::{BarretenbergPublicInputCodec, BARRETENBERG_FIELD_BYTES},
    BbStageProveRequest, LinkedBarretenbergBackend,
};

#[test]
fn prover_backend_uses_typed_command_and_decodes_success() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    let artifacts = stage_artifacts()?;
    let response = prove_response(binding(), artifacts.verification_key().as_bytes())?;
    let backend = NativeBarretenbergBackend::from_transport(ProveThenVerifyTransport {
        prove_response: Box::leak(response.into_boxed_slice()),
        verify_response: SUCCESS_RESPONSE,
        call_count: AtomicUsize::new(0),
    });
    let witness = witness()?;

    let proof = backend.prove_stage(BbStageProveRequest {
        bundle_kind: bundle_kind(),
        stage: stage(),
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        witness: &witness,
        session_binding: binding(),
    })?;

    assert_eq!(
        proof.public_inputs(),
        &public_inputs_for_binding(circuit_ref(), binding())?
    );
    assert_eq!(
        proof.proof_bytes().as_bytes(),
        vec![0_u8; super::EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES].as_slice()
    );
    Ok(())
}

#[test]
fn prover_backend_rejects_when_immediate_verify_fails() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    let artifacts = stage_artifacts()?;
    let response = prove_response(binding(), artifacts.verification_key().as_bytes())?;
    let backend = NativeBarretenbergBackend::from_transport(ProveThenVerifyTransport {
        prove_response: Box::leak(response.into_boxed_slice()),
        verify_response: &[
            0x92, 0xb5, b'C', b'i', b'r', b'c', b'u', b'i', b't', b'V', b'e', b'r', b'i', b'f',
            b'y', b'R', b'e', b's', b'p', b'o', b'n', b's', b'e', 0x81, 0xa8, b'v', b'e', b'r',
            b'i', b'f', b'i', b'e', b'd', 0xc2,
        ],
        call_count: AtomicUsize::new(0),
    });
    let witness = witness()?;

    let error = backend
        .prove_stage(BbStageProveRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            witness: &witness,
            session_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::InvalidProof);
    Ok(())
}

#[test]
fn prover_backend_rejects_non_full_crs_states_before_transport() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    for state in [
        BbapiProcessCrsState::Uninitialized,
        BbapiProcessCrsState::Poisoned,
        BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::VerifierOnly(
            super::BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
        )),
    ] {
        {
            let mut process_state = super::lock_bbapi_process_state()?;
            process_state.crs = state;
        }
        SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
        let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
            response: &[],
            required_command: b"CircuitProve",
            call_count: Some(&SRS_INIT_CALL_COUNT),
        });
        let artifacts = stage_artifacts()?;
        let witness = witness()?;

        let error = backend
            .prove_stage(BbStageProveRequest {
                bundle_kind: bundle_kind(),
                stage: stage(),
                circuit_ref: circuit_ref(),
                proof_suite: ZkProofSuite::PRODUCTION,
                artifacts: &artifacts,
                witness: &witness,
                session_binding: binding(),
            })
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

        assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 0);
        assert!(matches!(
            error.reason(),
            ZkErrorReason::BackendUnavailable | ZkErrorReason::BackendFailure
        ));
    }
    Ok(())
}

#[test]
fn prover_backend_rejects_response_binding_mismatch() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    let artifacts = stage_artifacts()?;
    let wrong_binding = ZkSessionBinding {
        nonce_hash: [9_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: None,
    };
    let response = prove_response(wrong_binding, artifacts.verification_key().as_bytes())?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: Box::leak(response.into_boxed_slice()),
        required_command: b"CircuitProve",
        call_count: None,
    });
    let witness = witness()?;

    let error = backend
        .prove_stage(BbStageProveRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            witness: &witness,
            session_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BindingMismatch);
    Ok(())
}

#[test]
fn prover_backend_rejects_returned_vk_mismatch() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    let artifacts = stage_artifacts()?;
    let response = prove_response_with_returned_vk(binding(), &[55_u8; 64])?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: Box::leak(response.into_boxed_slice()),
        required_command: b"CircuitProve",
        call_count: None,
    });
    let witness = witness()?;

    let error = backend
        .prove_stage(BbStageProveRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            witness: &witness,
            session_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn prover_backend_maps_transport_error_without_response_text() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(ErrorTransport {
        required_command: b"CircuitProve",
        call_count: &SRS_INIT_CALL_COUNT,
        reason: ZkErrorReason::BackendFailure,
    });
    let artifacts = stage_artifacts()?;
    let witness = witness()?;

    let error = backend
        .prove_stage(BbStageProveRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            witness: &witness,
            session_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn prove_stage_rejects_request_mismatches_before_transport() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: &[],
        required_command: b"CircuitProve",
        call_count: Some(&SRS_INIT_CALL_COUNT),
    });
    let artifacts = stage_artifacts()?;
    let witness = witness()?;

    let error = backend
        .prove_stage(BbStageProveRequest {
            bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            witness: &witness,
            session_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 0);
    Ok(())
}

fn prove_response(
    response_binding: ZkSessionBinding,
    _verification_key: &[u8],
) -> Result<Vec<u8>, ZkError> {
    prove_response_with_optional_returned_vk(response_binding, None)
}

fn prove_response_with_returned_vk(
    response_binding: ZkSessionBinding,
    verification_key: &[u8],
) -> Result<Vec<u8>, ZkError> {
    prove_response_with_optional_returned_vk(response_binding, Some(verification_key))
}

fn prove_response_with_optional_returned_vk(
    response_binding: ZkSessionBinding,
    verification_key: Option<&[u8]>,
) -> Result<Vec<u8>, ZkError> {
    let public_inputs = BarretenbergPublicInputCodec::encode(
        circuit_ref(),
        &public_inputs_for_binding(circuit_ref(), response_binding)?,
    )?;
    let mut output = Vec::new();
    pack_array_header(&mut output, 2);
    pack_str(&mut output, "CircuitProveResponse");
    pack_map_header(&mut output, 3);
    pack_str(&mut output, "public_inputs");
    pack_field_vector(&mut output, public_inputs.as_slice());
    pack_str(&mut output, "proof");
    pack_field_vector(
        &mut output,
        vec![0_u8; super::EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES].as_slice(),
    );
    pack_str(&mut output, "vk");
    pack_map_header(&mut output, 3);
    pack_str(&mut output, "bytes");
    pack_bin(&mut output, verification_key.unwrap_or(&[]));
    pack_str(&mut output, "fields");
    if verification_key.is_some() {
        pack_field_vector(&mut output, &[0_u8; BARRETENBERG_FIELD_BYTES]);
    } else {
        pack_array_header(&mut output, 0);
    }
    pack_str(&mut output, "hash");
    if verification_key.is_some() {
        pack_bin(&mut output, &[42_u8; BARRETENBERG_FIELD_BYTES]);
    } else {
        pack_bin(&mut output, &[]);
    }
    Ok(output)
}

struct ProveThenVerifyTransport {
    prove_response: &'static [u8],
    verify_response: &'static [u8],
    call_count: AtomicUsize,
}

impl BarretenbergBbapiTransport for ProveThenVerifyTransport {
    fn call(&self, command: &[u8]) -> Result<BarretenbergBbapiResponse, ZkError> {
        let call_index = self.call_count.fetch_add(1, Ordering::SeqCst);
        let (required_command, response) = match call_index {
            0 => (b"CircuitProve".as_slice(), self.prove_response),
            1 => (b"CircuitVerify".as_slice(), self.verify_response),
            _ => return Err(ZkError::new(ZkErrorReason::BackendFailure)),
        };
        if !command
            .windows(required_command.len())
            .any(|window| window == required_command)
        {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        BarretenbergBbapiResponse::try_copy_from_slice(response)
    }
}

fn pack_array_header(output: &mut Vec<u8>, size: u8) {
    output.push(0x90 | size);
}

fn pack_map_header(output: &mut Vec<u8>, size: u8) {
    output.push(0x80 | size);
}

fn pack_str(output: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    output.push(0xa0 | u8::try_from(bytes.len()).unwrap_or(0));
    output.extend_from_slice(bytes);
}

fn pack_bin(output: &mut Vec<u8>, bytes: &[u8]) {
    output.push(0xc4);
    output.push(u8::try_from(bytes.len()).unwrap_or(0));
    output.extend_from_slice(bytes);
}

fn pack_field_vector(output: &mut Vec<u8>, bytes: &[u8]) {
    let fields = u16::try_from(bytes.len() / BARRETENBERG_FIELD_BYTES).unwrap_or(0);
    if fields <= 15 {
        output.push(0x90 | u8::try_from(fields).unwrap_or(0));
    } else {
        output.push(0xdc);
        output.extend_from_slice(&fields.to_be_bytes());
    }
    for field in bytes.chunks(BARRETENBERG_FIELD_BYTES) {
        pack_bin(output, field);
    }
}
