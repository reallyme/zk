// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical provider exchange validation tests.

#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::{
        ZkCircuitFamily as DomainCircuitFamily, ZkCircuitRef as DomainCircuitRef,
        ZkCircuitStage as DomainCircuitStage,
        ZkCredentialHashAlgorithm as DomainCredentialHashAlgorithm,
    },
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs as DomainPublicInputs,
        ZkSessionBinding as DomainSessionBinding,
    },
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    zk_provider_operation_request::Operation, zk_provider_operation_response::Outcome,
    zk_provider_operation_result::Result as ProtoResult, ZkCircuitFamily, ZkCircuitId,
    ZkCircuitRef, ZkCircuitStage, ZkClaimProofBundleKind, ZkCredentialHashAlgorithm,
    ZkCredentialSubjectClaimSessionInput, ZkInputBytes32, ZkInputBytes64, ZkInputP256PublicKey,
    ZkInputSessionContext, ZkInputSubjectSessionAuthorization, ZkProofSuite,
    ZkProviderOperationRequest, ZkProviderOperationResponse, ZkProviderOperationResult,
    ZkStageWitnessInput, ZkStageWitnessOperation, ZkVerification,
};
use reallyme_zk_proto_codec::exchange::{
    decode_operation_request_kind, validate_operation_exchange, ZkProviderOperationKind,
};
use reallyme_zk_proto_codec::operation::ZkNativeStageWitnessHandle;
use reallyme_zk_proto_codec::result::encode_stage_witness_response;

fn backend_unavailable_response(request: &[u8]) -> Vec<u8> {
    ZkProviderOperationResponse {
        outcome: Some(Outcome::Error(Box::new(
            reallyme_zk_proto_codec::error::error_to_proto(ZkError::new(
                ZkErrorReason::BackendUnavailable,
            )),
        ))),
        request_sha256: Digest32::sha256(request).as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec()
}

#[test]
fn canonical_fixture_exchange_preserves_typed_provider_failure() -> Result<(), ZkError> {
    let request = decode_hex(include_str!(
        "../../proto/tests/fixtures/protobuf/artifact-operation.pb.hex"
    ));
    assert_eq!(
        decode_operation_request_kind(&request)?,
        ZkProviderOperationKind::GetArtifactManifest
    );
    // Validate the persisted cross-language response, not a fresh response
    // that would hide a stale correlation digest in the fixture pair.
    let response = decode_hex(include_str!(
        "../../proto/tests/fixtures/protobuf/backend-unavailable-response.pb.hex"
    ));
    validate_operation_exchange(&request, &response)
}

#[test]
fn success_result_must_match_the_request_operation() {
    let request = decode_hex(include_str!(
        "../../proto/tests/fixtures/protobuf/artifact-operation.pb.hex"
    ));
    let response = ZkProviderOperationResponse {
        outcome: Some(Outcome::Result(Box::new(ZkProviderOperationResult {
            result: Some(ProtoResult::StageVerification(Box::new(
                valid_stage_verification(),
            ))),
            __buffa_unknown_fields: Default::default(),
        }))),
        request_sha256: Digest32::sha256(&request).as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec();

    let error = validate_operation_exchange(&request, &response)
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::MalformedProtobuf));
    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
}

#[test]
fn malformed_request_fails_before_response_validation() {
    let error = validate_operation_exchange(&[0x80], &backend_unavailable_response(&[0x80]))
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure));
    assert_eq!(error.reason(), ZkErrorReason::MalformedProtobuf);
}

#[test]
fn response_for_one_canonical_request_cannot_be_cross_paired() -> Result<(), ZkError> {
    let request_a = decode_hex(include_str!(
        "../../proto/tests/fixtures/protobuf/artifact-operation.pb.hex"
    ));
    let mut request_b = ZkProviderOperationRequest::decode(&mut request_a.as_slice())
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    let Operation::GetArtifactManifest(operation) = request_b
        .operation
        .as_mut()
        .ok_or(ZkError::new(ZkErrorReason::MissingOperation))?
    else {
        return Err(ZkError::new(ZkErrorReason::MissingOperation));
    };
    operation.proof_suite = EnumValue::from(
        ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_UNMASKED_NO_IPA,
    );
    let request_b = request_b.encode_to_vec();
    let response_a = backend_unavailable_response(&request_a);

    let error = validate_operation_exchange(&request_b, &response_a)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

#[test]
fn witness_stage_response_must_match_request_session_binding() -> Result<(), ZkError> {
    let request = witness_stage_request();
    let expected_binding = DomainSessionBinding {
        nonce_hash: fixed32(1),
        audience_hash: fixed32(2),
        transaction_data_hash: Some(fixed32(5)),
    };
    let matching_response = witness_stage_response(&request, expected_binding)?;
    validate_operation_exchange(&request, matching_response.as_slice())?;

    let wrong_binding = DomainSessionBinding {
        nonce_hash: fixed32(9),
        audience_hash: fixed32(2),
        transaction_data_hash: Some(fixed32(5)),
    };
    let wrong_response = witness_stage_response(&request, wrong_binding)?;
    let error = validate_operation_exchange(&request, wrong_response.as_slice())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    Ok(())
}

fn valid_stage_verification() -> ZkVerification {
    ZkVerification {
        circuit_id: EnumValue::from(ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1),
        circuit_ref: MessageField::some(ZkCircuitRef {
            credential_hash_algorithm: EnumValue::from(
                ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            ),
            family: EnumValue::from(ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1),
            stage: EnumValue::from(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM),
            circuit_revision: 1,
            __buffa_unknown_fields: Default::default(),
        }),
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn witness_stage_request() -> Vec<u8> {
    ZkProviderOperationRequest {
        operation: Some(Operation::WitnessStage(Box::new(ZkStageWitnessOperation {
            circuit_ref: MessageField::some(stage_ref(ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION)),
            proof_suite: EnumValue::from(
                ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            input: MessageField::some(credential_subject_claim_session_input()),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec()
}

fn stage_ref(stage: ZkCircuitStage) -> ZkCircuitRef {
    ZkCircuitRef {
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        family: EnumValue::from(ZkCircuitFamily::ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1),
        stage: EnumValue::from(stage),
        circuit_revision: 1,
        __buffa_unknown_fields: Default::default(),
    }
}

fn credential_subject_claim_session_input() -> ZkStageWitnessInput {
    ZkStageWitnessInput {
        input: Some(
            reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_stage_witness_input::Input::CredentialSubjectClaimSession(
                Box::new(ZkCredentialSubjectClaimSessionInput {
                    session_context: MessageField::some(ZkInputSessionContext {
                        challenge: bytes32(1),
                        audience_hash: bytes32(2),
                        expiry_unix: 3,
                        session_binding: bytes32(4),
                        transaction_data_hash: bytes32(5),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    authorization: MessageField::some(ZkInputSubjectSessionAuthorization {
                        subject_public_key: p256_public_key(),
                        subject_signature: bytes64(9),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn p256_public_key() -> MessageField<ZkInputP256PublicKey, buffa::Inline<ZkInputP256PublicKey>> {
    MessageField::some(ZkInputP256PublicKey {
        x: bytes32(6),
        y: bytes32(7),
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes32(marker: u8) -> MessageField<ZkInputBytes32, buffa::Inline<ZkInputBytes32>> {
    MessageField::some(ZkInputBytes32 {
        value: vec![marker; 32],
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes64(marker: u8) -> MessageField<ZkInputBytes64, buffa::Inline<ZkInputBytes64>> {
    MessageField::some(ZkInputBytes64 {
        value: vec![marker; 64],
        __buffa_unknown_fields: Default::default(),
    })
}

fn witness_stage_response(
    request: &[u8],
    binding: DomainSessionBinding,
) -> Result<Vec<u8>, ZkError> {
    let response = encode_stage_witness_response(
        request,
        ZkNativeStageWitnessHandle {
            native_handle_id: 7,
            circuit_ref: domain_session_ref(),
        },
        &session_public_inputs(binding)?,
        binding,
    )?;
    Ok(response.to_vec())
}

fn session_public_inputs(binding: DomainSessionBinding) -> Result<DomainPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(domain_session_ref())?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_public_input(
        &mut bytes,
        descriptor,
        ZkPublicInputName::Challenge,
        &binding.nonce_hash,
    )?;
    write_public_input(
        &mut bytes,
        descriptor,
        ZkPublicInputName::AudienceHash,
        &binding.audience_hash,
    )?;
    write_public_input(
        &mut bytes,
        descriptor,
        ZkPublicInputName::TransactionDataHash,
        &binding.transaction_data_public_input(),
    )?;
    write_public_input(
        &mut bytes,
        descriptor,
        ZkPublicInputName::ExpiryUnix,
        &3_u64.to_be_bytes(),
    )?;
    write_public_input(
        &mut bytes,
        descriptor,
        ZkPublicInputName::SessionBinding,
        &fixed32(4),
    )?;
    DomainPublicInputs::try_from_bytes(bytes)
}

fn write_public_input(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) -> Result<(), ZkError> {
    let slot = bytes
        .get_mut(descriptor.field_range(name)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if slot.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    slot.copy_from_slice(value);
    Ok(())
}

const fn domain_session_ref() -> DomainCircuitRef {
    DomainCircuitRef {
        credential_hash_algorithm: DomainCredentialHashAlgorithm::Sha256,
        family: DomainCircuitFamily::CredentialSubjectClaimV1,
        stage: DomainCircuitStage::Session,
        revision: 1,
    }
}

const fn fixed32(marker: u8) -> [u8; 32] {
    [marker; 32]
}

fn decode_hex(value: &str) -> Vec<u8> {
    let bytes = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<u8>>();
    let (pairs, _) = bytes.as_chunks::<2>();

    pairs
        .iter()
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}
