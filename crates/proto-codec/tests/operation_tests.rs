// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Malicious-input and happy-path tests for canonical provider operations.

#![allow(missing_docs)]

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    circuits::ZkCircuitStage as DomainCircuitStage,
    errors::{ZkError, ZkErrorReason},
    proofs::ZkWitnessEncoding as DomainWitnessEncoding,
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    zk_provider_operation_request::Operation, zk_provider_operation_response::Outcome,
    ZkArtifactManifestOperation, ZkCircuitFamily, ZkCircuitId, ZkCircuitRef, ZkCircuitStage,
    ZkClaimProofBundleKind, ZkClaimProofBundleProveOperation, ZkClaimProofBundleWitness,
    ZkCredentialHashAlgorithm, ZkCredentialSubjectClaimInput, ZkCredentialSubjectClaimSessionInput,
    ZkInputBytes16, ZkInputBytes32, ZkInputBytes64, ZkInputClaimDisclosure, ZkInputIssuerContext,
    ZkInputMerkleClaimProof, ZkInputMerklePath, ZkInputP256PublicKey, ZkInputSessionContext,
    ZkInputSubjectClaimLink, ZkInputSubjectSessionAuthorization, ZkProofPackage, ZkProofSuite,
    ZkProviderOperationRequest, ZkProviderOperationResponse,
    ZkRetainedClaimProofBundleProveOperation, ZkRetainedClaimProofBundleWitness, ZkSessionBinding,
    ZkStageProveOperation, ZkStageVerifyOperation, ZkStageWitnessHandle, ZkStageWitnessInput,
    ZkStageWitnessOperation, ZkWitness, ZkWitnessEncoding,
};
use reallyme_zk_proto_codec::error::error_to_proto;
use reallyme_zk_proto_codec::operation::{
    decode_operation_request, decode_operation_request_json, ZkProviderOperation,
    MAX_ZK_PROTO_OPERATION_BYTES,
};

fn circuit_ref() -> ZkCircuitRef {
    stage_ref(ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM)
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

fn request(operation: Operation) -> ZkProviderOperationRequest {
    ZkProviderOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    }
}

fn operation_from_proto(
    request: ZkProviderOperationRequest,
) -> Result<ZkProviderOperation, ZkError> {
    decode_operation_request(&request.encode_to_vec())
}

fn error_reason(result: Result<ZkProviderOperation, ZkError>) -> ZkErrorReason {
    result
        .err()
        .unwrap_or(ZkError::new(ZkErrorReason::BackendFailure))
        .reason()
}

fn bundle_operation(stage_witnesses: Vec<ZkWitness>) -> ZkClaimProofBundleProveOperation {
    ZkClaimProofBundleProveOperation {
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        session_binding: MessageField::some(ZkSessionBinding {
            nonce_hash: vec![1; 32],
            audience_hash: vec![2; 32],
            transaction_data_hash: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        }),
        witness_bundle: MessageField::some(ZkClaimProofBundleWitness {
            bundle_kind: EnumValue::from(
                ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            credential_hash_algorithm: EnumValue::from(
                ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            ),
            stage_witnesses,
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    }
}

fn retained_claim_proof_bundle_operation(
    stage_witness_handles: Vec<ZkStageWitnessHandle>,
) -> ZkRetainedClaimProofBundleProveOperation {
    ZkRetainedClaimProofBundleProveOperation {
        bundle_kind: EnumValue::from(
            ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
        ),
        credential_hash_algorithm: EnumValue::from(
            ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        ),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        session_binding: MessageField::some(ZkSessionBinding {
            nonce_hash: vec![1; 32],
            audience_hash: vec![2; 32],
            transaction_data_hash: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        }),
        witness_bundle: MessageField::some(ZkRetainedClaimProofBundleWitness {
            bundle_kind: EnumValue::from(
                ZkClaimProofBundleKind::ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1,
            ),
            credential_hash_algorithm: EnumValue::from(
                ZkCredentialHashAlgorithm::ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
            ),
            stage_witness_handles,
            __buffa_unknown_fields: Default::default(),
        }),
        __buffa_unknown_fields: Default::default(),
    }
}

fn witness_stage_operation(
    circuit_ref: ZkCircuitRef,
    input: ZkStageWitnessInput,
) -> ZkStageWitnessOperation {
    ZkStageWitnessOperation {
        circuit_ref: MessageField::some(circuit_ref),
        proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        input: MessageField::some(input),
        __buffa_unknown_fields: Default::default(),
    }
}

fn credential_subject_claim_session_input() -> ZkStageWitnessInput {
    ZkStageWitnessInput {
        input: Some(
            reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_stage_witness_input::Input::CredentialSubjectClaimSession(
                Box::new(ZkCredentialSubjectClaimSessionInput {
                    session_context: session_context(),
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

fn credential_subject_claim_input_with_merkle_depth(
    path_length: u32,
    sibling_count: usize,
) -> ZkStageWitnessInput {
    ZkStageWitnessInput {
        input: Some(
            reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_stage_witness_input::Input::CredentialSubjectClaim(
                Box::new(ZkCredentialSubjectClaimInput {
                    issuer_context: issuer_context(),
                    session_binding: bytes32(21),
                    disclosure: MessageField::some(ZkInputClaimDisclosure {
                        credential_binding: bytes32(22),
                        value_length: 0,
                        value: bytes64(0),
                        claim_name_hash: bytes32(23),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    proof: MessageField::some(ZkInputMerkleClaimProof {
                        envelope_hash: bytes32(24),
                        merkle_root: bytes32(25),
                        claim_salt: bytes16(26),
                        leaf_index: 0,
                        path: MessageField::some(ZkInputMerklePath {
                            path_length,
                            siblings: vec![ZkInputBytes32 {
                                value: vec![27; 32],
                                __buffa_unknown_fields: Default::default(),
                            }; sibling_count],
                            __buffa_unknown_fields: Default::default(),
                        }),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    link: MessageField::some(ZkInputSubjectClaimLink {
                        issuer_subject_binding_signature: bytes64(28),
                        subject_public_key: p256_public_key(),
                        __buffa_unknown_fields: Default::default(),
                    }),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    }
}

fn session_context() -> MessageField<ZkInputSessionContext, buffa::Inline<ZkInputSessionContext>> {
    MessageField::some(ZkInputSessionContext {
        challenge: bytes32(1),
        audience_hash: bytes32(2),
        expiry_unix: 3,
        session_binding: bytes32(4),
        transaction_data_hash: bytes32(5),
        __buffa_unknown_fields: Default::default(),
    })
}

fn issuer_context() -> MessageField<ZkInputIssuerContext, buffa::Inline<ZkInputIssuerContext>> {
    MessageField::some(ZkInputIssuerContext {
        issuer_public_key: p256_public_key(),
        challenge: bytes32(11),
        audience_hash: bytes32(12),
        expiry_unix: 13,
        transaction_data_hash: bytes32(14),
        __buffa_unknown_fields: Default::default(),
    })
}

fn p256_public_key() -> MessageField<ZkInputP256PublicKey, buffa::Inline<ZkInputP256PublicKey>> {
    MessageField::some(ZkInputP256PublicKey {
        x: bytes32(6),
        y: bytes32(7),
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes32(marker: u8) -> MessageField<ZkInputBytes32, buffa::Inline<ZkInputBytes32>> {
    bytes32_len(marker, 32)
}

fn bytes32_len(
    marker: u8,
    len: usize,
) -> MessageField<ZkInputBytes32, buffa::Inline<ZkInputBytes32>> {
    MessageField::some(ZkInputBytes32 {
        value: vec![marker; len],
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes16(marker: u8) -> MessageField<ZkInputBytes16, buffa::Inline<ZkInputBytes16>> {
    MessageField::some(ZkInputBytes16 {
        value: vec![marker; 16],
        __buffa_unknown_fields: Default::default(),
    })
}

fn bytes64(marker: u8) -> MessageField<ZkInputBytes64, buffa::Inline<ZkInputBytes64>> {
    MessageField::some(ZkInputBytes64 {
        value: vec![marker; 64],
        __buffa_unknown_fields: Default::default(),
    })
}

fn exact_stage_witnesses() -> Vec<ZkWitness> {
    [
        ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION,
        ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE,
        ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT,
        ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM,
    ]
    .into_iter()
    .map(|stage| ZkWitness {
        encoded: vec![7, 8, 9],
        circuit_ref: MessageField::some(stage_ref(stage)),
        encoding: EnumValue::from(ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1),
        __buffa_unknown_fields: Default::default(),
    })
    .collect()
}

fn exact_stage_witness_handles() -> Vec<ZkStageWitnessHandle> {
    [
        ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION,
        ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ENVELOPE,
        ZkCircuitStage::ZK_CIRCUIT_STAGE_CREDENTIAL_ROOT,
        ZkCircuitStage::ZK_CIRCUIT_STAGE_CLAIM,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, stage)| ZkStageWitnessHandle {
        native_handle_id: u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .unwrap_or(0),
        circuit_ref: MessageField::some(stage_ref(stage)),
        encoding: EnumValue::from(ZkWitnessEncoding::ZK_WITNESS_ENCODING_NOIR_WITNESS_STACK_V1),
        __buffa_unknown_fields: Default::default(),
    })
    .collect()
}

#[test]
fn canonical_cross_lane_vector_matches_rust_encoding() {
    const VECTOR: &str = include_str!("../../../vectors/provider-boundary-v1.vector");
    let operation = request(Operation::GetArtifactManifest(Box::default()));
    let response = ZkProviderOperationResponse {
        outcome: Some(Outcome::Error(Box::new(error_to_proto(ZkError::new(
            ZkErrorReason::BackendUnavailable,
        ))))),
        request_sha256: Digest32::sha256(&operation.encode_to_vec())
            .as_bytes()
            .to_vec(),
        __buffa_unknown_fields: Default::default(),
    };

    assert_eq!(
        vector_value(VECTOR, "format"),
        "reallyme.zk.provider-boundary.v1"
    );
    assert_eq!(
        hex(&operation.encode_to_vec()),
        vector_value(VECTOR, "request")
    );
    assert_eq!(
        hex(&response.encode_to_vec()),
        vector_value(VECTOR, "response")
    );
}

fn vector_value<'a>(source: &'a str, key: &str) -> &'a str {
    source
        .lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            line.split_once('=')
                .filter(|(candidate, _)| *candidate == key)
        })
        .map_or("", |(_, value)| value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn binary_artifact_operation_decodes_to_exact_domain_ref() -> Result<(), ZkError> {
    let message = request(Operation::GetArtifactManifest(Box::new(
        ZkArtifactManifestOperation {
            circuit_ref: MessageField::some(circuit_ref()),
            proof_suite: EnumValue::from(
                ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
            ),
            __buffa_unknown_fields: Default::default(),
        },
    )));

    match decode_operation_request(&message.encode_to_vec())? {
        ZkProviderOperation::GetArtifactManifest {
            circuit_ref,
            proof_suite,
        } => {
            assert_eq!(circuit_ref.stage, DomainCircuitStage::Claim);
            assert_eq!(
                proof_suite,
                reallyme_zk_api::proofs::ZkProofSuite::PRODUCTION
            );
            Ok(())
        }
        _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn artifact_protojson_decodes_to_exact_domain_ref() -> Result<(), ZkError> {
    let json = br#"{"getArtifactManifest":{"circuitRef":{"credentialHashAlgorithm":"ZK_CREDENTIAL_HASH_ALGORITHM_SHA256","family":"ZK_CIRCUIT_FAMILY_CREDENTIAL_SUBJECT_CLAIM_V1","stage":"ZK_CIRCUIT_STAGE_CLAIM","circuitRevision":1},"proofSuite":"ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA"}}"#;

    match decode_operation_request_json(json)? {
        ZkProviderOperation::GetArtifactManifest {
            circuit_ref,
            proof_suite,
        } => {
            assert_eq!(circuit_ref.stage, DomainCircuitStage::Claim);
            assert_eq!(
                proof_suite,
                reallyme_zk_api::proofs::ZkProofSuite::PRODUCTION
            );
            Ok(())
        }
        _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn artifact_operation_preserves_poseidon2_unmasked_suite() -> Result<(), ZkError> {
    let message = request(Operation::GetArtifactManifest(Box::new(
        ZkArtifactManifestOperation {
            circuit_ref: MessageField::some(circuit_ref()),
            proof_suite: EnumValue::from(
                ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_POSEIDON2_UNMASKED_NO_IPA,
            ),
            __buffa_unknown_fields: Default::default(),
        },
    )));

    match decode_operation_request(&message.encode_to_vec())? {
        ZkProviderOperation::GetArtifactManifest { proof_suite, .. } => {
            assert_eq!(
                proof_suite,
                reallyme_zk_api::proofs::ZkProofSuite::BarretenbergUltraHonkPoseidon2UnmaskedNoIpa
            );
            Ok(())
        }
        _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn secret_bearing_protojson_is_rejected_before_deserialization() {
    let json = br#"{"proveClaimProofBundle":{"witness":{"encoded":"not-valid-base64"}}}"#;

    assert_eq!(
        error_reason(decode_operation_request_json(json)),
        ZkErrorReason::UnsupportedTransport
    );
}

#[test]
fn escaped_operation_selector_is_rejected() {
    let json = br#"{"prove\u0042undle":{}}"#;

    assert_eq!(
        error_reason(decode_operation_request_json(json)),
        ZkErrorReason::MalformedJson
    );
}

#[test]
fn multiple_top_level_operations_are_rejected() {
    let json = br#"{"verifyStage":{},"getArtifactManifest":{}}"#;

    assert_eq!(
        error_reason(decode_operation_request_json(json)),
        ZkErrorReason::MalformedJson
    );
}

#[test]
fn missing_binary_operation_fails_closed() {
    assert_eq!(
        error_reason(decode_operation_request(&[])),
        ZkErrorReason::MissingOperation
    );
}

#[test]
fn unknown_binary_field_is_rejected() {
    // Field 6 is outside the canonical oneof and the strict decoder permits no
    // unknown fields at executable boundaries.
    assert_eq!(
        error_reason(decode_operation_request(&[0x30, 0x00])),
        ZkErrorReason::MalformedProtobuf
    );
}

#[test]
fn nonminimal_binary_tag_encoding_is_rejected() {
    // Field 5 encoded with a redundant varint byte still describes the same
    // message, but canonical provider bytes permit only the minimal tag.
    assert_eq!(
        error_reason(decode_operation_request(&[0xaa, 0x00, 0x00])),
        ZkErrorReason::MalformedProtobuf
    );
}

#[test]
fn oversized_binary_message_is_rejected_before_decode() {
    let bytes = vec![0_u8; MAX_ZK_PROTO_OPERATION_BYTES.saturating_add(1)];

    assert_eq!(
        error_reason(decode_operation_request(&bytes)),
        ZkErrorReason::MessageTooLarge
    );
}

#[test]
fn inconsistent_exact_proof_metadata_fails_closed() {
    let mut proof = ZkProofPackage::default();
    proof.circuit_id = EnumValue::from(ZkCircuitId::ZK_CIRCUIT_ID_CREDENTIAL_SUBJECT_CLAIM_V1);
    proof.circuit_id_string = "wrong".to_owned();
    proof.circuit_ref.get_or_insert_default().circuit_revision = 1;
    proof.circuit_ref = MessageField::some(circuit_ref());
    let message = request(Operation::VerifyStage(Box::new(ZkStageVerifyOperation {
        proof: MessageField::some(proof),
        expected_binding: MessageField::some(ZkSessionBinding::default()),
        expected_proof_suite: EnumValue::from(
            ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
        ),
        __buffa_unknown_fields: Default::default(),
    })));

    assert_eq!(
        error_reason(operation_from_proto(message)),
        ZkErrorReason::StageMismatch
    );
}

#[test]
fn proving_operation_moves_witness_into_zeroizing_domain_owner() -> Result<(), ZkError> {
    let message = request(Operation::ProveClaimProofBundle(Box::new(
        bundle_operation(exact_stage_witnesses()),
    )));

    match operation_from_proto(message)? {
        ZkProviderOperation::ProveClaimProofBundle { witness_bundle, .. } => {
            let witness = witness_bundle
                .stage_witness(reallyme_zk_api::claim_bundle::ZkClaimProofBundleStage::Claim)?;
            assert_eq!(
                witness.encoding(),
                DomainWitnessEncoding::NoirWitnessStackV1
            );
            assert_eq!(witness.expose_bytes(), &[7, 8, 9]);
            Ok(())
        }
        _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn retained_claim_proof_bundle_operation_admits_ordered_native_handles() -> Result<(), ZkError> {
    let message = request(Operation::ProveRetainedClaimProofBundle(Box::new(
        retained_claim_proof_bundle_operation(exact_stage_witness_handles()),
    )));

    match operation_from_proto(message)? {
        ZkProviderOperation::ProveRetainedClaimProofBundle {
            bundle_kind,
            credential_hash_algorithm,
            witness_handles,
            ..
        } => {
            assert_eq!(
                bundle_kind,
                reallyme_zk_api::claim_bundle::ZkClaimProofBundleKind::CredentialSubjectClaimV1
            );
            assert_eq!(
                credential_hash_algorithm,
                reallyme_zk_api::circuits::ZkCredentialHashAlgorithm::Sha256
            );
            assert_eq!(witness_handles.len(), 4);
            assert_eq!(witness_handles[0].native_handle_id, 1);
            assert_eq!(witness_handles[3].native_handle_id, 4);
            Ok(())
        }
        _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

#[test]
fn witness_stage_rejects_empty_input_oneof_at_codec_boundary() {
    let message = request(Operation::WitnessStage(Box::new(witness_stage_operation(
        stage_ref(ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION),
        ZkStageWitnessInput::default(),
    ))));

    assert_eq!(
        error_reason(operation_from_proto(message)),
        ZkErrorReason::EmptyInput
    );
}

#[test]
fn witness_stage_invalid_circuit_ref_fails_with_owned_input() {
    // Circuit validation runs before input validation. Keep the generated
    // input under a cleanup owner across this early error path.
    let message = request(Operation::WitnessStage(Box::new(witness_stage_operation(
        ZkCircuitRef::default(),
        credential_subject_claim_session_input(),
    ))));

    assert_eq!(
        error_reason(operation_from_proto(message)),
        ZkErrorReason::UnsupportedCircuit
    );
}

#[test]
fn witness_stage_invalid_suite_fails_with_owned_input() {
    let mut operation = witness_stage_operation(
        stage_ref(ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION),
        credential_subject_claim_session_input(),
    );
    operation.proof_suite = EnumValue::from(65_535);

    assert_eq!(
        error_reason(operation_from_proto(request(Operation::WitnessStage(
            Box::new(operation)
        )))),
        ZkErrorReason::UnsupportedProofSuite
    );
}

#[test]
fn witness_stage_rejects_input_variant_that_does_not_match_circuit_ref() {
    let message = request(Operation::WitnessStage(Box::new(witness_stage_operation(
        circuit_ref(),
        credential_subject_claim_session_input(),
    ))));

    assert_eq!(
        error_reason(operation_from_proto(message)),
        ZkErrorReason::StageMismatch
    );
}

#[test]
fn witness_stage_rejects_malformed_fixed_width_bytes_at_codec_boundary() {
    let mut input = credential_subject_claim_session_input();
    if let Some(
        reallyme_zk_proto::generated::proto::reallyme::zk::v1::zk_stage_witness_input::Input::CredentialSubjectClaimSession(session),
    ) = input.input.as_mut()
    {
        session.session_context = MessageField::some(ZkInputSessionContext {
            challenge: bytes32_len(1, 3),
            audience_hash: bytes32(2),
            expiry_unix: 3,
            session_binding: bytes32(4),
            transaction_data_hash: bytes32(5),
            __buffa_unknown_fields: Default::default(),
        });
    }
    let message = request(Operation::WitnessStage(Box::new(witness_stage_operation(
        stage_ref(ZkCircuitStage::ZK_CIRCUIT_STAGE_SESSION),
        input,
    ))));

    assert_eq!(
        error_reason(operation_from_proto(message)),
        ZkErrorReason::InvalidProofEncoding
    );
}

#[test]
fn witness_stage_rejects_over_depth_merkle_input_at_codec_boundary() {
    let message = request(Operation::WitnessStage(Box::new(witness_stage_operation(
        circuit_ref(),
        credential_subject_claim_input_with_merkle_depth(7, 7),
    ))));

    assert_eq!(
        error_reason(operation_from_proto(message)),
        ZkErrorReason::ClaimPayloadTooLarge
    );
}

#[test]
fn retained_claim_proof_bundle_with_missing_handle_fails_closed() {
    let mut handles = exact_stage_witness_handles();
    let _removed = handles.pop();

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveRetainedClaimProofBundle(Box::new(
                retained_claim_proof_bundle_operation(handles)
            ))
        ))),
        ZkErrorReason::MissingStage
    );
}

#[test]
fn retained_claim_proof_bundle_with_reordered_handle_fails_closed() {
    let mut handles = exact_stage_witness_handles();
    handles.swap(0, 1);

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveRetainedClaimProofBundle(Box::new(
                retained_claim_proof_bundle_operation(handles)
            ))
        ))),
        ZkErrorReason::StageMismatch
    );
}

#[test]
fn retained_claim_proof_bundle_with_duplicate_handle_id_fails_closed() {
    let mut handles = exact_stage_witness_handles();
    handles[1].native_handle_id = handles[0].native_handle_id;

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveRetainedClaimProofBundle(Box::new(
                retained_claim_proof_bundle_operation(handles)
            ))
        ))),
        ZkErrorReason::DuplicateStage
    );
}

#[test]
fn retained_claim_proof_bundle_with_zero_handle_id_fails_closed() {
    let mut handles = exact_stage_witness_handles();
    handles[0].native_handle_id = 0;

    assert_eq!(
        error_reason(operation_from_proto(request(
            Operation::ProveRetainedClaimProofBundle(Box::new(
                retained_claim_proof_bundle_operation(handles)
            ))
        ))),
        ZkErrorReason::EmptyInput
    );
}

#[path = "operation_tests/validation_failure_tests.rs"]
mod validation_failure_tests;
